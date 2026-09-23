import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Establishment

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Alice's side of establishment, layered over the identity-based
	/// primitive below: mint a fresh Group_A leaf bundle under `principal`'s
	/// per-half signing keys (book concepts.md's credential-scoped signer —
	/// the classical leaf signs under the classical key, the PQ leaf under the
	/// PQ key) and delegate.
	public static func initiate(
		principal: Principal,
		their: CombinerKeyPackage,
		appBinding: Data? = nil
	) throws -> EstablishResult {
		let identity = try TwoMLSIdentity.generate(
			clientID: principal.clientID, signingKey: principal.signingKey,
			signatureKey: principal.signatureKey,
			pqSigningKey: principal.pqSigningKey,
			pqSignatureKey: principal.pqSignatureKey,
			classicalProvider: principal.classicalProvider,
			pqProvider: principal.pqProvider)
		return try initiate(
			identity: identity, their: their,
			classicalProvider: principal.classicalProvider,
			pqProvider: principal.pqProvider, appBinding: appBinding,
			codepoints: principal.codepoints)
	}

	/// The session acknowledges a replayed initial frame the invitation's
	/// forward table routed here: validation only, no state change (book
	/// session-lifecycle.md, "Invitations & replayed initial frames" —
	/// `Ok(None)`). A token that does not match the one this session was
	/// actually spawned under is a mis-route.
	public func forwarded(spawnToken token: Data) throws {
		guard token == spawnToken else { throw TwoMLSError.misroutedSpawnToken }
	}

	/// Found Group_A (a full pair) and return the un-header-sealed `APQWelcome_A` to
	/// hand the acceptor out of band. `isEstablished` is false until the
	/// acceptor's first frame is processed (no receive group yet).
	///
	/// Internal: the app-facing entry point is `initiate(principal:their:)`
	/// above; this lower-level primitive stays available in-module for tests
	/// that need direct identity access.
	///
	/// `appBinding` is the optional app-state binding welded into Group_A's
	/// classical GroupContext at this moment and immutable for the session's
	/// lifetime (book group-rules.md rule 8) — pass a digest, never empty
	/// (empty is reserved-invalid, rejected here before any group is built).
	static func initiate(
		identity: TwoMLSIdentity,
		their: CombinerKeyPackage,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		appBinding: Data? = nil,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> EstablishResult {
		guard classicalProvider.cipherSuite == TwoMLSSuite.classical,
			pqProvider.cipherSuite == TwoMLSSuite.pq
		else { throw TwoMLSError.cipherSuiteMismatch }
		guard appBinding.map(\.isEmpty) != true else {
			throw TwoMLSError.appBindingMismatch
		}

		// AS binding: `their.classical` and `their.pq` are two separate
		// caller-supplied `KeyPackage`s — nothing else ties them to the same
		// party. Require the two halves to present the SAME Basic identity, and
		// seed `theirs` from it (the peer this session is established against).
		let theirClassicalID = try basicIdentifier(their.classical.leafNode.credential)
		guard try basicIdentifier(their.pq.leafNode.credential) == theirClassicalID else {
			throw TwoMLSError.remoteIdentityMismatch
		}
		let auth = AuthCore(
			mine: .seeded(identity.clientID), theirs: .seeded(theirClassicalID))

		// Every leaf this identity occupies or will occupy — Group_A's
		// founded classical+PQ leaves, and Group_B's classical leaf (once
		// joined) plus KP′'s reservation — presents the SAME per-half key,
		// minted once here so founding and the stored `leafKeys` below read
		// the identical local value rather than re-deriving it from
		// `identity` twice.
		let classicalKey = LeafKey(
			signingKey: identity.signingKey, signatureKey: identity.signatureKey)
		let pqKey = LeafKey(
			signingKey: identity.pqSigningKey, signatureKey: identity.pqSignatureKey)

		let classicalHalf = try halfCreation(
			identity: identity, half: identity.keyPackage.classical,
			leafSecretKey: identity.classicalLeafSecretKey,
			signingKey: classicalKey.signingKey,
			peerKeyPackage: their.classical,
			provider: classicalProvider)
		let pqHalf = try halfCreation(
			identity: identity, half: identity.keyPackage.pq,
			leafSecretKey: identity.pqLeafSecretKey, signingKey: pqKey.signingKey,
			peerKeyPackage: their.pq,
			provider: pqProvider)

		let (groupA, welcome) = try APQGroup.establishFull(
			classical: classicalHalf, pq: pqHalf, mode: 0,
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			appBinding: appBinding, codepoints: codepoints)

		let apqWelcomeA = Frames.encodeAPQWelcome(
			t: try welcome.tWelcome.mlsEncoded(), pq: try welcome.pqWelcome.mlsEncoded()
		)

		// Mint the §A.3 bootstrap KeyPackage KP′ now: a fresh leaf+init
		// keypair distinct from `identity.keyPackage.pq` (Alice's leaf IN
		// Group_A) — what Bob Adds into the new Group_B.pq. Its commitment
		// `H(KP′)` hashes the MLSMessage-wrapped bytes (§11 #7).
		let bootstrap = try identity.freshPQKeyPackage(pqProvider: pqProvider)

		// `identity.pqInitSecretKey` founded (not joined) `groupA`'s PQ half
		// above, and is never read again by the initiator — clear it before
		// it can ever be archived. The classical init secret stays: the
		// initiator still needs it later, to join Group_B once the
		// acceptor's first frame arrives (`joinGroupBIfNeeded`), which
		// clears it in turn once THAT join completes.
		let establishedIdentity = identity.clearingInitSecrets(classical: false, pq: true)

		// The same two pairs minted above seed all four sets.
		let leafKeys = LeafKeys(
			sendClassical: GroupKeySet(current: classicalKey),
			recvClassical: GroupKeySet(current: classicalKey),
			sendPQ: GroupKeySet(current: pqKey),
			recvPQ: GroupKeySet(current: pqKey))

		var session = TwoMLSSession(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, identity: establishedIdentity, auth: auth,
			sendGroup: groupA,
			recvGroup: nil,
			currentStaple: apqWelcomeA, pendingProposal: nil, joinedWelcomeDigest: nil,
			initiated: true,
			bootstrapKPSecret: (
				leafSecretKey: bootstrap.leafSecretKey,
				initSecretKey: bootstrap.initSecretKey,
				keyPackage: bootstrap.keyPackage
			), initialTheirKP: their, pqTurnMine: true, leafKeys: leafKeys)
		// The send group (Group_A) exists from construction: capture its
		// birth epoch's rendezvous address before minting the baseline
		// archive (routing works from birth, book session-lifecycle.md).
		try session.recordListenRendezvous()
		// Group_A is a full pair from construction, so its send-PQ half
		// exists immediately too — capture its birth-epoch header key
		// alongside (PR2).
		try session.recordPQHeaderKey()
		// Same "works from birth" reasoning, `0xFF03` attachment component
		// (+Attachment.swift).
		try session.captureSendAttachmentComponent()
		// `apqWelcomeA` IS this session's first staple — the baseline
		// `StateUpdate` (there is no separate sink/`installSink` call).
		session.markStapleInstalled()
		let baseline = try session.stateUpdate(kind: .checkpoint)
		return EstablishResult(
			session: session, welcome: apqWelcomeA, baseline: baseline,
			returnKeyPackage: session.identity.keyPackage.classical)
	}

	/// KP′'s MLSMessage-wrapped wire bytes (§11 #7), derived on demand from
	/// the still-live `bootstrapKPSecret` rather than a separately stored
	/// field — the public form can then never outlive the private one.
	/// `nil` on the responder, or once `pqBootstrapJoin` has spent the secret.
	func bootstrapKPBytes() throws -> Data? {
		guard let secret = bootstrapKPSecret else { return nil }
		return try MLS.RFC9420.Message.keyPackage(secret.keyPackage).mlsEncoded()
	}

	/// `sha256(bootstrapKP)` — the commitment the initiator hands the
	/// responder out of band (typically stapled alongside `welcome`, or
	/// threaded into the peer's `receive` call), and the responder later
	/// checks the §A.3 `pqBootstrapBegin` frame's KP′ against.
	public func bootstrapKPCommitment() throws -> Data {
		guard let bootstrapKP = try bootstrapKPBytes() else {
			throw TwoMLSError.sessionNotReady
		}
		return try classicalProvider.hash(bootstrapKP)
	}

	/// Join Group_A from the initiator's welcome, then found Group_B
	/// (classical-only, deferred PQ) with the cross-party PSK exported off the
	/// freshly-joined Group_A.classical. `isEstablished` is true immediately —
	/// the acceptor never waits on an inbound frame.
	///
	/// `bootstrapKPCommitment` is the initiator's `H(KP′)` (its
	/// `bootstrapKPCommitment()`), pinned here before any state is claimed —
	/// it must be exactly 32 bytes, else `.bootstrapKPMismatch`.
	///
	/// Internal: the app-facing entry point is `Invitation.receive`, which
	/// delegates here with its captured identity and the caller's
	/// `spawnToken`; this lower-level primitive stays available in-module
	/// for tests that need direct identity access. `spawnToken` is `nil` for
	/// those direct callers — a session accepted that way has no forward-
	/// table routing to acknowledge.
	///
	/// `expectedAppBinding` is a TRAILING optional — the app-state binding
	/// the joined welcome must carry: an exact, symmetric match (`Some`
	/// byte-equal, `None` unbound), verified against Group_A right after the
	/// join and BEFORE the AS seed or any caller-side state claim (book
	/// group-rules.md rule 8) — a rejected welcome consumes nothing
	/// (`Invitation.receive` stages its four tables on a copy only after
	/// this call returns). An empty expectation is rejected up front, before
	/// any group is even decoded — empty is reserved-invalid, so it could
	/// never match.
	///
	/// `newClientID` (slice 11, contract-26) is the reserved trailing slot:
	/// when it differs from `identity.clientID`, this mints a fresh,
	/// dedicated principal D under it to found Group_B — the session
	/// `identity` becomes D, while `recvGroup` (Group_A) stays joined under
	/// the invitation identity (protocol-flows.md:407-432). `nil` or equal
	/// to `identity.clientID` degenerates to today's nil topology
	/// (unchanged, no gate, no `0x0B` staple). Empty (but non-nil) is
	/// reserved-invalid, rejected here before any group is even decoded.
	static func receive(
		identity: TwoMLSIdentity,
		welcome: Data,
		theirClassicalKeyPackage: MLS.RFC9420.KeyPackage,
		bootstrapKPCommitment: Data,
		spawnToken: Data? = nil,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed,
		expectedAppBinding: Data? = nil,
		newClientID: Data? = nil
	) throws -> EstablishResult {
		guard classicalProvider.cipherSuite == TwoMLSSuite.classical,
			pqProvider.cipherSuite == TwoMLSSuite.pq
		else { throw TwoMLSError.cipherSuiteMismatch }
		guard expectedAppBinding.map(\.isEmpty) != true else {
			throw TwoMLSError.appBindingMismatch
		}
		if let newClientID {
			guard !newClientID.isEmpty else { throw TwoMLSError.invalidClientID }
		}

		guard bootstrapKPCommitment.count == 32 else {
			throw TwoMLSError.bootstrapKPMismatch
		}
		let (tBytes, pqBytes) = try Frames.decodeAPQWelcome(welcome)
		let apqWelcome = MLS.Combiner.APQWelcome(
			tWelcome: try MLS.RFC9420.Welcome(mlsEncoded: tBytes),
			pqWelcome: try MLS.RFC9420.Welcome(mlsEncoded: pqBytes))

		var groupA = try APQGroup.joinFull(
			welcome: apqWelcome,
			classicalCredentials: identity.classicalJoinCredentials,
			pqCredentials: identity.pqJoinCredentials,
			classicalProvider: classicalProvider,
			pqProvider: pqProvider, codepoints: codepoints)
		try TwoPartyRules.ensureTwoParty(groupA.classical)
		if let pq = groupA.pq {
			try TwoPartyRules.ensureTwoParty(pq)
		}

		// Slice-2 seam CLOSED: the AS seeds `theirs` from the creator leaf this
		// join actually landed — read straight off the joined tree, not a claim
		// — then requires the caller-supplied `theirClassicalKeyPackage` to
		// present that SAME identity (Rust's mandatory welcome-creator ≡ KP
		// binding, `two-mls-pq/src/session/mod.rs`). A KeyPackage naming any
		// other party — including this device's own id — is rejected here,
		// rather than relying solely on the 0xFF02 cross-party PSK export
		// failing later.
		let peerLeaf = try Self.joinedCreatorLeaf(of: groupA.classical)
		let peerID = try basicIdentifier(peerLeaf.credential)
		guard try basicIdentifier(theirClassicalKeyPackage.leafNode.credential) == peerID
		else { throw TwoMLSError.remoteIdentityMismatch }
		// Defense-in-depth: a dedicated id equal to the remote/initiator's own
		// id can never be legitimate (it would found Group_B under an identity
		// the peer already occupies in Group_A) — reject before minting.
		if let newClientID, newClientID == peerID {
			throw TwoMLSError.invalidClientID
		}

		// App-state binding: the joined welcome must carry exactly the binding
		// the caller expects (book group-rules.md rule 8) — verified before the
		// AS seed just below, so a rejected welcome (`Invitation.receive` stages
		// its tables only after this call returns) leaves everything reusable.
		// The PQ half inherits coverage through the `APQInfo` half-binding; a
		// smuggled PQ-half copy is rejected at every PQ-half join.
		try verifyAppBinding(groupA.classical, expected: expectedAppBinding)
		try verifyPQHalfUnbound(groupA.pq)
		if expectedAppBinding != nil {
			try ensureAppBindingCreatorLeafAdvert(peerLeaf)
		}
		// Mirrored onto Group_B below — re-read off the just-verified group
		// rather than trusting the caller's claim a second time (matches
		// `verifyAppBinding`'s own ground truth).
		let verifiedAppBinding = try AppBinding.read(
			fromExtensionsOf: groupA.classical.context)

		// Mint the dedicated principal D ONLY when `newClientID` differs from
		// the invitation identity (protocol-flows.md:420, credential-differ
		// rule) — equal/nil
		// degenerates to today's nil topology below. D founds Group_B under
		// a completely fresh identity (fresh signing key, fresh classical+PQ
		// leaves): a born-dedicated principal never joins, so both init
		// secrets are cleared immediately (mirrors `clearingInitSecrets`'s
		// "never separately read" reasoning at `initiate`/`receive`).
		let dedicated: TwoMLSIdentity?
		if let newClientID, newClientID != identity.clientID {
			dedicated = try TwoMLSIdentity.generate(
				clientID: newClientID, classicalProvider: classicalProvider,
				pqProvider: pqProvider
			).clearingInitSecrets(classical: true, pq: true)
		} else {
			dedicated = nil
		}
		let founderIdentity = dedicated ?? identity
		// Minted once here so founding and the stored `leafKeys` below read
		// the identical local value, rather than re-deriving it from
		// `founderIdentity` twice.
		let sendClassicalKey = LeafKey(
			signingKey: founderIdentity.signingKey,
			signatureKey: founderIdentity.signatureKey)

		let crossPSK = try MLS.Combiner.ExportedPsk.export(
			from: &groupA.classical, classicalProvider,
			componentID: crossPartyComponentID)

		let founderHalf = try halfCreation(
			identity: founderIdentity, half: founderIdentity.keyPackage.classical,
			leafSecretKey: founderIdentity.classicalLeafSecretKey,
			signingKey: sendClassicalKey.signingKey,
			peerKeyPackage: theirClassicalKeyPackage, provider: classicalProvider)
		// Pre-allocated: Group_B's PQ half is not founded in slice 1 (A.3), but
		// its `APQInfo` still names the eventual group id (a draft-02 PARTIAL).
		let pqGroupID = pqProvider.randomBytes(pqProvider.hashSize)
		let nonce = classicalProvider.randomBytes(classicalProvider.hashSize)

		let (groupB, classicalWelcomeB) = try APQGroup.establishClassicalOnly(
			founder: founderHalf, pqGroupID: pqGroupID, crossPSK: crossPSK,
			nonce: nonce,
			provider: classicalProvider, appBinding: verifiedAppBinding,
			codepoints: codepoints)
		try TwoPartyRules.ensureTwoParty(groupB.classical)

		let apqWelcomeB = Frames.encodeAPQWelcome(
			t: try classicalWelcomeB.mlsEncoded(), pq: Data())

		// Both of `identity`'s init secrets are now spent: `classicalJoin-
		// Credentials`/`pqJoinCredentials` already joined `groupA` above (the
		// only join this identity ever does), and `groupB` was FOUNDED, not
		// joined (founding takes only the leaf secret). Clear both before
		// the baseline archive can ever carry them — a reusable invitation's
		// identity is the SAME published key package across every welcome
		// it accepts, so a leaked (sealed) session archive must not also
		// expose the still-published key package's init secret.
		let establishedIdentity = identity.clearingInitSecrets(classical: true, pq: true)
		let sessionIdentity = dedicated ?? establishedIdentity

		// AS both sides (Bob): with a dedicated principal, seed `mine`
		// from the invitation identity then commit D — `.current == D`,
		// with the invitation id retained in `history` for the recv leaf's
		// custody arm (`myPrincipalState == .sync(D)`). Degenerate topology
		// is unchanged.
		let auth: AuthCore
		let recvLeafPrincipal: RecvLeafPrincipal?
		if dedicated != nil, let newClientID {
			var mine = PartySequence.seeded(identity.clientID)
			try mine.commit(newClientID)
			auth = AuthCore(mine: mine, theirs: .seeded(peerID))
			recvLeafPrincipal = RecvLeafPrincipal(
				clientID: identity.clientID, signingKey: identity.signingKey,
				signatureKey: identity.signatureKey,
				pqSigningKey: identity.pqSigningKey,
				pqSignatureKey: identity.pqSignatureKey)
		} else {
			auth = AuthCore(mine: .seeded(identity.clientID), theirs: .seeded(peerID))
			recvLeafPrincipal = nil
		}

		// Send-classical/send-PQ present the FOUNDER identity (D when
		// dedicated, else the invitation identity) from the moment Group_B
		// is founded; recv-PQ always joins under the ORIGINAL invitation
		// identity's already-signed PQ leaf (Group_A was joined above with
		// `identity.classicalJoinCredentials`/`pqJoinCredentials`, before
		// any dedicated principal exists). recv-classical is the one
		// split: the degenerate topology joins under `identity` directly (no
		// dedicated principal, nothing to catch up), while the born-dedicated
		// topology's recv-classical leaf still presents the INVITATION
		// identity, with D's key staged as the rule-4 target
		// (group-rules.md rule 4) — written here, at the exact moment D is
		// minted, matching the live `recvLeafPrincipal` custody this mirrors.
		let sendPQKey = LeafKey(
			signingKey: founderIdentity.pqSigningKey,
			signatureKey: founderIdentity.pqSignatureKey)
		let recvPQKey = LeafKey(
			signingKey: identity.pqSigningKey, signatureKey: identity.pqSignatureKey)
		let recvClassical: GroupKeySet
		if let newClientID, dedicated != nil {
			let invitationClassicalKey = LeafKey(
				signingKey: identity.signingKey, signatureKey: identity.signatureKey
			)
			recvClassical = GroupKeySet(
				current: invitationClassicalKey,
				pending: [newClientID: sendClassicalKey])
		} else {
			recvClassical = GroupKeySet(current: sendClassicalKey)
		}
		let leafKeys = LeafKeys(
			sendClassical: GroupKeySet(current: sendClassicalKey),
			recvClassical: recvClassical,
			sendPQ: GroupKeySet(current: sendPQKey),
			recvPQ: GroupKeySet(current: recvPQKey))

		var session = TwoMLSSession(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, identity: sessionIdentity, auth: auth,
			sendGroup: groupB, recvGroup: groupA,
			currentStaple: apqWelcomeB, pendingProposal: nil,
			joinedWelcomeDigest: try classicalProvider.hash(welcome), initiated: false,
			expectedBootstrapKPCommitment: bootstrapKPCommitment, pqTurnMine: false,
			// §11 #1: `lastCrossInjected` tracks the epoch of `recvGroup.classical`
			// (Group_A, joined above) at the last cross-party PSK injection —
			// Bob's freshly-joined copy is already at epoch 1, so the watermark
			// seeds there too.
			lastCrossInjected: 1, spawnToken: spawnToken,
			recvLeafPrincipal: recvLeafPrincipal,
			owesEstablishmentEnvelope: dedicated != nil, leafKeys: leafKeys)
		// The send group (Group_B) exists from construction: capture its
		// birth epoch's rendezvous address before minting the baseline
		// archive (routing works from birth, book session-lifecycle.md).
		try session.recordListenRendezvous()
		// Group_B is classical-only pre-A.3 (PR2): a no-op today, kept for
		// call-site symmetry with `initiate` and against a future establish
		// shape that founds the PQ half earlier.
		try session.recordPQHeaderKey()
		// Same "works from birth" reasoning, `0xFF03` attachment component
		// (+Attachment.swift) — send-side (Group_B) and, CAPTURE-ON-ENTRY,
		// recv-side (Group_A, this session's recv group from the moment it
		// joins here).
		try session.captureSendAttachmentComponent()
		try session.captureRecvAttachmentComponent()
		// `apqWelcomeB` IS this session's first staple — the baseline
		// `StateUpdate` (there is no separate sink/`installSink` call).
		session.markStapleInstalled()
		let baseline = try session.stateUpdate(kind: .checkpoint)
		return EstablishResult(
			session: session, welcome: apqWelcomeB, baseline: baseline,
			returnKeyPackage: session.identity.keyPackage.classical)
	}

	// MARK: - Contract-26 non-emittable gate + install

	/// The non-emittable gate: throws while a dedicated
	/// principal's contract-26 handoff is still owed. Call FIRST in every
	/// frame-producing public method — a commit before install would
	/// replace the bare `0x01` staple and make `installEstablishmentEnvelope`
	/// fail `.sessionNotReady` forever.
	func ensureEstablishmentDelegated() throws {
		guard !owesEstablishmentEnvelope else {
			throw TwoMLSError.establishmentEnvelopeRequired
		}
	}

	/// Wraps `currentStaple` (still the bare `0x01` `apqWelcomeB`) in the
	/// contract-26 signed handoff blob — NOT the §A.1 HPKE envelope of
	/// `EstablishmentEnvelope.swift`, a different mechanism entirely: this is
	/// the signed delegation the host mints (over `initialWelcome()`'s bytes)
	/// proving D's succession from the invitation identity, carried on the
	/// message path as a `0x0B` staple (`Frames.encodeEstablishmentHandoff`).
	///
	/// - empty `envelope` → `.establishmentEnvelopeRequired`.
	/// - already installed, IDENTICAL `envelope` → idempotent no-op (still
	///   bumps `stateSeq`/returns a fresh `StateUpdate`, like every other
	///   idempotent re-send in this module).
	/// - already installed, DIFFERENT `envelope` → `.establishmentEnvelopeConflict`.
	/// - not owed, and not already installed → `.sessionNotReady` (also the
	///   fail-closed catch-all when `currentStaple` somehow moved off the
	///   bare `0x01` shape without ever installing, Rust mod.rs:2018-22).
	/// - success: `currentStaple` becomes the `0x0B` handoff, the gate
	///   clears, and — being a SECOND writer of `currentStaple` alongside
	///   `committingRound` — this advances `stateSeq` then
	///   `markStapleInstalled()` before persisting, so `PrepareResult.dependsOnSeq`
	///   gates transmitting a later re-staple on this update's durability.
	public mutating func installEstablishmentEnvelope(_ envelope: Data) throws -> StateUpdate {
		guard !envelope.isEmpty else { throw TwoMLSError.establishmentEnvelopeRequired }
		if currentStaple.first == Frames.establishmentHandoffTag {
			let (installed, _) = try Frames.decodeEstablishmentHandoff(currentStaple)
			guard installed == envelope else {
				throw TwoMLSError.establishmentEnvelopeConflict
			}
			advanceStateSeq()
			return try stateUpdate(kind: .core)
		}
		guard owesEstablishmentEnvelope, currentStaple.first == Frames.apqWelcomeTag else {
			throw TwoMLSError.sessionNotReady
		}
		currentStaple = Frames.encodeEstablishmentHandoff(
			envelope: envelope, welcome: currentStaple)
		owesEstablishmentEnvelope = false
		advanceStateSeq()
		markStapleInstalled()
		return try stateUpdate(kind: .core)
	}

	/// The peer's occupied leaf in a freshly-joined 2-party group, read
	/// straight off the tree — the AS's admission check must be cryptographic
	/// fact, not a caller-supplied claim. Reached only after
	/// `TwoPartyRules.ensureTwoParty`, so exactly one non-self leaf exists.
	// internal: used by APQGroup.joinClassicalOnly
	static func joinedCreatorLeaf(of group: MLS.RFC9420.Group) throws
		-> MLS.RFC9420.LeafNode
	{
		guard
			let entry = group.tree.nonBlankLeaves().first(where: {
				$0.index != group.myLeafIndex
			})
		else { throw TwoMLSError.unknownIdentity }
		return try MLS.RFC9420.LeafNode(mlsEncoded: entry.record.encoded)
	}

	/// A `HalfCreation` for `identity`'s own already-signed half adding `peer`,
	/// with fresh randomness/group id — the founder side of either an
	/// `establishFull` or an `establishClassicalOnly`. `signingKey` is a
	/// REQUIRED param (D1, FIX3): under independent per-half signing keys
	/// there is no single "the" identity signing key to default to — every
	/// caller states which of `identity`'s two pairs signs this half
	/// (classical → `identity.signingKey`, PQ → `identity.pqSigningKey`).
	private static func halfCreation(
		identity: TwoMLSIdentity,
		half: MLS.RFC9420.KeyPackage,
		leafSecretKey: MLS.HpkeSecretKey,
		signingKey: MLS.SignatureSecretKey,
		peerKeyPackage: MLS.RFC9420.KeyPackage,
		provider: any MLS.CipherSuiteProvider
	) throws -> MLS.Combiner.HalfCreation {
		MLS.Combiner.HalfCreation(
			groupID: provider.randomBytes(provider.hashSize),
			leafNode: half.leafNode,
			leafSecretKey: leafSecretKey,
			signingKey: signingKey,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize),
			randomness: try .generate(provider),
			peerKeyPackage: peerKeyPackage)
	}
}
