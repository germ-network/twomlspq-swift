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
	/// signing key (book concepts.md's credential-scoped signer — every leaf
	/// a principal mints shares its one signing key) and delegate.
	public static func initiate(
		principal: Principal,
		their: CombinerKeyPackage
	) throws -> EstablishResult {
		let identity = try TwoMLSIdentity.generate(
			clientID: principal.clientID, signingKey: principal.signingKey,
			signatureKey: principal.signatureKey,
			classicalProvider: principal.classicalProvider,
			pqProvider: principal.pqProvider)
		return try initiate(
			identity: identity, their: their,
			classicalProvider: principal.classicalProvider,
			pqProvider: principal.pqProvider, codepoints: principal.codepoints)
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
	static func initiate(
		identity: TwoMLSIdentity,
		their: CombinerKeyPackage,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> EstablishResult {
		guard classicalProvider.cipherSuite == TwoMLSSuite.classical,
			pqProvider.cipherSuite == TwoMLSSuite.pq
		else { throw TwoMLSError.cipherSuiteMismatch }

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

		let classicalHalf = try halfCreation(
			identity: identity, half: identity.keyPackage.classical,
			leafSecretKey: identity.classicalLeafSecretKey,
			peerKeyPackage: their.classical,
			provider: classicalProvider)
		let pqHalf = try halfCreation(
			identity: identity, half: identity.keyPackage.pq,
			leafSecretKey: identity.pqLeafSecretKey, peerKeyPackage: their.pq,
			provider: pqProvider)

		let (groupA, welcome) = try APQGroup.establishFull(
			classical: classicalHalf, pq: pqHalf, mode: 0,
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints)

		let apqWelcomeA = Frames.encodeAPQWelcome(
			t: try welcome.tWelcome.mlsEncoded(), pq: try welcome.pqWelcome.mlsEncoded()
		)

		// Mint the §A.3 bootstrap KeyPackage KP′ now: a fresh leaf+init
		// keypair distinct from `identity.keyPackage.pq` (Alice's leaf IN
		// Group_A) — what Bob Adds into the new Group_B.pq. Its commitment
		// `H(KP′)` hashes the MLSMessage-wrapped bytes (§11 #7).
		let bootstrap = try identity.freshPQKeyPackage(pqProvider: pqProvider)

		var session = TwoMLSSession(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, identity: identity, auth: auth, sendGroup: groupA,
			recvGroup: nil,
			currentStaple: apqWelcomeA, pendingProposal: nil, joinedWelcomeDigest: nil,
			initiated: true,
			bootstrapKPSecret: (
				leafSecretKey: bootstrap.leafSecretKey,
				initSecretKey: bootstrap.initSecretKey,
				keyPackage: bootstrap.keyPackage
			), pqTurnMine: true)
		// `apqWelcomeA` IS this session's first staple — the baseline
		// `StateUpdate` (there is no separate sink/`installSink` call).
		session.markStapleInstalled()
		let baseline = try session.stateUpdate(kind: .checkpoint)
		return EstablishResult(session: session, welcome: apqWelcomeA, baseline: baseline)
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
	static func receive(
		identity: TwoMLSIdentity,
		welcome: Data,
		theirClassicalKeyPackage: MLS.RFC9420.KeyPackage,
		bootstrapKPCommitment: Data,
		spawnToken: Data? = nil,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> EstablishResult {
		guard classicalProvider.cipherSuite == TwoMLSSuite.classical,
			pqProvider.cipherSuite == TwoMLSSuite.pq
		else { throw TwoMLSError.cipherSuiteMismatch }

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
		let auth = AuthCore(
			mine: .seeded(identity.clientID), theirs: .seeded(peerID))

		let crossPSK = try MLS.Combiner.ExportedPsk.export(
			from: &groupA.classical, classicalProvider,
			componentID: crossPartyComponentID)

		let founderHalf = try halfCreation(
			identity: identity, half: identity.keyPackage.classical,
			leafSecretKey: identity.classicalLeafSecretKey,
			peerKeyPackage: theirClassicalKeyPackage, provider: classicalProvider)
		// Pre-allocated: Group_B's PQ half is not founded in slice 1 (A.3), but
		// its `APQInfo` still names the eventual group id (a draft-02 PARTIAL).
		let pqGroupID = pqProvider.randomBytes(pqProvider.hashSize)
		let nonce = classicalProvider.randomBytes(classicalProvider.hashSize)

		let (groupB, classicalWelcomeB) = try APQGroup.establishClassicalOnly(
			founder: founderHalf, pqGroupID: pqGroupID, crossPSK: crossPSK,
			nonce: nonce,
			provider: classicalProvider, codepoints: codepoints)
		try TwoPartyRules.ensureTwoParty(groupB.classical)

		let apqWelcomeB = Frames.encodeAPQWelcome(
			t: try classicalWelcomeB.mlsEncoded(), pq: Data())

		var session = TwoMLSSession(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, identity: identity, auth: auth, sendGroup: groupB,
			recvGroup: groupA,
			currentStaple: apqWelcomeB, pendingProposal: nil,
			joinedWelcomeDigest: try classicalProvider.hash(welcome), initiated: false,
			expectedBootstrapKPCommitment: bootstrapKPCommitment, pqTurnMine: false,
			// §11 #1: `lastCrossInjected` tracks the epoch of `recvGroup.classical`
			// (Group_A, joined above) at the last cross-party PSK injection —
			// Bob's freshly-joined copy is already at epoch 1, so the watermark
			// seeds there too.
			lastCrossInjected: 1, spawnToken: spawnToken)
		// `apqWelcomeB` IS this session's first staple — the baseline
		// `StateUpdate` (there is no separate sink/`installSink` call).
		session.markStapleInstalled()
		let baseline = try session.stateUpdate(kind: .checkpoint)
		return EstablishResult(session: session, welcome: apqWelcomeB, baseline: baseline)
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
	/// `establishFull` or an `establishClassicalOnly`.
	private static func halfCreation(
		identity: TwoMLSIdentity,
		half: MLS.RFC9420.KeyPackage,
		leafSecretKey: MLS.HpkeSecretKey,
		peerKeyPackage: MLS.RFC9420.KeyPackage,
		provider: any MLS.CipherSuiteProvider
	) throws -> MLS.Combiner.HalfCreation {
		MLS.Combiner.HalfCreation(
			groupID: provider.randomBytes(provider.hashSize),
			leafNode: half.leafNode,
			leafSecretKey: leafSecretKey,
			signingKey: identity.signingKey,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize),
			randomness: try .generate(provider),
			peerKeyPackage: peerKeyPackage)
	}
}
