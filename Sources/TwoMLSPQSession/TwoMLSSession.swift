import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import MLSTreeMath

/// The result of `initiate`/`receive`: the session plus the welcome staple to
/// hand the peer out of band. Slice 1 omits the §A.1 header-encryption
/// envelope, so the frame rides un-sealed — the Welcome still HPKE-seals its
/// own group secrets to the joiner; only the outer envelope is deferred.
@available(iOS 26, macOS 26, *)
public struct EstablishResult: Sendable {
	public let session: TwoMLSSession
	public let welcome: Data
}

/// The result of `prepareToEncrypt`: slice 1's routine no-commit path always
/// stages an `Upd(self)` into the receive group rather than committing.
public struct PrepareResult: Sendable {
	public let proposalMessage: Data
	public let proposalHash: Data
	public let didCommit: Bool
}

/// Which §A.3 bootstrap side-band step is outstanding on this session, if
/// any — `pqBootstrapBegin`/`pqBootstrapRespond` set it; `applyBind` clears
/// it once the bind lands.
enum PQInflight: Sendable, Equatable {
	case bootstrapInitiated
	case bootstrapResponded
}

/// Alice's parked PQ-half bind commit (`owePQBind`), owed to
/// `sendGroup.classical` until a licensed `prepareToEncrypt` can discharge it
/// (§4).
struct OwedBind: Sendable {
	var pqCommitMessage: Data
	var tEpoch: UInt64
	var pqEpoch: UInt64
}

/// The peer's staged proposal, carried uninterpreted alongside a
/// `DecryptResult` — `digest` is `sha256` of the proposal bytes, `proposing`
/// is the sender's `ClientId`.
public struct QueuedProposal: Sendable {
	public let digest: Data
	public let proposing: Data
}

/// The result of `processIncoming`: the decrypted application payload, its
/// epoch-bound sender, and the peer's staged proposal — carried, not folded,
/// in slice 1 (the fold path lands with commits in slice 2).
public struct DecryptResult: Sendable {
	public let applicationMessage: Data
	public let sender: MLS.LeafIndex
	public let epoch: UInt64
	/// The app message's own carried `authenticated_data` — `sha256` of the
	/// proposal bytes the sender framed alongside it. Round-trips as a value;
	/// `unprotect` never checks it against `queuedProposal` (M1).
	public let authenticatedData: Data
	public let queuedProposal: QueuedProposal
}

/// One directional APQ session: a send group (`sendGroup` — my Group_B,
/// classical-only) and a receive group (`recvGroup` — my copy of the peer's
/// Group_A, the full pair), plus the un-header-sealed staple re-sent with every
/// frame until the first commit (slice 2+). Value type with `mutating`
/// methods, matching the profile `Group` idiom: a single-owner, non-forkable
/// state machine.
@available(iOS 26, macOS 26, *)
public struct TwoMLSSession: Sendable {
	/// The session-layer cross-party PSK component id (`0xFF02`) — distinct
	/// from the combiner's own `apq_psk` component (`0xFF01`, `Codepoints`);
	/// derived on demand from each party's own Group_A.classical copy, never
	/// carried on the wire or ledgered (m6).
	static let crossPartyComponentID = MLS.Extensions.ComponentID(rawValue: 0xFF02)

	let classicalProvider: any MLS.CipherSuiteProvider
	let pqProvider: any MLS.CipherSuiteProvider
	let codepoints: MLS.Combiner.Codepoints
	let identity: TwoMLSIdentity
	var sendGroup: APQGroup?
	var recvGroup: APQGroup?
	var currentStaple: Data
	var pendingProposal: (proposing: Data, message: Data, hash: Data)?
	var joinedWelcomeDigest: Data?
	let initiated: Bool
	/// The initiator's (Alice's) pre-committed bootstrap `KeyPackage` KP′,
	/// MLSMessage-wrapped (§11 #7) — `nil` on the responder (Bob). Minted at
	/// `initiate`, spent by `pqBootstrapRespond`.
	var bootstrapKP: Data?
	/// KP′'s own leaf+init secrets plus the `KeyPackage` itself — the
	/// initiator's joiner credentials for `pqBootstrapJoin`. `nil` on the
	/// responder.
	var bootstrapKPSecret:
		(
			leafSecretKey: MLS.HpkeSecretKey, initSecretKey: MLS.HpkeSecretKey,
			keyPackage: MLS.RFC9420.KeyPackage
		)?
	/// The responder's (Bob's) pinned `H(KP′)`, validated at `receive` —
	/// `nil` on the initiator.
	var expectedBootstrapKPCommitment: Data?
	/// Whose turn it is to drive the next PQ-bootstrap/bind step — `true` on
	/// the initiator (Alice owns the bootstrap), `false` on the responder,
	/// until the bind passes it back (`applyBind`).
	var pqTurnMine: Bool
	/// Alice's PQ-half bind commit, parked after `owePQBind` until a licensed
	/// `prepareToEncrypt` can discharge it (§4). `nil` once discharged.
	var owedBind: OwedBind?
	/// Which §A.3 side-band step is outstanding, if any.
	var pqInflight: PQInflight?
	/// The retained `0x13`/`0x15` side-band frame, for `pqBootstrapBegin`'s
	/// idempotent re-send.
	var pendingSideBand: Data?
	/// The discharge license (§5): `sendGroup.classical`'s epoch, as evidenced
	/// by the peer's inbound `Upd(self)` proposal validating against it
	/// (`processIncoming`'s `stampLicenseIfOffered`).
	var peerAppliedSendEpoch: UInt64?
	/// The last `recvGroup.classical` epoch whose cross-party `0xFF02` PSK
	/// Alice has injected into a discharge — a watermark, not a full ledger
	/// (§11 #1). Bob seeds this to `1` in `receive` (mirroring the
	/// establishment-time cross-party binding epoch); Alice's stays `nil`
	/// until her first discharge.
	var lastCrossInjected: UInt64?
	/// The `recvGroup.pq` epoch `owePQBind` exported the cross-party `0xFF02`
	/// PSK (`S`) from — carried for A.5, not guarded here.
	var lastCrossInjectedPQ: UInt64?
	/// The `sendGroup.pq` epoch `applyBind` re-exported `S` from — carried for
	/// A.5, not guarded here.
	var lastSendPQExported: UInt64?

	public var isEstablished: Bool { sendGroup != nil && recvGroup != nil }
	/// Both directional pairs have their PQ half present — the §A.3
	/// bootstrap's completion condition.
	public var isFullyEstablished: Bool { sendGroup?.pq != nil && recvGroup?.pq != nil }
	public var myPQTurn: Bool { pqTurnMine }

	init(
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints,
		identity: TwoMLSIdentity,
		sendGroup: APQGroup?,
		recvGroup: APQGroup?,
		currentStaple: Data,
		pendingProposal: (proposing: Data, message: Data, hash: Data)?,
		joinedWelcomeDigest: Data?,
		initiated: Bool,
		bootstrapKP: Data? = nil,
		bootstrapKPSecret:
			(
				leafSecretKey: MLS.HpkeSecretKey, initSecretKey: MLS.HpkeSecretKey,
				keyPackage: MLS.RFC9420.KeyPackage
			)? = nil,
		expectedBootstrapKPCommitment: Data? = nil,
		pqTurnMine: Bool,
		owedBind: OwedBind? = nil,
		pqInflight: PQInflight? = nil,
		pendingSideBand: Data? = nil,
		peerAppliedSendEpoch: UInt64? = nil,
		lastCrossInjected: UInt64? = nil,
		lastCrossInjectedPQ: UInt64? = nil,
		lastSendPQExported: UInt64? = nil
	) {
		self.classicalProvider = classicalProvider
		self.pqProvider = pqProvider
		self.codepoints = codepoints
		self.identity = identity
		self.sendGroup = sendGroup
		self.recvGroup = recvGroup
		self.currentStaple = currentStaple
		self.pendingProposal = pendingProposal
		self.joinedWelcomeDigest = joinedWelcomeDigest
		self.initiated = initiated
		self.bootstrapKP = bootstrapKP
		self.bootstrapKPSecret = bootstrapKPSecret
		self.expectedBootstrapKPCommitment = expectedBootstrapKPCommitment
		self.pqTurnMine = pqTurnMine
		self.owedBind = owedBind
		self.pqInflight = pqInflight
		self.pendingSideBand = pendingSideBand
		self.peerAppliedSendEpoch = peerAppliedSendEpoch
		self.lastCrossInjected = lastCrossInjected
		self.lastCrossInjectedPQ = lastCrossInjectedPQ
		self.lastSendPQExported = lastSendPQExported
	}
}

// MARK: - Establishment

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Found Group_A (a full pair) and return the un-header-sealed `APQWelcome_A` to
	/// hand the acceptor out of band. `isEstablished` is false until the
	/// acceptor's first frame is processed (no receive group yet).
	public static func initiate(
		identity: TwoMLSIdentity,
		their: CombinerKeyPackage,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> EstablishResult {
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
		let bootstrapKPBytes = try MLS.RFC9420.Message.keyPackage(bootstrap.keyPackage)
			.mlsEncoded()

		let session = TwoMLSSession(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, identity: identity, sendGroup: groupA,
			recvGroup: nil,
			currentStaple: apqWelcomeA, pendingProposal: nil, joinedWelcomeDigest: nil,
			initiated: true, bootstrapKP: bootstrapKPBytes,
			bootstrapKPSecret: (
				leafSecretKey: bootstrap.leafSecretKey,
				initSecretKey: bootstrap.initSecretKey,
				keyPackage: bootstrap.keyPackage
			), pqTurnMine: true)
		return EstablishResult(session: session, welcome: apqWelcomeA)
	}

	/// `sha256(bootstrapKP)` — the commitment the initiator hands the
	/// responder out of band (typically stapled alongside `welcome`, or
	/// threaded into the peer's `receive` call), and the responder later
	/// checks the §A.3 `pqBootstrapBegin` frame's KP′ against.
	public func bootstrapKPCommitment() throws -> Data {
		guard let bootstrapKP else { throw TwoMLSError.sessionNotReady }
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
	public static func receive(
		identity: TwoMLSIdentity,
		welcome: Data,
		theirClassicalKeyPackage: MLS.RFC9420.KeyPackage,
		bootstrapKPCommitment: Data,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> EstablishResult {
		guard bootstrapKPCommitment.count == 32 else {
			throw TwoMLSError.bootstrapKPMismatch
		}
		let (tBytes, pqBytes) = try Frames.decodeAPQWelcome(welcome)
		let apqWelcome = MLS.Combiner.APQWelcome(
			tWelcome: try MLS.RFC9420.Welcome(mlsEncoded: tBytes),
			pqWelcome: try MLS.RFC9420.Welcome(mlsEncoded: pqBytes))
		// Slice-2 seam: this does not check the creator's leaf credential
		// against `theirClassicalKeyPackage` (Rust's `RemoteIdentityMismatch` /
		// `expected_remote`). It currently fails closed regardless — a
		// mismatched party cannot derive the same 0xFF02 cross-party PSK below,
		// since that PSK is exported off THIS freshly-joined Group_A.classical.

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

		let session = TwoMLSSession(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, identity: identity, sendGroup: groupB,
			recvGroup: groupA,
			currentStaple: apqWelcomeB, pendingProposal: nil,
			joinedWelcomeDigest: try classicalProvider.hash(welcome), initiated: false,
			expectedBootstrapKPCommitment: bootstrapKPCommitment, pqTurnMine: false,
			// §11 #1: mirrors the establishment-time cross-party binding epoch
			// — Bob's own send group (Group_B.classical) is founded at epoch 1
			// here, so its watermark starts there too.
			lastCrossInjected: 1)
		return EstablishResult(session: session, welcome: apqWelcomeB)
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
			epochSecret: provider.randomBytes(provider.hashSize),
			randomness: try .generate(provider),
			peerKeyPackage: peerKeyPackage)
	}
}

// MARK: - Send / receive (one app message; no commit)

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Stage a routine `Upd(self)` into the **receive** group (the peer's send
	/// group, where the peer folds it) — framed `.publicMessage` to match the
	/// Rust reference's control-message framing (m4). Requires `isEstablished`:
	/// the initiator cannot send before its first inbound frame joins Group_B.
	///
	/// First discharges an owed bind if one is licensed
	/// (`dischargeOwedBindIfLicensed`, §4b) — folding it into a FULL commit on
	/// `sendGroup.classical` and stapling the pq+classical commit pair as the
	/// `0x05` bind, so `encrypt` then protects the app on the newly-advanced
	/// epoch. `didCommit` reports whether that happened.
	public mutating func prepareToEncrypt() throws -> PrepareResult {
		guard recvGroup != nil, sendGroup != nil else {
			throw TwoMLSError.notEstablished
		}
		let didCommit = try dischargeOwedBindIfLicensed()

		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }
		let (message, _) = try recv.classical.proposeUpdate(
			classicalProvider, signingKey: identity.signingKey, framing: .publicMessage)
		recvGroup = recv

		let proposalBytes = try message.mlsEncoded()
		// `sha256` for the deployed classical suite (curve25519Aes128), matching
		// the book's fixed sha256 for `proposal_hash`.
		let proposalHash = try classicalProvider.hash(proposalBytes)
		pendingProposal = (
			proposing: identity.clientID, message: proposalBytes, hash: proposalHash
		)
		return PrepareResult(
			proposalMessage: proposalBytes, proposalHash: proposalHash,
			didCommit: didCommit
		)
	}

	/// Seal `app` on the send group with the pending proposal's hash as its
	/// carried `authenticated_data`, and frame it alongside that proposal and
	/// the current staple. The AEAD binds the hash to *this* app message, not
	/// to the frame's separate proposal section — proposal integrity is its own
	/// MLS leaf signature, checked when folded (slice 2) (M1).
	public mutating func encrypt(_ app: Data) throws -> Data {
		guard let pending = pendingProposal else { throw TwoMLSError.noPendingProposal }
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }
		let appPM = try send.classical.protect(
			classicalProvider, applicationData: app, authenticatedData: pending.hash,
			signingKey: identity.signingKey)
		sendGroup = send
		pendingProposal = nil

		// The app section is a full `Message`, not a bare `PrivateMessage` (M2) —
		// matches the proposal section, which already carries a full `Message`.
		let appBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		let proposalSection = Frames.encodeProposalSection(
			proposing: pending.proposing, message: pending.message)
		return Frames.encodeMessageFrame(
			staple: currentStaple, proposal: proposalSection, app: appBytes)
	}

	/// Decode a frame, join Group_B off its staple if this is the first inbound
	/// frame (or skip idempotently if already joined), decrypt the app section
	/// against the receive group, and surface the peer's staged proposal
	/// uninterpreted (carried, not folded, in slice 1).
	public mutating func processIncoming(_ frame: Data) throws -> DecryptResult {
		let (staple, proposalSection, appSection) = try Frames.decodeMessageFrame(frame)
		let appMessage = try MLS.RFC9420.Message(mlsEncoded: appSection)
		guard case .privateMessage(let appPM) = appMessage else {
			throw TwoMLSError.appSectionNotPrivateMessage
		}

		try handleStaple(staple)

		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }
		let unprotected = try recv.classical.unprotect(classicalProvider, message: appPM)
		recvGroup = recv

		guard case .application(let data) = unprotected.content else {
			throw TwoMLSError.unprotectedContentNotApplication
		}

		let (proposing, proposalMessage) = try Frames.decodeProposalSection(proposalSection)
		// `sha256` for the deployed classical suite, matching the book's fixed
		// sha256 for `proposal_hash`.
		let digest = try classicalProvider.hash(proposalMessage)
		stampLicenseIfOffered(proposalMessage)

		return DecryptResult(
			applicationMessage: data, sender: unprotected.sender,
			epoch: unprotected.epoch,
			authenticatedData: unprotected.authenticatedData,
			queuedProposal: QueuedProposal(digest: digest, proposing: proposing))
	}

	/// `0x01` welcome → join Group_B if this staple hasn't been joined yet
	/// (idempotent otherwise, matching the reference's welcome dedup); `0x00`
	/// mlsMessage (commit) → slice 1 sends no commits, so receiving one is an
	/// unsupported protocol state. `0x05` apqPrivateMessage → `applyBind`.
	private mutating func handleStaple(_ staple: Data) throws {
		guard let tag = staple.first else { throw TwoMLSError.truncatedSection }
		switch Frames.stapleKind(tag) {
		case .welcome:
			try joinGroupBIfNeeded(fromStaple: staple)
		case .mlsMessage:
			throw TwoMLSError.commitStapleUnsupported
		case .apqPrivateMessage:
			try applyBind(staple)
		case .unsupported(let tag):
			throw TwoMLSError.unsupportedStapleTag(tag)
		}
	}

	/// §5/§11 #8: the discharge license. If `proposalMessage` (every frame's
	/// routine staged proposal) decodes as a `PublicMessage` `Update` that
	/// verifies against MY OWN `sendGroup.classical` — framed by the peer's
	/// own leaf there, not mine — the peer has evidently applied at least my
	/// current send epoch, so `prepareToEncrypt` may discharge an owed bind
	/// against it. Any other shape (a decode failure, a stale/foreign epoch,
	/// a failed signature, or a proposal apparently framed by my own leaf) is
	/// silently not-a-license, not an error — this is an additional read on
	/// data `processIncoming` already carries uninterpreted, not a required
	/// decode.
	private mutating func stampLicenseIfOffered(_ proposalMessage: Data) {
		withDeployedWireWidth {
			guard let message = try? MLS.RFC9420.Message(mlsEncoded: proposalMessage),
				case .publicMessage(let updatePub) = message,
				let send = sendGroup
			else {
				return
			}
			guard
				let verified = try? send.classical.verifying(
					classicalProvider, proposal: updatePub),
				case .member(let senderLeaf) = verified.sender,
				senderLeaf != send.classical.myLeafIndex
			else {
				return
			}
			peerAppliedSendEpoch = send.classical.context.epoch
		}
	}

	private mutating func joinGroupBIfNeeded(fromStaple staple: Data) throws {
		// `sha256` for the deployed classical suite, matching the book's fixed
		// sha256 for the welcome digest.
		let digest = try classicalProvider.hash(staple)
		if let joined = joinedWelcomeDigest, joined != digest {
			throw TwoMLSError.unexpectedWelcome
		}
		guard joinedWelcomeDigest != digest else { return }

		let (tBytes, pqBytes) = try Frames.decodeAPQWelcome(staple)
		guard pqBytes.isEmpty else { throw TwoMLSError.fullEstablishmentStapleUnsupported }

		// Derive my own copy of the cross-party PSK off MY Group_A (the session's
		// send group here — I am the initiator joining Group_B) rather than
		// trusting any wire-carried value (m6).
		guard var groupA = sendGroup else { throw TwoMLSError.notEstablished }
		let crossPSK = try MLS.Combiner.ExportedPsk.export(
			from: &groupA.classical, classicalProvider,
			componentID: Self.crossPartyComponentID)
		sendGroup = groupA

		let welcome = try MLS.RFC9420.Welcome(mlsEncoded: tBytes)
		let groupB = try APQGroup.joinClassicalOnly(
			welcome: welcome, credentials: identity.classicalJoinCredentials,
			crossPSK: crossPSK, provider: classicalProvider, codepoints: codepoints)
		try TwoPartyRules.ensureTwoParty(groupB.classical)

		recvGroup = groupB
		joinedWelcomeDigest = digest
	}

	/// §4b, called from `prepareToEncrypt`: if a bind is owed AND licensed
	/// (`peerAppliedSendEpoch >= sendGroup.classical.context.epoch` — `>=`,
	/// not `==`: the peer's evidenced epoch may be stale relative to a commit
	/// this discharge is about to make, but never ahead of the one it is
	/// discharging against), fold it into a FULL commit on
	/// `sendGroup.classical` carrying the `apq_psk` chain, the cross-party
	/// `0xFF02` PSK (§11 #1, when `recvGroup.classical` has moved since the
	/// last injection), and the attestation — then staple the pq+classical
	/// commit pair as the `0x05` bind and pass the turn back. Returns whether
	/// a commit happened.
	private mutating func dischargeOwedBindIfLicensed() throws -> Bool {
		guard let owed = owedBind, let peerApplied = peerAppliedSendEpoch,
			var send = sendGroup, let sendPQHalf = send.pq
		else {
			return false
		}
		guard peerApplied >= send.classical.context.epoch else { return false }

		return try withDeployedWireWidth {
			guard
				send.classical.context.epoch + 1 == owed.tEpoch,
				sendPQHalf.context.epoch == owed.pqEpoch
			else {
				throw TwoMLSError.epochDesync
			}

			var pqForExport = sendPQHalf
			let apqPSK = try MLS.Combiner.ExportedPsk.export(
				from: &pqForExport, pqProvider,
				componentID: codepoints.apqComponentID)
			send.pq = pqForExport

			let attestation = MLS.Combiner.ApqInfoUpdate(
				tEpoch: owed.tEpoch, pqEpoch: owed.pqEpoch)

			var store = MLS.Combiner.PSKStore()
			store.register(apqPSK)
			var proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(
					apqPSK.proposal(
						nonce: classicalProvider.randomBytes(
							classicalProvider.hashSize))),
				.proposal(
					try attestation.proposal(
						componentID: codepoints.apqComponentID)),
			]

			if var recv = recvGroup, recv.classical.context.epoch != lastCrossInjected {
				var crossForExport = recv.classical
				let crossPSK = try MLS.Combiner.ExportedPsk.export(
					from: &crossForExport, classicalProvider,
					componentID: Self.crossPartyComponentID)
				recv.classical = crossForExport
				recvGroup = recv
				store.register(crossPSK)
				lastCrossInjected = crossForExport.context.epoch
				proposals.append(
					.proposal(
						crossPSK.proposal(
							nonce: classicalProvider.randomBytes(
								classicalProvider.hashSize))))
			}

			let transition = try send.classical.committing(
				classicalProvider, proposals: proposals,
				signingKey: identity.signingKey,
				randomness: try .generate(classicalProvider), includePath: true,
				framing: .publicMessage, psk: store.resolver())
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let advanced = try sent.takePending().apply(onto: adopted)
			send.classical = advanced.group
			sendGroup = send

			currentStaple = Frames.encodeAPQPrivateMessage(
				t: commitBytes, pq: owed.pqCommitMessage)
			owedBind = nil
			pqTurnMine = false
			return true
		}
	}

	/// §4c/§11 #2/#5, Bob: apply Alice's `0x05` bind staple. Classifies the
	/// classical commit's epoch against `recvGroup.classical`'s live epoch
	/// BEFORE consuming anything — behind it (`<`) is an idempotent re-ride
	/// (the staple rides every frame until Alice's next commit) and a no-op;
	/// ahead of it (`>`) is `.epochDesync`; equal is the one live application.
	/// Gated on `pqInflight == .bootstrapResponded` so a bind cannot land
	/// outside a founded-and-not-yet-bound state. Applies the PQ half before
	/// the classical half — the classical discharge's `apq_psk` (`0xFF01`) is
	/// exported off the PQ half's POST-commit epoch. `S` (and the classical
	/// half's cross-party/`apq_psk` PSKs) are resolved lazily inside each
	/// `validating` call's `psk` closure, which the profile invokes only
	/// after the commit's framing signature and membership tag verify — so a
	/// forged staple cannot burn `sendGroup.pq`'s single-shot `0xFF02` leaf.
	private mutating func applyBind(_ staple: Data) throws {
		// The commit messages decoded below carry `ComponentID`-bearing
		// proposals (the injected external PSK and both `AppDataUpdate`s) —
		// their decode, not just their construction, must run at the
		// deployed wire width (§11 #6), so the whole body lives in one scope.
		try withDeployedWireWidth {
			let (tBytes, pqBytes) = try Frames.decodeAPQPrivateMessage(staple)
			guard
				case .publicMessage(let tPub) = try MLS.RFC9420.Message(
					mlsEncoded: tBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			guard
				case .publicMessage(let pqPub) = try MLS.RFC9420.Message(
					mlsEncoded: pqBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			guard var recv = recvGroup, recv.pq != nil else {
				throw TwoMLSError.notEstablished
			}
			guard var send = sendGroup, send.pq != nil else {
				throw TwoMLSError.notEstablished
			}

			if tPub.content.epoch < recv.classical.context.epoch {
				return
			}
			guard tPub.content.epoch == recv.classical.context.epoch else {
				throw TwoMLSError.epochDesync
			}
			guard pqInflight == .bootstrapResponded else {
				throw TwoMLSError.sessionNotReady
			}

			var sendPQ = send.pq!
			let pqPending = try recv.pq!.validating(
				pqProvider, commit: pqPub, proposals: MLS.RFC9420.ProposalStore(),
				psk: { identifier in
					guard case .external = identifier else { return nil }
					let exported = try MLS.Combiner.ExportedPsk.export(
						from: &sendPQ, pqProvider,
						componentID: Self.crossPartyComponentID)
					return exported.psk.withUnsafeBytes { Data($0) }
				})
			let pqEffects = pqPending.effects
			try TwoPartyRules.validateBindPQEffects(pqEffects)
			let pqTransition = try pqPending.apply(onto: recv.pq!)
			recv.pq = pqTransition.group
			send.pq = sendPQ
			lastSendPQExported = 1

			var apqSource = recv.pq!
			let apqPSK = try MLS.Combiner.ExportedPsk.export(
				from: &apqSource, pqProvider, componentID: codepoints.apqComponentID
			)
			recv.pq = apqSource

			var crossSource = send.classical
			let crossPSK = try MLS.Combiner.ExportedPsk.export(
				from: &crossSource, classicalProvider,
				componentID: Self.crossPartyComponentID)
			send.classical = crossSource

			var store = MLS.Combiner.PSKStore()
			store.register(apqPSK)
			store.register(crossPSK)

			let tPending = try recv.classical.validating(
				classicalProvider, commit: tPub,
				proposals: MLS.RFC9420.ProposalStore(),
				psk: store.resolver())
			let classicalEffects = tPending.effects
			try TwoPartyRules.validateBindClassicalEffects(classicalEffects)
			let tTransition = try tPending.apply(onto: recv.classical)
			recv.classical = tTransition.group

			_ = try MLS.Combiner.verifyFullCommitAttestation(
				classicalEffects: classicalEffects, pqEffects: pqEffects,
				classicalEpoch: recv.classical.context.epoch,
				pqEpoch: recv.pq!.context.epoch, codepoints: codepoints)

			try TwoPartyRules.ensureTwoParty(recv.pq!)
			try TwoPartyRules.ensureTwoParty(recv.classical)

			recvGroup = recv
			sendGroup = send
			pqTurnMine = true
			pqInflight = nil
			pendingSideBand = nil
		}
	}
}

// MARK: - §A.3 PQ bootstrap

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// The initiator (Alice) begins the bootstrap: hand the pre-committed KP′
	/// to the peer as a `0x13` side-band frame. Requires it be my turn, both
	/// groups founded, and Group_B.pq not yet founded. Idempotent while a
	/// begin is already outstanding: re-returns the retained frame rather
	/// than re-checking turn/state (a re-send should not depend on nothing
	/// having moved since the first call).
	public mutating func pqBootstrapBegin() throws -> Data {
		if pqInflight == .bootstrapInitiated, let pending = pendingSideBand {
			return pending
		}
		guard
			pqTurnMine, sendGroup != nil, let recv = recvGroup, recv.pq == nil,
			let bootstrapKP
		else {
			throw TwoMLSError.sessionNotReady
		}
		let frame = Frames.encodePQBootstrapKP(bootstrapKP)
		pqInflight = .bootstrapInitiated
		pendingSideBand = frame
		return frame
	}

	/// The responder (Bob) receives KP′, checks it against the commitment
	/// pinned at `receive`, founds Group_B.pq (`APQGroup.foundPQHalf`) with
	/// KP′ as the sole Add, and returns the resulting Welcome′ as a `0x15`
	/// side-band frame. Bob is `isFullyEstablished` once this returns.
	public mutating func pqBootstrapRespond(_ frame: Data) throws -> Data {
		let kpBytes = try Frames.decodePQBootstrapKP(frame)
		guard
			let expected = expectedBootstrapKPCommitment,
			try classicalProvider.hash(kpBytes) == expected
		else {
			throw TwoMLSError.bootstrapKPMismatch
		}
		guard
			case .keyPackage(let peerBootstrapKP) = try MLS.RFC9420.Message(
				mlsEncoded: kpBytes)
		else {
			throw TwoMLSError.malformedSideBandMessage
		}
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }

		let (pqGroup, welcome) = try APQGroup.foundPQHalf(
			sendGroupClassical: send.classical,
			ownPQLeaf: identity.keyPackage.pq.leafNode,
			ownPQLeafSecret: identity.pqLeafSecretKey, signingKey: identity.signingKey,
			peerBootstrapKP: peerBootstrapKP, randomness: try .generate(pqProvider),
			epochSecret: pqProvider.randomBytes(pqProvider.hashSize),
			pqProvider: pqProvider,
			codepoints: codepoints)
		send.pq = pqGroup
		sendGroup = send

		let welcomeBytes = try MLS.RFC9420.Message.welcome(welcome).mlsEncoded()
		let responseFrame = Frames.encodePQBootstrapWelcome(welcomeBytes)
		pqInflight = .bootstrapResponded
		pendingSideBand = responseFrame
		return responseFrame
	}

	/// The initiator (Alice) joins Group_B.pq off Bob's Welcome′, using the
	/// KP′ secrets minted at `initiate` as joiner credentials, then owes the
	/// bind (`owePQBind`, §4a). Alice is `isFullyEstablished` once this
	/// returns. `pendingProposal == nil` guards against staple-stacking
	/// (§11 #4): a routine `Upd(self)` must already be discharged (`encrypt`)
	/// before the bootstrap can add its own commit to the pile. Clears
	/// `bootstrapKPSecret` once spent (§11 #11).
	public mutating func pqBootstrapJoin(_ frame: Data) throws {
		guard pendingProposal == nil else { throw TwoMLSError.sessionNotReady }
		let welcomeBytes = try Frames.decodePQBootstrapWelcome(frame)
		guard case .welcome(let welcome) = try MLS.RFC9420.Message(mlsEncoded: welcomeBytes)
		else {
			throw TwoMLSError.malformedSideBandMessage
		}
		guard let secret = bootstrapKPSecret else { throw TwoMLSError.sessionNotReady }
		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }

		let credentials = MLS.RFC9420.Group.JoinerCredentials(
			keyPackage: secret.keyPackage, initKey: secret.initSecretKey,
			encryptionKey: secret.leafSecretKey)
		let pqGroup = try APQGroup.joinPQHalf(
			welcome: welcome, credentials: credentials,
			classicalHalfForPairCheck: recv.classical, pqProvider: pqProvider,
			codepoints: codepoints)
		recv.pq = pqGroup
		recvGroup = recv
		bootstrapKPSecret = nil

		try owePQBind()
	}

	/// §4a: immediately after `pqBootstrapJoin` sets `recvGroup.pq`, export
	/// the cross-party `S` off the freshly-joined Group_B.pq epoch-1 leaf,
	/// re-inject it as an external PSK into a pathless PARTIAL commit on
	/// `sendGroup.pq` (Group_A.pq), and park the resulting commit message as
	/// `owedBind` until a licensed `prepareToEncrypt` can discharge it (§4b).
	private mutating func owePQBind() throws {
		guard var recv = recvGroup, let recvPQ = recv.pq else {
			throw TwoMLSError.notEstablished
		}
		guard var send = sendGroup, let sendPQ = send.pq else {
			throw TwoMLSError.notEstablished
		}

		try withDeployedWireWidth {
			var pqForExport = recvPQ
			let sExport = try MLS.Combiner.ExportedPsk.export(
				from: &pqForExport, pqProvider,
				componentID: Self.crossPartyComponentID)
			recv.pq = pqForExport
			recvGroup = recv
			lastCrossInjectedPQ = 1
			let s = sExport.psk.withUnsafeBytes { Data($0) }

			let attestation = MLS.Combiner.ApqInfoUpdate(
				tEpoch: send.classical.context.epoch + 1,
				pqEpoch: sendPQ.context.epoch + 1)

			// Id = LE64(epoch) ‖ groupID ‖ [0x52] — hand-rolled per §4, never
			// re-derived from the wire (Bob matches on `.external` alone,
			// §11 #5).
			let injectedID =
				withUnsafeBytes(of: sendPQ.context.epoch.littleEndian) { Data($0) }
				+ sendPQ.context.groupID + Data([0x52])
			let nonce = pqProvider.randomBytes(pqProvider.hashSize)

			let proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(
					.preSharedKey(.external(pskID: injectedID, nonce: nonce))),
				.proposal(
					try attestation.proposal(
						componentID: codepoints.apqComponentID)),
			]
			let transition = try sendPQ.committing(
				pqProvider, proposals: proposals, signingKey: identity.signingKey,
				randomness: try .generate(pqProvider), includePath: false,
				framing: .publicMessage,
				psk: { identifier in
					guard case .external(let pskID, _) = identifier,
						pskID == injectedID
					else {
						return nil
					}
					return s
				})
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let advanced = try sent.takePending().apply(onto: adopted)
			send.pq = advanced.group
			sendGroup = send

			owedBind = OwedBind(
				pqCommitMessage: commitBytes, tEpoch: attestation.tEpoch,
				pqEpoch: attestation.pqEpoch)
		}
	}
}
