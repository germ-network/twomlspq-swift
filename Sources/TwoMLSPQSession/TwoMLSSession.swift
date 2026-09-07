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

	public var isEstablished: Bool { sendGroup != nil && recvGroup != nil }

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
		initiated: Bool
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

		let session = TwoMLSSession(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, identity: identity, sendGroup: groupA,
			recvGroup: nil,
			currentStaple: apqWelcomeA, pendingProposal: nil, joinedWelcomeDigest: nil,
			initiated: true)
		return EstablishResult(session: session, welcome: apqWelcomeA)
	}

	/// Join Group_A from the initiator's welcome, then found Group_B
	/// (classical-only, deferred PQ) with the cross-party PSK exported off the
	/// freshly-joined Group_A.classical. `isEstablished` is true immediately —
	/// the acceptor never waits on an inbound frame.
	public static func receive(
		identity: TwoMLSIdentity,
		welcome: Data,
		theirClassicalKeyPackage: MLS.RFC9420.KeyPackage,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> EstablishResult {
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
			joinedWelcomeDigest: try classicalProvider.hash(welcome), initiated: false)
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
	/// Slice 1's only send path: no queued proposal, no owed bind, so
	/// `didCommit` is always false. Stage a routine `Upd(self)` into the
	/// **receive** group (the peer's send group, where the peer folds it) —
	/// framed `.publicMessage` to match the Rust reference's control-message
	/// framing (m4). Requires `isEstablished`: the initiator cannot send before
	/// its first inbound frame joins Group_B.
	public mutating func prepareToEncrypt() throws -> PrepareResult {
		guard var recv = recvGroup, sendGroup != nil else {
			throw TwoMLSError.notEstablished
		}
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
			proposalMessage: proposalBytes, proposalHash: proposalHash, didCommit: false
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

		return DecryptResult(
			applicationMessage: data, sender: unprotected.sender,
			epoch: unprotected.epoch,
			authenticatedData: unprotected.authenticatedData,
			queuedProposal: QueuedProposal(digest: digest, proposing: proposing))
	}

	/// `0x01` welcome → join Group_B if this staple hasn't been joined yet
	/// (idempotent otherwise, matching the reference's welcome dedup); `0x00`
	/// mlsMessage (commit) → slice 1 sends no commits, so receiving one is an
	/// unsupported protocol state.
	private mutating func handleStaple(_ staple: Data) throws {
		guard let tag = staple.first else { throw TwoMLSError.truncatedSection }
		switch Frames.stapleKind(tag) {
		case .welcome:
			try joinGroupBIfNeeded(fromStaple: staple)
		case .mlsMessage:
			throw TwoMLSError.commitStapleUnsupported
		case .unsupported(let tag):
			throw TwoMLSError.unsupportedStapleTag(tag)
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
}
