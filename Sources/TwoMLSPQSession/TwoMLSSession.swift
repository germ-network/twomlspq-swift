import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import MLSTreeMath
import SecretBytes
import TwoMLSPQCrypto

/// The result of `initiate`/`receive`: the session plus the welcome staple to
/// hand the peer out of band. Slice 1 omits the §A.1 header-encryption
/// envelope, so the frame rides un-sealed — the Welcome still HPKE-seals its
/// own group secrets to the joiner; only the outer envelope is deferred.
@available(iOS 26, macOS 26, *)
public struct EstablishResult: Sendable {
	public let session: TwoMLSSession
	public let welcome: Data
}

/// The result of `prepareToEncrypt`: first runs a committing round — folding
/// an approved peer Update (§5) and/or discharging an owed bind if one is
/// licensed (§4b) — `didCommit` reports whether that happened, then always
/// stages a routine `Upd(self)` into the receive group regardless.
public struct PrepareResult: Sendable {
	public let proposalMessage: Data
	public let proposalHash: Data
	public let didCommit: Bool
	/// The verified identity of the peer leaf a FOLD just refreshed — `nil`
	/// unless this round folded an approved `queuedProposal` (a bind-only
	/// discharge canonicalizes nothing of the peer's, so it stays `nil` even
	/// when `didCommit` is true).
	public let committedRemoteClientID: Data?
}

/// Which side-band round is outstanding on this session, if any — the §A.3
/// bootstrap (`pqBootstrapBegin`/`pqBootstrapRespond`, cleared by
/// `pqBootstrapJoin`/`applyBind`), the §A.4 ratchet (`stageRatchet`/
/// `pqRatchetRespond`, cleared by `pqRatchetBind`/`applyBind`), or the §A.5
/// mechanical re-key (`pqRekeyBegin`/`pqRekeyRespond`, cleared by
/// `pqRekeyApply`/`applyBind`). Payloaded, so it is no longer `Equatable`-
/// `=='able — sites that used to compare against a bare case now pattern-match.
enum PQInflight: Sendable {
	case bootstrapInitiated
	case bootstrapResponded
	/// The initiator's §A.4 round: the ephemeral KEM secret is held, awaiting
	/// the responder's CT leg.
	case initiating(PQEphemeral)
	/// The responder's §A.4 round: `S` and the sealed CT are held — `S` for
	/// `applyBind`'s held-S arm (no re-export needed), `wireCT` for
	/// `rewrapSideBand`'s re-mint.
	case responding(secret: SecretBytes, wireCT: Data)
	/// The initiator's §A.5 round: the parked Upd′ MLSMessage bytes, held so
	/// `pqRekeyApply` can re-`verifying` and re-insert it into a
	/// `ProposalStore` — `validating` resolves a Commit's `.reference` only
	/// from the store the same call supplies (§13 M1); swift-mls keeps no
	/// cross-call proposal cache.
	case rekeyInitiated(updMessage: Data)
	/// The committer's §A.5 round: the rekey Commit′ is already applied to
	/// `sendGroup.pq`, awaiting the initiator's bind ack. `applyBind`'s
	/// re-export arm resolves `S` off it, like `.bootstrapResponded`.
	case rekeyResponded
}

/// The initiator's held §A.4 ephemeral: the ML-KEM secret key kept until the
/// responder's CT leg arrives, plus the encapsulation key already staged on
/// the wire (kept for `rewrapSideBand`'s re-mint).
struct PQEphemeral: Sendable {
	let secretKey: MLS.HpkeSecretKey
	let ek: Data
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
/// epoch-bound sender, and the peer's staged proposal (surfaced uninterpreted
/// — `queueProposal` is the approval step that folds it into a later commit).
public struct DecryptResult: Sendable {
	public let applicationMessage: Data
	public let sender: MLS.LeafIndex
	public let epoch: UInt64
	/// The app message's own carried `authenticated_data` — `sha256` of the
	/// proposal bytes the sender framed alongside it. Round-trips as a value;
	/// `unprotect` never checks it against `queuedProposal` (M1).
	public let authenticatedData: Data
	/// Whether this frame's staple actually applied a remote commit (a `0x00`
	/// fold or a `0x05` bind) — `false` for a welcome staple, or an
	/// idempotent re-ride of a commit already applied off an earlier frame.
	public let didApplyRemoteCommit: Bool
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
	/// carried on the wire. Since slice 5 it IS held — as a zeroizing
	/// `ExportedPsk`/`SecretBytes`, never plaintext — in the bounded in-memory
	/// `sendCrossPSKLedger`, so a peer commit that references a past send
	/// epoch can still resolve it without a second (consuming, and thus
	/// failing) export.
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
	/// The `recvGroup.pq` epoch this session last exported the cross-party
	/// `0xFF02` PSK from — stamped by `pqBootstrapJoin`/`pqRekeyApply` (the
	/// initiator's post-round `S` export) and by `pqRekeyRespond` (the
	/// committer's cross-PSK injection into the rekey Commit′). Gates every
	/// such export against a second, failing export of the same `(group,
	/// epoch, component)` (§13 A1/M2/M3).
	var lastCrossInjectedPQ: UInt64?
	/// The `sendGroup.pq` epoch this session last exported the cross-party
	/// `0xFF02` PSK from — stamped by `applyBind`'s re-export arm (the
	/// committer resolving `S`) and by `pqRekeyApply`'s pre-register step
	/// (the initiator resolving the committer's cross-PSK). Same guard as
	/// `lastCrossInjectedPQ`, over `sendGroup.pq` instead.
	var lastSendPQExported: UInt64?

	// MARK: §5 classical FOLD (slice 5, no credential rotation)

	/// The last peer `Upd(self)` offer surfaced by `processIncoming` — set on
	/// every inbound frame, unconditionally (§11 MF8), from that frame's
	/// carried proposal section. `queueProposal(digest:)` is the approval
	/// step that turns this into `queuedProposal`; a later offer simply
	/// replaces an unapproved one (single-occupancy, latest-wins).
	var offeredProposal: (digest: Data, proposing: Data, message: Data)? = nil
	/// The approved fold tally (`queueProposal`) — single-occupancy,
	/// latest-wins. `committingRound` is the only committer of
	/// `sendGroup.classical`, and it always folds this when present, so a
	/// queued tally can never go stale relative to that group's epoch (§11
	/// MF8) — it is cleared only by being folded, never by a timeout or an
	/// unrelated commit.
	var queuedProposal: (digest: Data, proposing: Data, message: Data)? = nil
	/// Every `Upd(self)` staged into `recvGroup.classical` at its CURRENT
	/// epoch (§11 MF3) — `prepareToEncrypt` appends a fresh one on every
	/// call, and swift-mls retains every one's secrets, so the peer may fold
	/// ANY of them (not necessarily the latest) under reorder. Re-verified
	/// and re-inserted into a fresh `ProposalStore` on every `0x00`/`0x05`
	/// staple apply (`rebuildStagedProposalStore`) — swift-mls keeps no
	/// cross-call proposal cache (§13 M1). Cleared when `recvGroup.classical`
	/// advances.
	var stagedUpdates: [(digest: Data, message: Data)] = []
	/// The bounded send-side `0xFF02` cross-party PSK ledger over
	/// `sendGroup.classical`, keyed by epoch (§11 MF4) — mirrors the Rust
	/// `send_psk_ledger`. `committingRound` remembers (exports once, then
	/// never again) the departing epoch's export before committing past it,
	/// and the newly-landed epoch's right after; the `0x00`/`0x05` apply arms
	/// inject every ledgered entry as a resolver candidate before
	/// `validating`, since an unlicensed fold's cadence means an inbound
	/// commit may reference either the current epoch or one this session has
	/// since committed past — and the -02 exporter tree retains only the
	/// CURRENT epoch's frontier (`HandshakeStateMachine.swift`), so a past
	/// epoch's export is otherwise unrecoverable. Bounded to
	/// `sendCrossPSKLedgerWindow` entries, oldest evicted first.
	var sendCrossPSKLedger: [UInt64: MLS.Combiner.ExportedPsk] = [:]
	/// `sendCrossPSKLedger`'s retention depth — generous over the handful of
	/// outstanding commits either side's unlicensed fold cadence can produce
	/// in flight, matching the Rust reference's own `SEND_PSK_WINDOW`.
	static let sendCrossPSKLedgerWindow = 8

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
		guard classicalProvider.cipherSuite == TwoMLSSuite.classical,
			pqProvider.cipherSuite == TwoMLSSuite.pq
		else { throw TwoMLSError.cipherSuiteMismatch }

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
			// §11 #1: `lastCrossInjected` tracks the epoch of `recvGroup.classical`
			// (Group_A, joined above) at the last cross-party PSK injection —
			// Bob's freshly-joined copy is already at epoch 1, so the watermark
			// seeds there too.
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
			epochSecret: SecretBytes(randomByteCount: provider.hashSize),
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
	/// First runs a `committingRound` (§4b/§5) — folding an approved peer
	/// Update and/or discharging an owed bind if one is licensed — into a FULL
	/// commit on `sendGroup.classical`, stapling either a bare `0x00` fold or
	/// the `0x05` bind pair, so `encrypt` then protects the app on the
	/// newly-advanced epoch. `didCommit` reports whether that happened;
	/// `committedRemoteClientID` is set only when a fold rode.
	public mutating func prepareToEncrypt() throws -> PrepareResult {
		guard recvGroup != nil, sendGroup != nil else {
			throw TwoMLSError.notEstablished
		}
		let (didCommit, committedRemoteClientID) = try committingRound()
		rewrapSideBand()

		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }
		let (message, _) = try recv.classical.proposeUpdate(
			classicalProvider, signingKey: identity.signingKey, framing: .publicMessage)
		recvGroup = recv

		let proposalBytes = try message.mlsEncoded()
		// `sha256` for the deployed classical suite (curve25519ChaCha), matching
		// the book's fixed sha256 for `proposal_hash`.
		let proposalHash = try classicalProvider.hash(proposalBytes)
		pendingProposal = (
			proposing: identity.clientID, message: proposalBytes, hash: proposalHash
		)
		// §11 MF3: retain every Upd(self) staged this recv epoch — not just the
		// latest — so a `0x00`/`0x05` staple that folds an earlier one by
		// reference can still resolve it.
		stagedUpdates.append((digest: proposalHash, message: proposalBytes))
		return PrepareResult(
			proposalMessage: proposalBytes, proposalHash: proposalHash,
			didCommit: didCommit, committedRemoteClientID: committedRemoteClientID
		)
	}

	/// Seal `app` on the send group with the pending proposal's hash as its
	/// carried `authenticated_data`, and frame it alongside that proposal and
	/// the current staple. The AEAD binds the hash to *this* app message, not
	/// to the frame's separate proposal section — proposal integrity is its own
	/// MLS leaf signature, checked when folded (`queueProposal`/
	/// `committingRound`/`applyFoldCommit`, slice 5) (M1).
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
		let frame = Frames.encodeMessageFrame(
			staple: currentStaple, proposal: proposalSection, app: appBytes)

		// §A.4 self-drive: both best-effort (never throw out of `encrypt`) —
		// `rewrapSideBand` re-mints a stale parked leg at the epoch this send
		// just moved to; `maybeStageNextRound` then stages the next EK if it's
		// my turn and nothing else is outstanding.
		rewrapSideBand()
		maybeStageNextRound()
		return frame
	}

	/// Decode a frame, apply its staple (join Group_B, a `0x00` fold, or a
	/// `0x05` bind — idempotently, when the staple merely re-rides a commit
	/// already applied off an earlier frame), decrypt the app section against
	/// the receive group, and surface the peer's staged proposal uninterpreted
	/// (`queueProposal` is the approval step that folds it).
	public mutating func processIncoming(_ frame: Data) throws -> DecryptResult {
		let (staple, proposalSection, appSection) = try Frames.decodeMessageFrame(frame)
		let appMessage = try MLS.RFC9420.Message(mlsEncoded: appSection)
		guard case .privateMessage(let appPM) = appMessage else {
			throw TwoMLSError.appSectionNotPrivateMessage
		}

		let didApplyRemoteCommit = try handleStaple(staple)

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
		// §11 MF8: replace whatever offer was previously surfaced,
		// unconditionally — single-occupancy, latest-wins, exactly like the
		// approved tally it feeds.
		offeredProposal = (digest: digest, proposing: proposing, message: proposalMessage)

		return DecryptResult(
			applicationMessage: data, sender: unprotected.sender,
			epoch: unprotected.epoch,
			authenticatedData: unprotected.authenticatedData,
			didApplyRemoteCommit: didApplyRemoteCommit,
			queuedProposal: QueuedProposal(digest: digest, proposing: proposing))
	}

	/// `0x01` welcome → join Group_B if this staple hasn't been joined yet
	/// (idempotent otherwise, matching the reference's welcome dedup); `0x00`
	/// mlsMessage → the fold-only commit apply arm (§11 checkpoint 3); `0x05`
	/// apqPrivateMessage → `applyBind`. Returns whether a remote commit was
	/// actually applied (`false` for a welcome, or an idempotent skip of a
	/// commit already applied off an earlier frame).
	@discardableResult
	private mutating func handleStaple(_ staple: Data) throws -> Bool {
		guard let tag = staple.first else { throw TwoMLSError.truncatedSection }
		switch Frames.stapleKind(tag) {
		case .welcome:
			try joinGroupBIfNeeded(fromStaple: staple)
			return false
		case .mlsMessage:
			let commitBytes = try Frames.decodeMlsMessageStaple(staple)
			return try applyFoldCommit(commitBytes)
		case .apqPrivateMessage:
			return try applyBind(staple)
		case .unsupported(let tag):
			throw TwoMLSError.unsupportedStapleTag(tag)
		}
	}

	/// §3a: approve the peer's currently-offered `Upd(self)` (identified by its
	/// digest), for `committingRound` to fold into the next commit. Matches
	/// only the LAST offer `processIncoming` surfaced — a digest that does not
	/// match (including "nothing offered") is `.proposalRejected`, never a
	/// silent no-op (§11, matching the Rust reference). Validated against
	/// `sendGroup.classical` — the group `committingRound` will actually fold
	/// it into — without disturbing that group otherwise: a rejected approval
	/// leaves `offeredProposal` intact (restored) so a later, different digest
	/// can still be approved.
	public mutating func queueProposal(digest: Data) throws {
		guard let offered = offeredProposal, offered.digest == digest else {
			throw TwoMLSError.proposalRejected
		}
		offeredProposal = nil
		do {
			try validateOfferedUpdate(offered)
		} catch {
			offeredProposal = offered
			throw error
		}
		queuedProposal = offered
	}

	/// The validation `queueProposal` (and, defensively, `committingRound`)
	/// runs on an offered Upd, without mutating any group: `send.classical.
	/// verifying(proposal:)` (non-consuming for a `PublicMessage`) authenticates
	/// the framing; the verified proposal must be a peer `.update` (`.member`
	/// sender, not this session's own leaf); its leaf's credential/signature
	/// key must be UNCHANGED from the current occupant's — slice 5 is
	/// fold-only, so any `.credentialReplaced` shape is rejected here, before
	/// it ever reaches a commit; and its verified `.basic` identity must match
	/// the frame's unauthenticated `proposing` claim (§11 MF5 — `proposing`
	/// rides outside the AAD, so the wire claim alone proves nothing).
	private func validateOfferedUpdate(
		_ offered: (digest: Data, proposing: Data, message: Data)
	) throws {
		guard let send = sendGroup else { throw TwoMLSError.proposalRejected }
		try withDeployedWireWidth {
			guard
				let offeredMessage = try? MLS.RFC9420.Message(
					mlsEncoded: offered.message),
				case .publicMessage(let updatePub) = offeredMessage
			else {
				throw TwoMLSError.proposalRejected
			}
			let verified: MLS.RFC9420.VerifiedProposal
			do {
				verified = try send.classical.verifying(
					classicalProvider, proposal: updatePub)
			} catch {
				throw TwoMLSError.proposalRejected
			}
			guard case .update(let leafNode) = verified.proposal,
				case .member(let senderLeaf) = verified.sender,
				senderLeaf != send.classical.myLeafIndex
			else {
				throw TwoMLSError.proposalRejected
			}
			guard let currentRecord = send.classical.tree.leaf(at: senderLeaf) else {
				throw TwoMLSError.proposalRejected
			}
			let currentLeaf = try MLS.RFC9420.LeafNode(
				mlsEncoded: currentRecord.encoded)
			guard currentLeaf.credential == leafNode.credential,
				currentLeaf.signatureKey == leafNode.signatureKey
			else {
				throw TwoMLSError.proposalRejected
			}
			guard case .basic(let identity) = leafNode.credential,
				identity == offered.proposing
			else {
				throw TwoMLSError.proposalRejected
			}
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
	///
	/// Seam: this checks the Update verifies against `sendGroup.classical`
	/// and was framed by a leaf other than my own, but never compares the
	/// Update's credential against `proposing` (the frame's carried sender
	/// id) — not a forgery vector today, since the Update is itself
	/// signature- and membership-tag-authenticated; only relevant once
	/// `proposing` names something other than "my one peer."
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
		// §11 MF4: this consumes `sendGroup.classical`'s (Group_A's) epoch-1
		// `0xFF02` leaf — the exact `(group, epoch, component)` the send-side
		// ledger otherwise "remembers" lazily on first commit. Seed it with
		// this already-derived value so `committingRound`'s first `0x00`/
		// `0x05` round doesn't attempt a second, failing export of the same
		// leaf.
		sendCrossPSKLedger[groupA.classical.context.epoch] = crossPSK

		let welcome = try MLS.RFC9420.Welcome(mlsEncoded: tBytes)
		let groupB = try APQGroup.joinClassicalOnly(
			welcome: welcome, credentials: identity.classicalJoinCredentials,
			crossPSK: crossPSK, provider: classicalProvider, codepoints: codepoints)
		try TwoPartyRules.ensureTwoParty(groupB.classical)

		recvGroup = groupB
		joinedWelcomeDigest = digest
	}

	/// Shared by the `0x00` fold-only arm and the `0x05` bind arm (§11 MF7 —
	/// Rust's own `staple_epoch_action`, factored out so the two arms cannot
	/// drift): behind the receive group's live epoch is an idempotent re-ride
	/// (the staple rides every frame until the sender's next commit) and a
	/// skip; ahead of it is `.epochDesync`; equal is the one live application.
	enum StapleEpochAction { case skip, apply }

	private static func classifyStapleEpoch(commitEpoch: UInt64, currentEpoch: UInt64) throws
		-> StapleEpochAction
	{
		if commitEpoch < currentEpoch { return .skip }
		guard commitEpoch == currentEpoch else { throw TwoMLSError.epochDesync }
		return .apply
	}

	/// §11 MF3: re-`verifying`+`insert` every `Upd(self)` staged into
	/// `recvGroup.classical` at its current epoch into a FRESH `ProposalStore`
	/// — swift-mls keeps no cross-call proposal cache (§13 M1), so
	/// `validating` can only resolve a commit's by-reference fold from a store
	/// THIS call supplies. A stale/foreign/tampered entry simply fails to
	/// verify and is skipped — `verifying` itself epoch-checks, so dropping it
	/// is harmless, not a required decode.
	private func rebuildStagedProposalStore(against classical: MLS.RFC9420.Group)
		-> MLS.RFC9420.ProposalStore
	{
		var store = MLS.RFC9420.ProposalStore()
		for staged in stagedUpdates {
			guard
				case .publicMessage(let stagedPub) = try? MLS.RFC9420.Message(
					mlsEncoded: staged.message),
				let verified = try? classical.verifying(
					classicalProvider, proposal: stagedPub)
			else {
				continue
			}
			_ = try? store.insert(verified, classicalProvider)
		}
		return store
	}

	/// §11 MF4: export+ledger `classical`'s CURRENT-epoch `0xFF02` cross-party
	/// PSK into `ledger`, unless that epoch is already there — mirrors the
	/// Rust `remember_send_psk`. Pure with respect to `self`: both parameters
	/// are `inout` local copies the caller owns, so a caller can discard both
	/// on failure and a retry re-derives (or re-reuses the ledgered value)
	/// cleanly — the -02 exporter tree consumes a `(group, epoch, component)`
	/// leaf on first export, so re-exporting an already-ledgered epoch would
	/// throw `componentSecretConsumed`.
	private func rememberSendCrossPSK(
		classical: inout MLS.RFC9420.Group,
		ledger: inout [UInt64: MLS.Combiner.ExportedPsk]
	) throws {
		let epoch = classical.context.epoch
		guard ledger[epoch] == nil else { return }
		let exported = try MLS.Combiner.ExportedPsk.export(
			from: &classical, classicalProvider, componentID: Self.crossPartyComponentID
		)
		ledger[epoch] = exported
		if ledger.count > Self.sendCrossPSKLedgerWindow {
			for evict in ledger.keys.sorted().prefix(
				ledger.count - Self.sendCrossPSKLedgerWindow)
			{
				ledger[evict] = nil
			}
		}
	}

	/// §3b/§11 MF6: a committing round on `sendGroup.classical` — folds the
	/// approved peer Update (`queuedProposal`, when present: a fold needs no
	/// license, since `queueProposal` already verified it against the live
	/// send group, and holding it IS the evidence) and/or discharges an owed
	/// PQ bind (when `owedBind != nil` AND licensed). An owed bind rides ANY
	/// committing round this triggers, licensed or not (MF6): a fold that
	/// commits advances `sendGroup.classical` regardless, which would make an
	/// owed bind's reserved epoch stale and doom it, so a fold that commits
	/// must carry an outstanding bind along. Staple selection keys off
	/// `owed != nil` (→ `0x05`), not `didCommit` (MF6). Reports whether a
	/// commit happened, and — fold only — the folded peer leaf's verified
	/// identity (MF5, never the unauthenticated wire `proposing`).
	private mutating func committingRound() throws -> (
		didCommit: Bool, committedRemoteClientID: Data?
	) {
		let folded = queuedProposal
		let owed = owedBind
		let licensed: Bool
		if let peerApplied = peerAppliedSendEpoch, let send = sendGroup {
			licensed = peerApplied >= send.classical.context.epoch
		} else {
			licensed = false
		}
		// The `folded != nil ||` disjunct is DEFENSIVE and unreachable via the
		// public API today: a queued fold implies the peer already applied our
		// send epoch, so `licensed` is already true whenever `folded != nil`.
		// It stays so a fold can never strand an owed bind by advancing the
		// epoch without discharging it, should that invariant ever change.
		let willDischargeBind = owed != nil && (folded != nil || licensed)
		guard folded != nil || willDischargeBind else {
			return (false, nil)
		}
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }

		return try withDeployedWireWidth {
			var proposalStore = MLS.RFC9420.ProposalStore()
			var proposals: [MLS.RFC9420.ProposalOrRef] = []
			var store = MLS.Combiner.PSKStore()
			var committedRemoteClientID: Data?
			var pqCommitMessageForStaple: Data?

			if let folded {
				guard
					let foldedMessage = try? MLS.RFC9420.Message(
						mlsEncoded: folded.message),
					case .publicMessage(let updatePub) = foldedMessage
				else {
					throw TwoMLSError.invalidFoldEffects
				}
				let verified: MLS.RFC9420.VerifiedProposal
				do {
					verified = try send.classical.verifying(
						classicalProvider, proposal: updatePub)
				} catch {
					throw TwoMLSError.invalidFoldEffects
				}
				guard case .update(let leafNode) = verified.proposal,
					case .basic(let remoteIdentity) = leafNode.credential
				else {
					throw TwoMLSError.invalidFoldEffects
				}
				let ref = try proposalStore.insert(verified, classicalProvider)
				proposals.append(.reference(ref))
				committedRemoteClientID = remoteIdentity
			}

			if willDischargeBind {
				guard let owedValue = owed, let sendPQHalf = send.pq else {
					throw TwoMLSError.notEstablished
				}
				guard send.classical.context.epoch + 1 == owedValue.tEpoch,
					sendPQHalf.context.epoch == owedValue.pqEpoch
				else {
					throw TwoMLSError.epochDesync
				}

				var pqForExport = sendPQHalf
				let apqPSK = try MLS.Combiner.ExportedPsk.export(
					from: &pqForExport, pqProvider,
					componentID: codepoints.apqComponentID)
				send.pq = pqForExport
				store.register(apqPSK)

				let attestation = MLS.Combiner.ApqInfoUpdate(
					tEpoch: owedValue.tEpoch, pqEpoch: owedValue.pqEpoch)
				proposals.append(
					.proposal(
						apqPSK.proposal(
							nonce: classicalProvider.randomBytes(
								classicalProvider.hashSize))))
				proposals.append(
					.proposal(
						try attestation.proposal(
							componentID: codepoints.apqComponentID)))
				pqCommitMessageForStaple = owedValue.pqCommitMessage
			}

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

			// §11 MF4: remember the departing send epoch's own `0xFF02` export
			// BEFORE committing past it — an unlicensed fold needs no
			// evidence of the peer's progress, so a peer frame referencing
			// this exact epoch may still be in flight.
			var ledger = sendCrossPSKLedger
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)

			let transition = try send.classical.committing(
				classicalProvider, proposals: proposals,
				proposalStore: proposalStore,
				signingKey: identity.signingKey,
				randomness: try .generate(classicalProvider), includePath: true,
				framing: .publicMessage, psk: store.resolver())
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let pending = sent.takePending()

			if willDischargeBind {
				try TwoPartyRules.validateBindClassicalEffects(
					pending.effects, foldedPeerUpdate: folded != nil)
			} else {
				try TwoPartyRules.validateTwoPartyUpdateCommit(
					pending.effects, foldedPeerUpdate: true,
					allowAppDataUpdate: false,
					orThrow: .invalidFoldEffects)
			}

			let advanced = try pending.apply(onto: adopted)
			send.classical = advanced.group

			// MF4: also remember the newly-landed epoch, so a crossed peer
			// commit referencing it still resolves even if this session
			// commits again before that peer commit arrives.
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)

			sendGroup = send
			sendCrossPSKLedger = ledger

			if let pqCommitMessageForStaple {
				currentStaple = Frames.encodeAPQPrivateMessage(
					t: commitBytes, pq: pqCommitMessageForStaple)
				owedBind = nil
				pqTurnMine = false
			} else {
				currentStaple = Frames.encodeMlsMessageStaple(commitBytes)
			}
			// Either way this round is now fully spent: the fold it carried
			// (if any) is consumed, and any still-unapproved offer is bound
			// to the epoch this commit just left behind (§11 MF8's "the peer
			// re-proposes at the new epoch once it sees this commit's
			// staple").
			queuedProposal = nil
			offeredProposal = nil
			return (true, committedRemoteClientID)
		}
	}

	/// §3c/checkpoint 3: the `0x00` fold-only commit staple apply arm.
	/// Classifies the commit's epoch against `recvGroup.classical`'s live
	/// epoch (the shared classifier, MF7) before consuming anything;
	/// re-inserts every staged `Upd(self)` (MF3) so the commit's by-reference
	/// fold resolves regardless of which staged Upd the peer approved;
	/// live-injects the send-group `0xFF02` ledger (MF4); validates the
	/// fold-only effects shape; applies; `ensureTwoParty`. Value semantics:
	/// only local `recv`/`send`/`ledger` copies are touched, written back to
	/// `self` on success — any throw above that point burns no state.
	private mutating func applyFoldCommit(_ commitBytes: Data) throws -> Bool {
		// The commit's injected `0xFF02` PSK is `ComponentID`-bearing, like
		// the `0x05` bind's — decode and construct at the deployed width
		// (§11 #6/MF7), so the whole body lives in one scope.
		try withDeployedWireWidth {
			guard
				case .publicMessage(let commitPub) = try MLS.RFC9420.Message(
					mlsEncoded: commitBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			guard var recv = recvGroup else { throw TwoMLSError.notEstablished }

			switch try Self.classifyStapleEpoch(
				commitEpoch: commitPub.content.epoch,
				currentEpoch: recv.classical.context.epoch)
			{
			case .skip: return false
			case .apply: break
			}

			let proposalStore = rebuildStagedProposalStore(against: recv.classical)

			guard var send = sendGroup else { throw TwoMLSError.notEstablished }
			var ledger = sendCrossPSKLedger
			var store = MLS.Combiner.PSKStore()
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)
			for exported in ledger.values { store.register(exported) }

			let pending = try recv.classical.validating(
				classicalProvider, commit: commitPub, proposals: proposalStore,
				psk: store.resolver())
			try TwoPartyRules.validateTwoPartyUpdateCommit(
				pending.effects, foldedPeerUpdate: true, allowAppDataUpdate: false,
				orThrow: .invalidFoldEffects)
			let advanced = try pending.apply(onto: recv.classical)
			recv.classical = advanced.group
			try TwoPartyRules.ensureTwoParty(recv.classical)

			recvGroup = recv
			sendGroup = send
			sendCrossPSKLedger = ledger
			stagedUpdates = []
			return true
		}
	}

	/// §4c/§11 #2/#5, Bob: apply Alice's `0x05` bind staple (a fold may ride
	/// it too — the SAME commit that discharges the bind can fold an approved
	/// peer Update by reference, §11 MF1). Classifies the classical commit's
	/// epoch with the shared classifier (MF7) before consuming anything.
	/// Gated on `pqInflight` being `.bootstrapResponded`/`.responding`/
	/// `.rekeyResponded` so a bind cannot land outside a founded-and-not-yet-
	/// bound state. Applies the PQ half before
	/// the classical half — the classical discharge's `apq_psk` (`0xFF01`) is
	/// exported off the PQ half's POST-commit epoch. Only `S` is resolved
	/// lazily, inside the PQ `validating` call's `psk` closure (the profile
	/// invokes it only after that commit's framing signature and membership
	/// tag verify); the classical half's `apq_psk` is exported eagerly, ahead
	/// of its own `validating` call, and the cross-party `0xFF02` is resolved
	/// via the send-group ledger (MF4) rather than an unconditional fresh
	/// export — a fold-then-bind+fold at one peer epoch makes a second bare
	/// export here reachable (`componentSecretConsumed`), and a crossed
	/// concurrent commit may reference an epoch this session has already
	/// committed past (the -02 exporter tree retains only the current
	/// epoch's frontier). The actual guard against a forged staple burning
	/// any single-shot leaf is not laziness but value semantics: the whole
	/// body works on local copies (`recv`/`send`/`ledger`), written back to
	/// `self` only on success at the very end — any throw above that point
	/// (a bad signature, a bad membership tag, a bad effects shape, or a
	/// failed attestation) discards every export this call made. Returns
	/// whether the bind was actually applied (`false` for an idempotent
	/// re-ride).
	private mutating func applyBind(_ staple: Data) throws -> Bool {
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

			switch try Self.classifyStapleEpoch(
				commitEpoch: tPub.content.epoch,
				currentEpoch: recv.classical.context.epoch)
			{
			case .skip: return false
			case .apply: break
			}
			switch pqInflight {
			case .bootstrapResponded, .responding, .rekeyResponded:
				break
			default:
				throw TwoMLSError.sessionNotReady
			}

			// §11 MF1: does this commit ALSO fold a peer Update by reference
			// (a fold+bind `0x05`), or is it a bare bind? Purely structural —
			// `committingRound` only ever emits a `.reference` entry when a
			// fold rode — so this determines the exact `.updated`-count the
			// whitelist below expects, never trusted claims from elsewhere.
			guard case .commit(let commitValue) = tPub.content.content else {
				throw TwoMLSError.malformedSideBandMessage
			}
			let foldedPeerUpdate = commitValue.proposals.contains { entry in
				if case .reference = entry { return true }
				return false
			}

			// Mirrors the id `owePQBind` builds on Alice's side (LE64(epoch) ‖
			// groupID ‖ [0x52]) against `recv.pq!`'s PRE-apply epoch/group id —
			// the same `(group, epoch)` Alice's `sendPQ` named there — so the
			// resolver matches the exact injected id, not any `.external` PSK
			// (§11 #5).
			let expectedInjectedID =
				withUnsafeBytes(of: recv.pq!.context.epoch.littleEndian) {
					Data($0)
				}
				+ recv.pq!.context.groupID + Data([0x52])

			var sendPQ = send.pq!
			let sendPQEpochBeforeExport = sendPQ.context.epoch
			let pqPending = try recv.pq!.validating(
				pqProvider, commit: pqPub, proposals: MLS.RFC9420.ProposalStore(),
				psk: { identifier in
					guard case .external(let pskID, _) = identifier,
						pskID == expectedInjectedID
					else {
						return nil
					}
					// §A.4: `S` was already sealed/held at `pqRatchetRespond` —
					// reuse it rather than exporting a fresh one off `sendPQ`
					// (which A.4 never spends here at all).
					if case .responding(let secret, _) = pqInflight {
						return secret
					}
					let exported = try MLS.Combiner.ExportedPsk.export(
						from: &sendPQ, pqProvider,
						componentID: Self.crossPartyComponentID)
					return exported.psk
				})
			let pqEffects = pqPending.effects
			try TwoPartyRules.validateBindPQEffects(pqEffects)
			let pqTransition = try pqPending.apply(onto: recv.pq!)
			recv.pq = pqTransition.group
			send.pq = sendPQ
			switch pqInflight {
			case .bootstrapResponded, .rekeyResponded:
				lastSendPQExported = sendPQEpochBeforeExport
			default:
				break
			}

			var apqSource = recv.pq!
			let apqPSK = try MLS.Combiner.ExportedPsk.export(
				from: &apqSource, pqProvider, componentID: codepoints.apqComponentID
			)
			recv.pq = apqSource

			let proposalStore = rebuildStagedProposalStore(against: recv.classical)
			var ledger = sendCrossPSKLedger
			var store = MLS.Combiner.PSKStore()
			store.register(apqPSK)
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)
			for exported in ledger.values { store.register(exported) }

			let tPending = try recv.classical.validating(
				classicalProvider, commit: tPub,
				proposals: proposalStore,
				psk: store.resolver())
			let classicalEffects = tPending.effects
			try TwoPartyRules.validateBindClassicalEffects(
				classicalEffects, foldedPeerUpdate: foldedPeerUpdate)
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
			sendCrossPSKLedger = ledger
			stagedUpdates = []
			pqTurnMine = true
			pqInflight = nil
			pendingSideBand = nil
			return true
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
	/// having moved since the first call) — but only while `recvGroup.pq` is
	/// still nil, so a spent round (the bind already landed) falls through
	/// to the normal guard instead of re-emitting a stale `0x13`.
	public mutating func pqBootstrapBegin() throws -> Data {
		if case .bootstrapInitiated = pqInflight, let pending = pendingSideBand,
			recvGroup?.pq == nil
		{
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
	/// Idempotent once `sendGroup.pq` is founded: re-returns the retained
	/// `0x15` rather than founding a second Group_B.pq off a re-delivered
	/// `0x13` (a re-delivery with no retained frame to re-serve, e.g. after
	/// a restart, is `.duplicateSideBand` — this module does not persist
	/// `pendingSideBand` across process restarts).
	///
	/// Seam: this does not check KP′'s leaf credential names the already-
	/// established peer (Rust's AS `validate_member`; no AS exists until a
	/// later slice). It fails closed regardless — a wrong-peer KP′ founds a
	/// Group_B.pq the real peer never agrees to join, so the bind can never
	/// complete.
	public mutating func pqBootstrapRespond(_ frame: Data) throws -> Data {
		if sendGroup?.pq != nil {
			guard let pending = pendingSideBand else {
				throw TwoMLSError.duplicateSideBand
			}
			return pending
		}
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
			epochSecret: SecretBytes(randomByteCount: pqProvider.hashSize),
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
	/// KP′ secrets minted at `initiate` as joiner credentials, exports the
	/// cross-party `S` off the freshly-joined epoch-1 leaf, then owes the
	/// bind (`owePQBind(s:)`, §4a). Alice is `isFullyEstablished` once this
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
		var pqGroup = try APQGroup.joinPQHalf(
			welcome: welcome, credentials: credentials,
			classicalHalfForPairCheck: recv.classical, pqProvider: pqProvider,
			codepoints: codepoints)
		bootstrapKPSecret = nil

		try withDeployedWireWidth {
			let recvPQEpochBeforeExport = pqGroup.context.epoch
			let sExport = try MLS.Combiner.ExportedPsk.export(
				from: &pqGroup, pqProvider,
				componentID: Self.crossPartyComponentID)
			recv.pq = pqGroup
			recvGroup = recv
			lastCrossInjectedPQ = recvPQEpochBeforeExport
			try owePQBind(s: sExport.psk)
		}
		// The `0x13`/`0x15` side-band round is now fully spent (Group_B.pq is
		// joined and the bind is owed) — clear the retained frame and inflight
		// marker so a stray re-call of `pqBootstrapBegin`/`pqBootstrapRespond`
		// cannot re-emit them.
		pqInflight = nil
		pendingSideBand = nil
	}

	/// §4a/§4c: fold `s` into a pathless PARTIAL commit on `sendGroup.pq`
	/// and park the resulting commit message as `owedBind` until a licensed
	/// `prepareToEncrypt` can discharge it (§4b). Callers supply `s` however
	/// their round obtained it — the A.3 bootstrap exports it off the
	/// freshly-joined Group_B.pq (`pqBootstrapJoin`); the A.4 ratchet opens
	/// it from a KEM ciphertext (`pqRatchetBind`) — this function only ever
	/// reads/writes `sendGroup`/`send.pq`.
	///
	/// Seam: `s`'s single-shot leaf (however the caller obtained it) is
	/// already spent by the time this runs; a throw from `committing` wedges
	/// the session with `isFullyEstablished == true` but no `owedBind` and no
	/// way to re-derive `s` (Rust latches a `BindTriggerFailed` state for
	/// this). Not handled here.
	private mutating func owePQBind(s: SecretBytes) throws {
		guard var send = sendGroup, let sendPQ = send.pq else {
			throw TwoMLSError.notEstablished
		}

		try withDeployedWireWidth {
			let attestation = MLS.Combiner.ApqInfoUpdate(
				tEpoch: send.classical.context.epoch + 1,
				pqEpoch: sendPQ.context.epoch + 1)

			// Id = LE64(epoch) ‖ groupID ‖ [0x52] — hand-rolled per §4, never
			// re-derived from the wire; the peer recomputes this same id from
			// its own mirror and matches on it exactly, not on `.external`
			// alone (§11 #5).
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

// MARK: - §A.4 PQ ratchet

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Decrypt+authenticate one §A.4 leg (shared by `pqRatchetRespond` and
	/// `pqRatchetBind`): the content-type gate runs BEFORE decrypting — a
	/// Commit smuggled behind the tag must not spend a handshake generation —
	/// then `unprotect`, the inner-tag check, and a peer-sender check. Any
	/// failure to decrypt an untrusted leg (a tampered/replayed/foreign-epoch
	/// frame) surfaces as the non-fatal `.decryptionFailed`, never a raw
	/// `MLS.*` teardown error (§12). Mutates `group` (spends a generation);
	/// call only after the inflight/epoch-floor guards already passed.
	private mutating func processA4Leg(
		on group: inout MLS.RFC9420.Group, innerTag: UInt8, message: MLS.RFC9420.Message
	) throws -> Data {
		guard case .privateMessage(let pm) = message, pm.contentType == .application else {
			throw TwoMLSError.decryptionFailed
		}
		let out: MLS.RFC9420.Group.Unprotected
		do {
			out = try group.unprotect(classicalProvider, message: pm)
		} catch {
			throw TwoMLSError.decryptionFailed
		}
		guard case .application(let content) = out.content else {
			throw TwoMLSError.decryptionFailed
		}
		let (tag, payload) = try Frames.decodePQLegContent(content)
		guard tag == innerTag, out.sender != group.myLeafIndex else {
			throw TwoMLSError.decryptionFailed
		}
		return payload
	}

	/// Self-driven, whichever side holds `pqTurnMine`: generate a fresh
	/// ML-KEM ephemeral, frame its `ek` as a `0x17` leg on `sendGroup.classical`,
	/// and park it awaiting the peer's CT. Classical-only mutation.
	private mutating func stageRatchet() throws {
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }
		let eph = try MLKEM768KEM.generateEphemeral()
		let inner = Frames.encodePQLegContent(tag: Frames.pqEKTag, payload: eph.ek)
		let appPM = try send.classical.protect(
			classicalProvider, applicationData: inner, authenticatedData: Data(),
			signingKey: identity.signingKey)
		sendGroup = send

		let messageBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		pendingSideBand = Frames.encodePQLeg(
			tag: Frames.pqEKTag, messageBytes: messageBytes)
		pqInflight = .initiating(PQEphemeral(secretKey: eph.secretKey, ek: eph.ek))
	}

	/// The responder: receive the initiator's `0x17` EK (decrypted off my
	/// `recvGroup.classical` — the initiator's send group), seal a fresh `S`
	/// to it under the `ctSealPSK` both sides can derive off `recvGroup.pq`
	/// (my mirror of the initiator's PQ half, at its current epoch), and emit
	/// the `0x19` CT on my OWN `sendGroup.classical` — not the mirror the EK
	/// arrived in, which may hold an uncommitted proposal of my own.
	public mutating func pqRatchetRespond(_ frame: Data) throws -> Data {
		let (tag, messageBytes) = try Frames.decodePQLeg(frame)
		guard tag == Frames.pqEKTag else { throw TwoMLSError.unsupportedSideBandTag(tag) }
		let msg = try MLS.RFC9420.Message(mlsEncoded: messageBytes)
		guard case .privateMessage(let pm) = msg else { throw TwoMLSError.decryptionFailed }

		guard var recv = recvGroup, recv.pq != nil else { throw TwoMLSError.notEstablished }
		guard pm.epoch >= recv.classical.context.epoch else { throw TwoMLSError.staleFrame }
		if case .responding = pqInflight {
			throw TwoMLSError.duplicateSideBand
		} else if pqInflight != nil {
			throw TwoMLSError.sessionNotReady
		}
		guard pendingProposal == nil else { throw TwoMLSError.sessionNotReady }
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }

		let ek = try processA4Leg(
			on: &recv.classical, innerTag: Frames.pqEKTag, message: msg)
		recvGroup = recv

		let psk = try CTSeal.ctSealPSK(group: recv.pq!, pqProvider: pqProvider)
		let (s, wireCT) = try CTSeal.seal(ek: ek, ctSealPSK: psk, aead: classicalProvider)

		let inner = Frames.encodePQLegContent(tag: Frames.pqCTTag, payload: wireCT)
		let appPM = try send.classical.protect(
			classicalProvider, applicationData: inner, authenticatedData: Data(),
			signingKey: identity.signingKey)
		sendGroup = send

		let outMessageBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		let outFrame = Frames.encodePQLeg(
			tag: Frames.pqCTTag, messageBytes: outMessageBytes)
		pqInflight = .responding(secret: s, wireCT: wireCT)
		pendingSideBand = outFrame
		return outFrame
	}

	/// The initiator: receive the responder's `0x19` CT (decrypted off my
	/// `recvGroup.classical` — the responder's send group), open `S` against
	/// the `ctSealPSK` derived off `sendGroup.pq` (the same group/epoch the
	/// responder sealed against, via its `recvGroup.pq` mirror) using the
	/// ephemeral secret key held since `stageRatchet`, then owe the bind
	/// (`owePQBind(s:)`, §4c). `CTSeal.open`'s AEAD failure is the explicit
	/// reject for a tampered/misdirected CT — it propagates as thrown, not a
	/// silent no-op.
	public mutating func pqRatchetBind(_ frame: Data) throws {
		let (tag, messageBytes) = try Frames.decodePQLeg(frame)
		guard tag == Frames.pqCTTag else { throw TwoMLSError.unsupportedSideBandTag(tag) }
		let msg = try MLS.RFC9420.Message(mlsEncoded: messageBytes)
		guard case .privateMessage(let pm) = msg else { throw TwoMLSError.decryptionFailed }

		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }
		guard pm.epoch >= recv.classical.context.epoch else { throw TwoMLSError.staleFrame }
		guard pendingProposal == nil, owedBind == nil else {
			throw TwoMLSError.sessionNotReady
		}
		guard case .initiating(let eph) = pqInflight else {
			throw TwoMLSError.sessionNotReady
		}
		guard let sendPQ = sendGroup?.pq else { throw TwoMLSError.notEstablished }

		let wireCT = try processA4Leg(
			on: &recv.classical, innerTag: Frames.pqCTTag, message: msg)
		recvGroup = recv

		let psk = try CTSeal.ctSealPSK(group: sendPQ, pqProvider: pqProvider)
		let s = try CTSeal.open(
			wireCT: wireCT, secretKey: eph.secretKey, ctSealPSK: psk,
			aead: classicalProvider)

		try owePQBind(s: s)
		// §13g/§12#2: clear BOTH — the spent EK must not be re-handed by
		// `pqPendingOutbound`, and `maybeStageNextRound`'s
		// `pendingSideBand == nil` gate must reopen, or the self-driver
		// wedges for life.
		pqInflight = nil
		pendingSideBand = nil
	}

	/// Peek the parked `0x17`/`0x19`/`0x1B`/`0x1D` side-band frame, if any —
	/// non-mutating re the round; the host sends it alongside the message
	/// frame.
	public func pqPendingOutbound() -> Data? {
		pendingSideBand
	}

	/// Best-effort: if the parked side-band leg was minted at an epoch
	/// `sendGroup.classical` has since moved past, re-mint it (EK from the
	/// held `.initiating` ephemeral, CT from the held `.responding` wireCT)
	/// at the current epoch and re-park. Classical carrier only. Never
	/// throws — a failure here just leaves the stale leg parked for the next
	/// call to retry.
	private mutating func rewrapSideBand() {
		guard let pending = pendingSideBand, var send = sendGroup else { return }
		// Also the intended no-op for a parked `0x1B`/`0x1D` §A.5 leg:
		// `decodePQLeg` only recognizes `0x17`/`0x19`, so it throws and `try?`
		// early-returns here. Correct — a PQ-group Upd′/Commit′ sits at a
		// `pq_epoch` that cannot move mid-round, so it never needs re-minting.
		guard let (tag, messageBytes) = try? Frames.decodePQLeg(pending) else { return }
		guard let message = try? MLS.RFC9420.Message(mlsEncoded: messageBytes),
			case .privateMessage(let pm) = message
		else { return }
		guard pm.epoch < send.classical.context.epoch else { return }

		let payload: Data
		switch tag {
		case Frames.pqEKTag:
			guard case .initiating(let eph) = pqInflight else { return }
			payload = eph.ek
		case Frames.pqCTTag:
			guard case .responding(_, let wireCT) = pqInflight else { return }
			payload = wireCT
		default:
			return
		}

		guard
			let appPM = try? send.classical.protect(
				classicalProvider,
				applicationData: Frames.encodePQLegContent(
					tag: tag, payload: payload),
				authenticatedData: Data(), signingKey: identity.signingKey),
			let reEncoded = try? MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		else {
			return
		}
		sendGroup = send
		pendingSideBand = Frames.encodePQLeg(tag: tag, messageBytes: reEncoded)
	}

	/// Self-drive (A.4 arm only — the A.5 `send_pq_leaf_lags` branch is
	/// deferred). No-op unless it's my turn, both halves are established, and
	/// nothing else is outstanding (an inflight round, an owed bind, or an
	/// already-parked side-band leg). Best-effort: swallows `stageRatchet`'s
	/// throw rather than surfacing it out of `encrypt`.
	private mutating func maybeStageNextRound() {
		guard pqTurnMine, isFullyEstablished, pqInflight == nil, owedBind == nil,
			pendingSideBand == nil
		else {
			return
		}
		try? stageRatchet()
	}
}

// MARK: - §A.5 PQ re-key (mechanical — no credential rotation; Chunk 2)

/// Host tag routing for every side-band frame this module parks or expects:
/// `0x03` `processIncoming` (app message); `0x13`/`0x15` bootstrap
/// (`pqBootstrapRespond`/`pqBootstrapJoin`); `0x17`/`0x19` ratchet
/// (`pqRatchetRespond`/`pqRatchetBind`); `0x1B`/`0x1D` re-key
/// (`pqRekeyRespond`/`pqRekeyApply`, this section). A host dispatches on the
/// frame's leading tag byte; `pqPendingOutbound()` peeks whichever of these
/// this session has parked.
///
/// A §A.5 round re-keys ONE PQ group with a standalone `updatePath` Commit′,
/// ending in the reused A.4/A.3 bind: the turn-holder (INITIATOR) proposes a
/// plain self-Update into her `recvGroup.pq` mirror (`pqRekeyBegin`); the
/// peer (COMMITTER) folds it into an `includePath: true` commit on the
/// group it actually owns — `sendGroup.pq` (`pqRekeyRespond`); the
/// initiator applies that Commit′, exports `S` off the freshly-rekeyed
/// group, and owes the classical bind (`pqRekeyApply`, reusing `owePQBind`).
/// This mechanical form carries no credential/signature-key rotation — every
/// leaf keeps its identity (`.updated`, never `.credentialReplaced`); that
/// handoff is Chunk 2 (§15).
@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// The initiator (whoever holds `pqTurnMine`) begins an §A.5 round:
	/// propose a plain (non-rotating) self-Update into `recvGroup.pq` — the
	/// peer's own PQ group, mirrored here, and the one about to be re-keyed
	/// — and park it as a `0x1B` side-band frame. Idempotent while a begin
	/// is already outstanding, like `pqBootstrapBegin`.
	public mutating func pqRekeyBegin() throws -> Data {
		if case .rekeyInitiated = pqInflight, let pending = pendingSideBand {
			return pending
		}
		guard pqTurnMine, isFullyEstablished, pqInflight == nil, owedBind == nil,
			pendingProposal == nil, pendingSideBand == nil
		else {
			throw TwoMLSError.sessionNotReady
		}
		guard var recv = recvGroup, var recvPQ = recv.pq else {
			throw TwoMLSError.notEstablished
		}

		let (message, _) = try recvPQ.proposeUpdate(
			pqProvider, signingKey: identity.signingKey, framing: .publicMessage)
		recv.pq = recvPQ
		recvGroup = recv

		let updBytes = try message.mlsEncoded()
		let frame = Frames.encodePQRekeyUpd(updBytes)
		pqInflight = .rekeyInitiated(updMessage: updBytes)
		pendingSideBand = frame
		return frame
	}

	/// The committer — never the turn-holder (§13 M5: `!pqTurnMine`) —
	/// receives the peer's `0x1B` Upd′, verifies it against `sendGroup.pq`
	/// (the group actually being re-keyed), folds it into an `includePath:
	/// true` commit there — optionally carrying a fresh cross-party `0xFF02`
	/// PSK exported off `recvGroup.pq` (the initiator's own send-PQ mirror,
	/// event-driven off `lastCrossInjectedPQ`, §13 F3) — and parks the
	/// result as a `0x1D` side-band frame. Every export/write-back is
	/// deferred to the success point after the commit lands (§13 M3): a
	/// throw above that discards the local `recv`/`send` copies untouched.
	public mutating func pqRekeyRespond(_ frame: Data) throws -> Data {
		guard !pqTurnMine, pqInflight == nil, owedBind == nil else {
			throw TwoMLSError.sessionNotReady
		}
		guard var send = sendGroup, var sendPQ = send.pq else {
			throw TwoMLSError.notEstablished
		}
		guard var recv = recvGroup, recv.pq != nil else {
			throw TwoMLSError.notEstablished
		}

		return try withDeployedWireWidth {
			let updBytes = try Frames.decodePQRekeyUpd(frame)
			guard
				case .publicMessage(let updPub) = try MLS.RFC9420.Message(
					mlsEncoded: updBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}

			let verified: MLS.RFC9420.VerifiedProposal
			do {
				verified = try sendPQ.verifying(pqProvider, proposal: updPub)
			} catch {
				throw TwoMLSError.decryptionFailed
			}
			guard case .update = verified.proposal,
				case .member(let senderLeaf) = verified.sender,
				senderLeaf != sendPQ.myLeafIndex
			else {
				throw TwoMLSError.rekeyProposalRejected
			}

			var proposalStore = MLS.RFC9420.ProposalStore()
			let ref = try proposalStore.insert(verified, pqProvider)

			var pskStore = MLS.Combiner.PSKStore()
			var proposals: [MLS.RFC9420.ProposalOrRef] = [.reference(ref)]
			let recvPQEpoch = recv.pq!.context.epoch
			var crossInjectedEpoch: UInt64?
			if lastCrossInjectedPQ != recvPQEpoch {
				var recvPQForExport = recv.pq!
				let crossPSK = try MLS.Combiner.ExportedPsk.export(
					from: &recvPQForExport, pqProvider,
					componentID: Self.crossPartyComponentID)
				recv.pq = recvPQForExport
				pskStore.register(crossPSK)
				proposals.append(
					.proposal(
						crossPSK.proposal(
							nonce: pqProvider.randomBytes(
								pqProvider.hashSize))))
				crossInjectedEpoch = recvPQEpoch
			}

			let transition = try sendPQ.committing(
				pqProvider, proposals: proposals, proposalStore: proposalStore,
				signingKey: identity.signingKey,
				randomness: try .generate(pqProvider),
				includePath: true, framing: .publicMessage, psk: pskStore.resolver()
			)
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let pending = sent.takePending()
			try TwoPartyRules.validateRekeyCommitEffects(pending.effects)
			let advanced = try pending.apply(onto: adopted)
			sendPQ = advanced.group
			try TwoPartyRules.ensureTwoParty(sendPQ)

			send.pq = sendPQ
			sendGroup = send
			if let crossInjectedEpoch {
				recvGroup = recv
				lastCrossInjectedPQ = crossInjectedEpoch
			}

			let responseFrame = Frames.encodePQRekeyCommit(commitBytes)
			pqInflight = .rekeyResponded
			pendingSideBand = responseFrame
			return responseFrame
		}
	}

	/// The initiator applies the committer's `0x1D` Commit′: re-verifies the
	/// parked Upd′ and re-inserts it into a fresh `ProposalStore` (§13 M1 —
	/// `validating` resolves a `.reference` only from the store this call
	/// itself supplies), pre-registers the committer's cross-party PSK off a
	/// throwaway copy of `sendGroup.pq` (§13 M3 — never written back, so a
	/// retry after a later failure re-derives the same value rather than
	/// risking `componentSecretConsumed` on the real group), validates the
	/// mechanical rekey effects, applies the Commit′ to `recvGroup.pq`,
	/// exports `S` off the freshly-rekeyed group, and owes the classical
	/// bind (`owePQBind(s:)`, slice 3 reuse).
	public mutating func pqRekeyApply(_ frame: Data) throws {
		guard pendingProposal == nil, owedBind == nil else {
			throw TwoMLSError.sessionNotReady
		}
		guard case .rekeyInitiated(let updMessage) = pqInflight else {
			throw TwoMLSError.sessionNotReady
		}
		guard var recv = recvGroup, var recvPQ = recv.pq else {
			throw TwoMLSError.notEstablished
		}
		guard let sendPQ = sendGroup?.pq else { throw TwoMLSError.notEstablished }

		try withDeployedWireWidth {
			let commitBytes = try Frames.decodePQRekeyCommit(frame)
			guard
				case .publicMessage(let commitPub) = try MLS.RFC9420.Message(
					mlsEncoded: commitBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			guard
				case .publicMessage(let updPub) = try MLS.RFC9420.Message(
					mlsEncoded: updMessage)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}

			let verifiedUpd: MLS.RFC9420.VerifiedProposal
			do {
				verifiedUpd = try recvPQ.verifying(pqProvider, proposal: updPub)
			} catch {
				throw TwoMLSError.decryptionFailed
			}
			var proposalStore = MLS.RFC9420.ProposalStore()
			_ = try proposalStore.insert(verifiedUpd, pqProvider)

			let sendPQEpoch = sendPQ.context.epoch
			var pskStore = MLS.Combiner.PSKStore()
			let needsPreRegister = lastSendPQExported != sendPQEpoch
			if needsPreRegister {
				var pqForExport = sendPQ
				let crossPSK = try MLS.Combiner.ExportedPsk.export(
					from: &pqForExport, pqProvider,
					componentID: Self.crossPartyComponentID)
				pskStore.register(crossPSK)
			}

			let pending: MLS.RFC9420.PendingCommit
			do {
				pending = try recvPQ.validating(
					pqProvider, commit: commitPub, proposals: proposalStore,
					psk: pskStore.resolver())
			} catch {
				throw TwoMLSError.decryptionFailed
			}
			try TwoPartyRules.validateRekeyCommitEffects(pending.effects)
			let transition = try pending.apply(onto: recvPQ)
			recvPQ = transition.group
			try TwoPartyRules.ensureTwoParty(recvPQ)

			// §13 M2: export `S` off the just-rekeyed group and stamp the
			// watermark right after — mirrors `pqBootstrapJoin` (the export
			// consumes this exact `(group, epoch, component)` leaf).
			let recvPQEpochAfterRekey = recvPQ.context.epoch
			let sExport = try MLS.Combiner.ExportedPsk.export(
				from: &recvPQ, pqProvider, componentID: Self.crossPartyComponentID)
			recv.pq = recvPQ
			recvGroup = recv
			lastCrossInjectedPQ = recvPQEpochAfterRekey

			try owePQBind(s: sExport.psk)
			if needsPreRegister {
				lastSendPQExported = sendPQEpoch
			}
			pqInflight = nil
			pendingSideBand = nil
		}
	}
}
