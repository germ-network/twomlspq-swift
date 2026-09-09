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
	/// The credential-sequence Authentication Service state (Germ policy,
	/// RFC 9420 §5.3.1's "application responsibility") — seeded at
	/// `initiate`/`receive` and consulted there against the peer's other
	/// half; a future rotation slice consults it further at the
	/// commit-effect seam (`AuthCore.adjudicate`).
	var auth: AuthCore
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
		auth: AuthCore,
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
		self.auth = auth
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
