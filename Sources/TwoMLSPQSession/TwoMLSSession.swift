import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import MLSTreeMath
import SecretBytes
import TwoMLSPQCrypto

/// The result of `initiate`/`receive`: the session plus the plaintext birth
/// welcome to hand the peer out of band (the invitation/rendezvous channel,
/// not a header-sealed message-path frame) — the Welcome still HPKE-seals
/// its own group secrets to the joiner; only the outer message-path seal is
/// what `standaloneWelcome()` (slice 11) applies for a LATER re-send
/// on the message path.
@available(iOS 26, macOS 26, *)
public struct EstablishResult: Sendable {
	public let session: TwoMLSSession
	/// Each half of the `0x01` APQ welcome is an RFC 9420
	/// `MLSMessage`-wrapped `Welcome`.
	public let welcome: Data
	/// The baseline `StateUpdate` (always `.checkpoint`) — there is no
	/// sink/`installSink`; this return IS the first thing the app saves.
	public let baseline: StateUpdate
	/// The session's own classical KeyPackage — the establishment product an
	/// initiator/replier puts into the welcome's keyMaterial (the Rust
	/// `PQClient.reply`'s `myKeyPackage` 4th value; the invitation path's
	/// `InitialFrame.returnKeyPackage` is the same idea). Its wire and signed
	/// form is its RFC 9420 `MLSMessage` encoding.
	public let returnKeyPackage: MLS.RFC9420.KeyPackage
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
	/// This call's own `StateUpdate` (`.core`).
	public let update: StateUpdate
	/// The durability gate: `currentStapleSeq` as of this call. When
	/// `didCommit` installed a fresh staple, this equals `update.stateSeq` —
	/// the app must durably save `update` before transmitting the frame this
	/// staple rides on. Otherwise it names an EARLIER `StateUpdate` the app
	/// should already have saved (a routine re-staple of an already-persisted
	/// commit needs no additional wait; MLS's per-message `reuse_guard`
	/// covers it).
	public let dependsOnSeq: UInt64
}

/// Which side-band round is outstanding on this session, if any — the §A.3
/// bootstrap (registered at `initiate` for every initiator, or on the first
/// `pqBootstrapRespond` for the acceptor; cleared by `pqBootstrapJoin`/
/// `applyBind`), the §A.4 ratchet (`stageRatchet`/`pqRatchetRespond`,
/// cleared by `pqRatchetBind`/`applyBind`), or the §A.5 mechanical re-key
/// (`pqRekeyBegin`/`pqRekeyRespond`, cleared by `pqRekeyApply`/`applyBind`).
/// Payloaded, so it is no longer `Equatable`- `=='able — sites that used to
/// compare against a bare case now pattern-match.
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
struct OwedBind: Sendable, Codable {
	var pqCommitMessage: Data
	var tEpoch: UInt64
	var pqEpoch: UInt64

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case pqCommitMessage = 0
		case tEpoch = 1
		case pqEpoch = 2
	}
}

/// The persisted record of a session's own-offer window — hoisted
/// fields plus the count, NOT the window itself (which rides its own
/// separate, host-owned blob — `MigratedOwnOfferWindow`/
/// `MintedOwnOfferWindow`, never the session archives). `id` is what
/// `ownOfferWindowID`/a window load cross-checks; the other four fields are
/// what restore cross-checks against the rebuilt recv-classical group
/// (`buildSession`).
struct OwnOfferWindowRecord: Sendable, Codable, Equatable {
	var id: Data
	var epoch: UInt64
	var groupID: Data
	var senderLeafIndex: UInt32
	var count: UInt32

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case id = 0
		case epoch = 1
		case groupID = 2
		case senderLeafIndex = 3
		case count = 4
	}
}

/// The peer's staged proposal, carried uninterpreted alongside a
/// `DecryptResult` — `digest` is `sha256` of the proposal bytes, `proposing`
/// is the sender's `ClientId`, `context` is a digest of this session's
/// SEND-group classical group id — the sender's receive group — so it
/// equals the sender's `proposalContext()`.
public struct QueuedProposal: Sendable {
	public let digest: Data
	public let proposing: Data
	public let context: Data
	/// D6 (protocol doc §2): whether this offer's Update moves the proposer's
	/// leaf in OUR send group (`sendGroup.classical`) to a DIFFERENT
	/// credential id equal to the peer's CURRENT canonical principal
	/// (`theirPrincipalState`'s synced id) — a lagging leaf catching up,
	/// never a new authorization and never a rollback. `false` for a same-id
	/// refresh, a move to a candidate that is merely authorized (not yet
	/// canonical), a move to any canonical-but-not-current id, or any
	/// verification failure. A host may approve a flagged offer like a
	/// new-client offer (`queueProposal`); it authorizes no new credential.
	public let isCatchUp: Bool
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
	/// The peer's current credential id, whenever this apply moved the PEER's
	/// leaf in this recv group to a new presentation (their own-leaf rotation
	/// catch-up, or the first fold of their rotating `Upd`) — `nil` otherwise.
	/// Slice 6. swift-mls's `.credentialReplaced` effect fires on EITHER the
	/// credential id or the presented signing key changing
	/// (`CredentialPresentation` is `Equatable` over both), but `canonicalize`
	/// filters that down to an id change only: every own-leaf move now mints
	/// a fresh signature key under the SAME id (a routine offer, a catch-up,
	/// a commit's path leaf), so a same-id key-only move raises neither
	/// `newSender` nor `ownCredentialCanonicalized`. `newSender` fires only
	/// when the peer's id genuinely changes.
	/// Also set (slice 11) for a Group_B join that adopts a dedicated
	/// principal D: `didApplyRemoteCommit` stays `false` there (that Bool
	/// means "applied a remote *commit*"; a join is not one) — `newSender`
	/// is the sole adoption signal in that case.
	public let newSender: Data?
	/// Whether this apply moved MY OWN leaf in this recv group to a new
	/// credential — the first canonicalization of a rotation I authored via
	/// `prepareToEncrypt(rotating:)`. Named for what it reports (a Bool), not
	/// Rust's always-present `new_recipient` id. Slice 6.
	public let ownCredentialCanonicalized: Bool
	public let queuedProposal: QueuedProposal
	/// This call's own `StateUpdate` — `.checkpoint` when the applied staple
	/// (if any) moved a PQ tree (`applyBind` rides this method), else `.core`.
	public let update: StateUpdate
}

/// One directional group pair's `{pqEpoch, classicalEpoch}` — mirrors the
/// Rust reference's `ApqEpochs` (`lib.rs:517-519`). `pqEpoch` is `0` while
/// that group's PQ half is deferred (pre-§A.3 Group_B) or the pair is absent
/// entirely.
public struct GroupEpochs: Sendable, Hashable {
	public let pqEpoch: UInt64
	public let classicalEpoch: UInt64
}

/// `encrypt`'s result: the sealed frame plus this call's own `StateUpdate`
/// (`.core` — `encrypt` never touches a PQ tree).
public struct EncryptResult: Sendable {
	public let frame: Data
	public let update: StateUpdate
}

/// Slice 11 (contract-26): the paused `0x0B` establishment handoff a
/// `processIncoming` call surfaced instead of joining — the caller verifies
/// `envelope`'s signature out of band, then re-feeds the SAME (or a later)
/// frame carrying this exact pair to `processIncomingApproved`.
public struct PendingEstablishment: Sendable, Equatable {
	public let envelope: Data
	public let welcome: Data
}

/// The result of `processIncoming`/`processIncomingApproved` (slice 11):
/// the compiler-forced-unmissable 4-case sum, Rust lib.rs:586-92.
/// `.decrypted` is the everyday `0x03` app frame (unchanged join/commit
/// hints ride `DecryptResult` as before); `.joined` is a STANDALONE
/// welcome's FIRST join (a bare `0x01`, or an approved standalone `0x0B`) —
/// state-advancing, carrying that join's own `StateUpdate`; `.pendingEstablishment`
/// is any `0x0B` pre-approval pause (only while `recvGroup == nil`) — no
/// state change at all; `.ignored` is idempotent welcome RE-DELIVERY only,
/// never a first join (a first join is always state-advancing, so it is
/// always `.joined`/`.decrypted` — never this case, else a restore would
/// lose it).
public enum IncomingResult: Sendable {
	case decrypted(DecryptResult)
	case joined(newSender: Data?, update: StateUpdate)
	case pendingEstablishment(PendingEstablishment)
	case ignored
}

/// The shared result shape for every side-band round-starter/responder that
/// returns a bare frame today (`pqBootstrapBegin`/`pqBootstrapRespond`/
/// `pqRatchetRespond`/`pqRekeyBegin`/`pqRekeyRespond`) — the frame to hand the
/// peer, plus this call's own `StateUpdate`.
public struct SideBandResult: Sendable {
	public let frame: Data
	public let update: StateUpdate
	/// The peer leaf's NEW Basic credential id, when this call's Commit′
	/// moved it to a different id — `pqRekeyRespond` sets this whenever the
	/// folded peer Upd′ changed the sender leaf's id; every other side-band
	/// call (`pqBootstrapBegin`/`Respond`, `pqRatchetRespond`, `pqRekeyBegin`)
	/// leaves it `nil`, same as a same-id rekey. A hint for hosts; session
	/// state (`theirPrincipalState`) is the truth.
	public let rotatedCredential: Data?

	// Explicit, not the synthesized memberwise init: every existing
	// construction site (`pqBootstrapBegin`/`Respond`, `pqRatchetRespond`,
	// `pqRekeyBegin`) stays source-compatible via this default, while
	// `pqRekeyRespond` alone passes a non-nil value.
	init(frame: Data, update: StateUpdate, rotatedCredential: Data? = nil) {
		self.frame = frame
		self.update = update
		self.rotatedCredential = rotatedCredential
	}
}

/// One party's classical-credential state, as this session currently tracks
/// it (mirrors the Rust reference's `PrincipalState`, `lib.rs:654-667`) —
/// derived from the Authentication Service's own `PartySequence`, never
/// separately cached: `.sync` once the tracked party's sequence has no
/// outstanding authorization, `.pending` while one does.
public enum PrincipalState: Sendable, Equatable {
	case sync(Data)
	case pending(old: Data, new: Data)

	/// The live id this state names — the synced one, or the OLD one while a
	/// rotation is `.pending` (mirrors `lib.rs:660-666`).
	public var clientID: Data {
		switch self {
		case .sync(let id): id
		case .pending(let old, _): old
		}
	}
}

/// A minted classical successor, held while a rotation is in flight (a
/// single candidate at a time) — bookkeeping only: the actual signing key
/// this candidate names lives in `leafKeys.recvClassical.pending` alone,
/// seeded from the SAME mint (`prepareToEncrypt(rotating:)`). Send-classical
/// never holds a copy: our own commit mints its own fresh key straight into
/// `current` on apply, independent of any recv-classical candidate. Its
/// `.basic(clientID)` is what `NewSigningIdentity` carries (with the stored
/// recv-classical key) when authoring the rotation or catching up the
/// lagging leaf.
struct RotationCandidate: Sendable {
	let clientID: Data
	/// The `recvGroup.classical` epoch this candidate's rotating `Upd(self)`
	/// was staged at — `prepareToEncrypt(rotating:)`'s wedge relaxation
	/// compares this against that group's LIVE epoch: once it has moved on,
	/// the peer can no longer fold this now-stale proposal, so a fresh
	/// rotation may replace this candidate even though it has not yet
	/// canonicalized. An idempotent RE-STAGE of this SAME candidate (naming
	/// the same `clientID` again) refreshes this field to the CURRENT
	/// epoch unconditionally, rather than leaving it at its original stage
	/// point — otherwise a second re-stage within that same epoch would
	/// wrongly qualify for the wedge relaxation and silently strand this
	/// candidate's own key.
	let proposedAtRecvEpoch: UInt64
}

/// `handleStaple`'s internal result — `applyFoldCommit`/`applyBind` widened
/// (slice 6) to also report a credential change this apply just canonicalized,
/// alongside whether a commit applied at all.
struct StapleApplyResult: Sendable {
	let applied: Bool
	let newSender: Data?
	let ownCredentialCanonicalized: Bool

	static let notApplied = StapleApplyResult(
		applied: false, newSender: nil, ownCredentialCanonicalized: false)
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
	/// `var`, not `let`: the initiator clears its own classical init secret
	/// in place once `joinGroupBIfNeeded` (Messaging) has spent it —
	/// everything else about an identity is fixed for the session's life.
	var identity: TwoMLSIdentity
	/// The credential-sequence Authentication Service state (Germ policy,
	/// RFC 9420 §5.3.1's "application responsibility") — seeded at
	/// `initiate`/`receive` and consulted there against the peer's other
	/// half; slice 6 wires it further at every rotation seam:
	/// `validateOfferedUpdate` (peer-offer authorization, +ClassicalCommit),
	/// `committingRound` (canonicalizing our own fold), and
	/// `applyFoldCommit`/`applyBind` (the commit-effect adjudication seam,
	/// `AuthCore.adjudicate`).
	var auth: AuthCore
	var sendGroup: APQGroup?
	var recvGroup: APQGroup?
	var currentStaple: Data
	var pendingProposal: (proposing: Data, message: Data, hash: Data)?
	var joinedWelcomeDigest: Data?
	let initiated: Bool
	/// KP′'s own leaf+init secrets plus the `KeyPackage` itself — the
	/// initiator's joiner credentials for `pqBootstrapJoin`. `nil` on the
	/// responder. The public KP′ (MLSMessage-wrapped, §11 #7) is never stored
	/// separately — it is derived on demand from `keyPackage` here
	/// (`bootstrapKPBytes()`), so it structurally cannot outlive this secret.
	var bootstrapKPSecret:
		(
			leafSecretKey: MLS.HpkeSecretKey, initSecretKey: MLS.HpkeSecretKey,
			keyPackage: MLS.RFC9420.KeyPackage
		)?
	/// The responder's (Bob's) pinned `H(KP′)`, validated at `receive` —
	/// `nil` on the initiator.
	var expectedBootstrapKPCommitment: Data?
	/// The peer's published combiner key package (`initiate`'s `their`) —
	/// retained ONLY on the initiator, so `pendingOutbound()` (slice 9,
	/// PR3b) can re-seal the §A.1 establishment envelope on every re-send.
	/// Cleared at `joinGroupBIfNeeded` (Messaging.swift) once Group_B is
	/// joined: the initiator has nothing left to establish past that point.
	/// `nil` on the responder, which never sends this envelope.
	var initialTheirKP: CombinerKeyPackage?
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
	/// The opaque, replay-stable token this session was spawned under via
	/// `Invitation.receive` — `nil` on the initiator (who has no spawn
	/// token) or a session accepted through the lower-level
	/// `receive(identity:...)` entry point directly. `forwarded(spawnToken:)`
	/// validates a replayed initial frame's routing against this (book
	/// session-lifecycle.md, "Invitations & replayed initial frames").
	let spawnToken: Data?

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

	// MARK: Attachment CEK export (value-engine parity)

	/// The session-layer `0xFF03` attachment component id — distinct from
	/// the combiner's own `apq_psk` (`0xFF01`) and the cross-party PSK
	/// (`0xFF02`, `crossPartyComponentID` above); the deployed engine's own
	/// attachment component. `exportAttachmentCEKSend`/
	/// `exportAttachmentCEKRecv` (+Attachment.swift) derive each
	/// attachment's CEK from it via `ExpandWithLabel`; the id itself never
	/// rides the wire.
	static let attachmentComponentID = MLS.Extensions.ComponentID(rawValue: 0xFF03)

	/// The bounded send-side `0xFF03` attachment-component ledger over
	/// `sendGroup.classical`, keyed by epoch — mirrors `sendCrossPSKLedger`'s
	/// own shape and rationale (+Attachment.swift's
	/// `rememberSendAttachmentComponent`): `safeExportSecret` consumes a
	/// `(group, epoch, component)` leaf on export and the exporter tree
	/// retains only the current epoch's frontier, so every send-classical
	/// commit/creation site remembers it eagerly, keeping
	/// `exportAttachmentCEKSend` a pure read. Bounded to
	/// `attachmentLedgerWindow` entries, oldest evicted first.
	var sendAttachmentLedger: [UInt64: SecretBytes] = [:]
	/// The receive-side analogue of `sendAttachmentLedger`, keyed by
	/// `recvGroup.classical` epoch — CAPTURE-ON-ENTRY
	/// (+Attachment.swift's `rememberRecvAttachmentComponent`): every
	/// recv-group creation/advance site ledgers the newly-current epoch's
	/// component immediately, since `exportAttachmentCEKRecv` is a pure read
	/// with no live-export fallback for the epoch a caller actually asks
	/// for.
	var recvAttachmentLedger: [UInt64: SecretBytes] = [:]
	/// `sendAttachmentLedger`/`recvAttachmentLedger`'s shared retention
	/// depth — mirrors `sendCrossPSKLedgerWindow`'s own generous-over-
	/// in-flight-commits reasoning.
	static let attachmentLedgerWindow = 8

	// MARK: Routing (rendezvous, slice 9 PR1)

	/// Every retained classical epoch's rendezvous address for THIS
	/// session's own send group — `rendezvousSecret(sendGroup.classical)` at
	/// each epoch it has occupied. Captured live by `recordListenRendezvous()`
	/// at every site `sendGroup.classical`'s epoch advances or the group is
	/// first created (an exporter is only derivable at its own epoch, never
	/// retroactively) — group creation in `initiate`/`receive`, and
	/// `committingRound`'s success point (which also covers an owed §4b bind
	/// discharge: it folds into that same commit). Retained to
	/// `sendGroup.classical.retention.resumptionPskDepth` behind the current
	/// epoch, pruned on every capture, so the listen window is exactly the
	/// window a peer's frame can still be routed against (book
	/// session-lifecycle.md, "Routing"). `shouldListenOn()` only reads this —
	/// a mutating backstop there would violate the return-based persistence
	/// contract (nothing calling it returns a `StateUpdate`).
	var listenRendezvous: [UInt64: Data] = [:]

	// MARK: Header encryption (slice 9, PR2)

	/// Every retained classical epoch's `HeaderKey` for THIS session's own
	/// send group — captured by `recordListenRendezvous()` in lockstep with
	/// `listenRendezvous` (same sites, same idempotency, same retention):
	/// "routable ⟺ openable", the classical header window is exactly the
	/// rendezvous listen window (book header-encryption.md, "Receive rule").
	/// Trial-opened FIRST (before `recvHeaderKeysPQ`), newest epoch first.
	var recvHeaderKeys: [UInt64: Data] = [:]
	/// Every retained `pq_epoch`'s `HeaderKeyPQ` for THIS session's own
	/// send-PQ group — captured by `recordPQHeaderKey()` wherever
	/// `sendGroup.pq`'s epoch advances or the half is founded. No rendezvous
	/// coupling (the PQ side-band keeps no routing addresses of its own);
	/// retained to a flat keep-newest `pqHeaderWindow` regardless of
	/// classical traffic.
	var recvHeaderKeysPQ: [UInt64: Data] = [:]
	/// `PQ_HEADER_WINDOW` (header-encryption.md, "Receive rule" — the
	/// two-windows bullet) — a plain keep-newest count, not an
	/// epoch-arithmetic floor: A.3/A.5 are turn-based with one op in flight,
	/// so a few keys cover any lag regardless of classical traffic.
	static let pqHeaderWindow = 4

	/// The host's frame-sizing intent (book header-encryption.md, "Frame
	/// length prefix & padding" — `set_pad_target(Some(n))`): `nil` (the
	/// default) means natural size, unpadded. Live host plumbing — NOT
	/// archived (the header-key windows above ARE persisted; this and
	/// `lastMessageFrameLen` are not), so a restored session starts back at
	/// `nil` and the host must re-supply it via `setPadTarget`.
	var padTarget: Int? = nil
	/// The most recent `encrypt`'s UNSEALED message-frame length — what
	/// `Frames.encodeMessageFrame` builds, before `seal` wraps it — the
	/// ceiling `sideBandPadTo` grows a co-stapled side-band frame up to.
	/// Equal SEALED lengths follow from the constant per-frame seal overhead
	/// (book header-encryption.md, "Sealed frame"), so this is deliberately
	/// NOT a "sealed length." Live-only like `padTarget`: not archived,
	/// resets to 0 on restore.
	var lastMessageFrameLen: Int = 0

	// MARK: §15 classical principal rotation (slice 6)

	/// The classical successor minted by our own `prepareToEncrypt(rotating:)`
	/// (F2: a single in-flight candidate) — `nil` until we author a rotation.
	/// Retained for the life of the session once set (F4's minimal cut: the
	/// choke point (`assertLeafKeysPresented`) and every signing site read
	/// the stored key sets, never this record's own key, so a stale
	/// candidate is harmless — a real custodian would retire it once no
	/// leaf presents it, which needs the PQ catch-up of a later slice).
	var rotationCandidate: RotationCandidate? = nil

	// MARK: Born-dedicated principal + contract-26 handoff (slice 11)

	/// The non-emittable gate: `true` from the moment a
	/// dedicated principal is minted (`receive(newClientID:)`) until
	/// `installEstablishmentEnvelope` succeeds. `ensureEstablishmentDelegated()`
	/// is consulted first by every frame-producing public method while this
	/// is set, so Bob can never emit a frame under the bare, unauthenticated
	/// `0x01` staple before the signed contract-26 handoff wraps it.
	var owesEstablishmentEnvelope: Bool = false

	// MARK: Migration inputs on stored per-group signing keys

	/// The migrated deployed engine's own-offer window record, when this
	/// session was minted (or restored) with one — the window BLOB itself
	/// never rides here; this is only the hoisted fields plus id a window
	/// load/apply cross-checks. Drained to `nil` the moment
	/// `recvGroup.classical`'s epoch next advances (`ownOfferWindowID`'s own
	/// doc) — the host may then delete its stored blob once the archive
	/// from that same call is durable.
	var ownOfferWindow: OwnOfferWindowRecord? = nil
	/// The migrated deployed engine's PQ side-band wedge, when present —
	/// blocks the PQ bind/join doors and self-drive; never blocks owed-bind
	/// discharge or classical messaging (matching the deployed engine).
	/// Never cleared natively (this step); the book's exit is
	/// re-establishment. Internal: `pqSideBandWedged` (below) is the public
	/// `Bool` query — split the same way the deployed engine itself splits
	/// its internal `pq_wedged: Option<PqWedge>` from its public
	/// `pq_side_band_wedged() -> bool`.
	var pqWedge: MigratedPQWedge? = nil
	/// The host's establishment-self-sufficient app payload, set via
	/// `setInitialAppPayload` or carried by migration (rule 9: non-empty
	/// only for a pre-join initiator that still retains a seal target,
	/// `initialTheirKP`). Consumed by `composeInitialEnvelope`, both from
	/// `pendingOutbound()` and from a pre-join `encrypt`. Drains alongside
	/// `initialTheirKP` the moment the initiator joins.
	var initialAppPayload: Data? = nil
	/// The migrated deployed engine's set of groups this session presently
	/// has no signing custody over — a read-only query,
	/// exposed as the raw set. Signing in such a group throws
	/// `.leafCustodyUnavailable`; self-drive never opens a round that needs
	/// one. Monotonically drained (never re-added) the moment a promotion
	/// gives the group a `current` key (`StateUpdate.swift`'s choke point).
	public internal(set) var noCustody: Set<MigratedGroupRole> = []

	/// Read-only query: whether a PQ side-band round
	/// has wedged past its point of no return. Never blocks owed-bind
	/// discharge or classical messaging.
	public var pqSideBandWedged: Bool { pqWedge != nil }

	/// Read-only query: true when both classical roles
	/// currently have signing custody and the session is established — a
	/// recv-classical no-custody session cannot even mint its own
	/// `Upd(self)`.
	public var canSend: Bool {
		isEstablished && !noCustody.contains(.sendClassical)
			&& !noCustody.contains(.recvClassical)
	}

	/// The id of this session's own-offer window record, if
	/// one is outstanding. Only ever moves from a value to `nil` (the drain
	/// at every `recvGroup.classical` epoch advance) — never to a
	/// DIFFERENT id. `nil` means the host may delete its stored blob once
	/// the archive from that same call is durable.
	public var ownOfferWindowID: Data? { ownOfferWindow?.id }

	// MARK: Signing keys stored by role

	/// The four groups' own stored signing-key sets — the ONLY source of a
	/// group's signing secrets (`LeafKeys.swift`). `identity`/
	/// `rotationCandidate` stay for seeding, persistence and the migration
	/// mint only; no signing site reads them directly any more.
	var leafKeys: LeafKeys

	// MARK: Return cadence (slice 8a)

	/// This session's own persistence sequence number — every state-advancing
	/// method bumps it (checked add; stops rather than wraps past
	/// `UInt64.max`, `advanceStateSeq()`) and stamps its returned
	/// `StateUpdate` with the result. `restore` seeds it from the reconciled
	/// blob's own `stateSeq`. Public with an `internal` setter: any file in
	/// this module may advance it, but only a `StateUpdate` ever surfaces the
	/// value to the app — a same-named public accessor func is impossible
	/// alongside a stored property of that name (Swift, not a design choice).
	public internal(set) var stateSeq: UInt64 = 0
	/// The `stateSeq` at which `currentStaple` was last (re)installed by a
	/// real fold/bind commit (`committingRound`) — or, since slice 11, by
	/// `installEstablishmentEnvelope`, the SECOND writer of `currentStaple`
	/// past construction (wrapping the bare `0x01` in the signed `0x0B`
	/// handoff) — `PrepareResult.dependsOnSeq`'s durability watermark.
	/// `restore` seeds it to the reconciled `stateSeq` too: a safe,
	/// never-under value (that blob is already durable, or the app could
	/// not have restored from it), even though it may overstate exactly
	/// when `currentStaple` was first installed.
	var currentStapleSeq: UInt64 = 0
	/// The PQ-epoch manifest as of the last `.checkpoint` `StateUpdate` this
	/// session actually minted — `stateUpdate(kind:)`'s sticky invariant
	/// upgrades a `.core` request to `.checkpoint` whenever the LIVE manifest
	/// has since moved past this, so a PQ-tree move that lands on `self` but
	/// is cut short of ever returning its own `StateUpdate` (a throw further
	/// down the same call) cannot silently persist as an un-checkpointed
	/// Core. Seeded at the establishment baseline (every baseline mints a
	/// `.checkpoint`) and by `restore` from the reconciled blob's own
	/// manifest.
	var lastCheckpointedManifest = PQEpochManifest(
		sendPQEpoch: nil, recvPQEpoch: nil,
		sendPQKeys: GroupKeySetFingerprint(current: nil, pending: []),
		recvPQKeys: GroupKeySetFingerprint(current: nil, pending: []))

	/// The app-state binding this session was created with (`initiate`'s or
	/// `receive`'s `appBinding`), read from the send group's classical
	/// GroupContext — it rides the persisted group state, so a restored
	/// session's owner re-verifies here (book api-reference.md,
	/// group-rules.md rule 8). Errors only on a present-but-undecodable
	/// extension, so corruption can never read back as "unbound".
	public func appBinding() throws -> Data? {
		guard let send = sendGroup else { throw TwoMLSError.notEstablished }
		return try AppBinding.read(fromExtensionsOf: send.classical.context)
	}

	public var isEstablished: Bool { sendGroup != nil && recvGroup != nil }
	/// Both directional pairs have their PQ half present — the §A.3
	/// bootstrap's completion condition.
	public var isFullyEstablished: Bool { sendGroup?.pq != nil && recvGroup?.pq != nil }
	public var myPQTurn: Bool { pqTurnMine }

	/// The send group's epoch pair — mirrors the reference's `epochs()`
	/// (`mod.rs:2095-2105`); zeros while unestablished.
	public var epochs: GroupEpochs { Self.groupEpochs(of: sendGroup) }

	/// One directional group pair's `{pqEpoch, classicalEpoch}` — `epochs`'s
	/// underlying computation. Zeros for a `nil` pair (mirrors the
	/// reference's absent-group `epochs()`).
	static func groupEpochs(of group: APQGroup?) -> GroupEpochs {
		GroupEpochs(
			pqEpoch: group?.pq?.context.epoch ?? 0,
			classicalEpoch: group?.classical.context.epoch ?? 0)
	}

	/// The context digest a host binds a proposal to — a digest of this
	/// session's own RECEIVE-group classical group id — mirroring the
	/// reference implementation's `proposal_context()`; raw suite-hash bytes
	/// (sha256 for the deployed classical suite). Equals the peer's
	/// `QueuedProposal.context` for every frame this session sends. `nil`
	/// while `recvGroup` doesn't exist yet, same non-throwing shape as
	/// `Invitation.processedWelcomeGroupID`.
	public func proposalContext() -> Data? {
		guard let recv = recvGroup else { return nil }
		return try? classicalProvider.hash(recv.classical.context.groupID)
	}

	/// My own classical-credential state, DERIVED from the Authentication
	/// Service's `auth.mine` (never separately cached, so it cannot desync
	/// from the sequence `commit`/`authorize` actually maintain): `.pending`
	/// while an authorized-but-not-yet-canonical successor is outstanding
	/// (`prepareToEncrypt(rotating:)`, before the peer's fold commit lands),
	/// `.sync` once it has (mirrors `mod.rs:2115-2120`).
	public var myPrincipalState: PrincipalState { Self.principalState(auth.mine) }
	/// The peer's classical-credential state, as this session's `auth.theirs`
	/// currently tracks it — `.pending` from the moment we approve their
	/// offered rotation (`queueProposal`) until we fold it
	/// (`committingRound`'s `theirs.commit`).
	public var theirPrincipalState: PrincipalState { Self.principalState(auth.theirs) }

	private static func principalState(_ sequence: PartySequence) -> PrincipalState {
		let current = sequence.current ?? Data()
		if let next = sequence.authorizedNext.last {
			return .pending(old: current, new: next)
		}
		return .sync(current)
	}

	/// A classical group's own occupied leaf, read straight off its tree —
	/// the one read every custody/rotation site needs (my own leaf's
	/// CURRENTLY presented credential/key), never a cached claim.
	static func ownLeaf(of group: MLS.RFC9420.Group) throws -> MLS.RFC9420.LeafNode {
		guard let record = group.tree.leaf(at: group.myLeafIndex) else {
			throw TwoMLSError.credentialUnknown
		}
		return try MLS.RFC9420.LeafNode(mlsEncoded: record.encoded)
	}

	/// Resolve `sendGroup.classical`'s own leaf's CURRENT signing key — every
	/// classical send-group-leaf site's key: `encrypt`'s `protect`,
	/// `committingRound`'s `committing`, and the three §A.4 ratchet legs'
	/// `protect` (`+Ratchet.swift`). Reads `leafKeys.sendClassical`'s slot
	/// directly — no leaf decode, no identity/candidate resolution.
	func sendClassicalSigningKey() throws -> MLS.SignatureSecretKey {
		guard sendGroup != nil else { throw TwoMLSError.notEstablished }
		guard let current = leafKeys.sendClassical.current else {
			throw noCustody.contains(.sendClassical)
				? TwoMLSError.leafCustodyUnavailable : TwoMLSError.credentialUnknown
		}
		return current.signingKey
	}

	/// Resolve `recvGroup.classical`'s own leaf's CURRENT signing key —
	/// `prepareToEncrypt`'s `proposeUpdate`. Reads `leafKeys.recvClassical`'s
	/// slot directly.
	func recvClassicalSigningKey() throws -> MLS.SignatureSecretKey {
		guard recvGroup != nil else { throw TwoMLSError.notEstablished }
		guard let current = leafKeys.recvClassical.current else {
			throw noCustody.contains(.recvClassical)
				? TwoMLSError.leafCustodyUnavailable : TwoMLSError.credentialUnknown
		}
		return current.signingKey
	}

	/// Resolve `sendGroup.pq`'s own leaf's CURRENT signing key (slice 11)
	/// — `owePQBind`'s commit and `pqRekeyRespond`'s commit. Reads
	/// `leafKeys.sendPQ`'s slot directly.
	func sendPQSigningKey() throws -> MLS.SignatureSecretKey {
		guard let send = sendGroup, send.pq != nil else {
			throw TwoMLSError.notEstablished
		}
		guard let current = leafKeys.sendPQ.current else {
			throw noCustody.contains(.sendPQ)
				? TwoMLSError.leafCustodyUnavailable : TwoMLSError.credentialUnknown
		}
		return current.signingKey
	}

	/// Resolve `recvGroup.pq`'s own leaf's CURRENT signing key (slice 11)
	/// — `pqRekeyBegin`'s `proposeUpdate`. Reads `leafKeys.recvPQ`'s slot
	/// directly.
	func recvPQSigningKey() throws -> MLS.SignatureSecretKey {
		guard let recv = recvGroup, recv.pq != nil else {
			throw TwoMLSError.notEstablished
		}
		guard let current = leafKeys.recvPQ.current else {
			throw noCustody.contains(.recvPQ)
				? TwoMLSError.leafCustodyUnavailable : TwoMLSError.credentialUnknown
		}
		return current.signingKey
	}

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
		bootstrapKPSecret:
			(
				leafSecretKey: MLS.HpkeSecretKey, initSecretKey: MLS.HpkeSecretKey,
				keyPackage: MLS.RFC9420.KeyPackage
			)? = nil,
		expectedBootstrapKPCommitment: Data? = nil,
		initialTheirKP: CombinerKeyPackage? = nil,
		pqTurnMine: Bool,
		owedBind: OwedBind? = nil,
		pqInflight: PQInflight? = nil,
		pendingSideBand: Data? = nil,
		peerAppliedSendEpoch: UInt64? = nil,
		lastCrossInjected: UInt64? = nil,
		lastCrossInjectedPQ: UInt64? = nil,
		lastSendPQExported: UInt64? = nil,
		spawnToken: Data? = nil,
		owesEstablishmentEnvelope: Bool = false,
		ownOfferWindow: OwnOfferWindowRecord? = nil,
		pqWedge: MigratedPQWedge? = nil,
		noCustody: Set<MigratedGroupRole> = [],
		initialAppPayload: Data? = nil,
		leafKeys: LeafKeys
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
		self.bootstrapKPSecret = bootstrapKPSecret
		self.expectedBootstrapKPCommitment = expectedBootstrapKPCommitment
		self.initialTheirKP = initialTheirKP
		self.pqTurnMine = pqTurnMine
		self.owedBind = owedBind
		self.pqInflight = pqInflight
		self.pendingSideBand = pendingSideBand
		self.peerAppliedSendEpoch = peerAppliedSendEpoch
		self.lastCrossInjected = lastCrossInjected
		self.lastCrossInjectedPQ = lastCrossInjectedPQ
		self.lastSendPQExported = lastSendPQExported
		self.spawnToken = spawnToken
		self.owesEstablishmentEnvelope = owesEstablishmentEnvelope
		self.ownOfferWindow = ownOfferWindow
		self.pqWedge = pqWedge
		self.noCustody = noCustody
		self.initialAppPayload = initialAppPayload
		self.leafKeys = leafKeys
	}
}
