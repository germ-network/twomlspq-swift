import Foundation
import SecretBytes

// MARK: - Return-cadence plumbing (slice 8a)
//
// Return-based, sealing external: every state-advancing method bumps
// `stateSeq` and returns its own `StateUpdate` (`archive` from the session
// archive's own `makeSessionArchive`, which reads the live `stateSeq` field
// rather than taking it as a parameter) alongside its normal output.
// Return-on-success only: a throwing mutation returns nothing, so the live
// struct can run ahead of the last blob the app actually saved — a later
// `restore` just rewinds to that last consistent state (documented, accepted
// behavior).

/// One state-advancing call's persistable output: `kind` says which slot
/// (Core/Checkpoint) the app should file `archive` under, keyed by
/// `stateSeq` — the latest of each kind is what `restore` reconciles from.
public struct StateUpdate: Sendable {
	public let kind: BlobKind
	public let stateSeq: UInt64
	public let archive: SecretArchive
}

/// One `pending` entry of a `GroupKeySetFingerprint` — the target credential
/// id plus its signature key, rides as an array (sorted by target at
/// construction) rather than a `Dictionary`, exactly like
/// `GroupKeySetArchive`'s own `pending`, so the encoded bytes are stable
/// across runs instead of following `Dictionary`'s unspecified iteration
/// order.
struct PendingFingerprintEntry: Equatable, Sendable, Codable {
	let target: Data
	let signatureKey: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case target = 0
		case signatureKey = 1
	}
}

/// A `GroupKeySet`'s public shape only — its own leaf's current signature
/// key, plus every pending target's signature key. Equatable, Sendable and
/// Codable, none of which `GroupKeySet` itself needs to be, since the
/// secrets never ride in this type. What `PQEpochManifest` compares to catch
/// a PQ key-set change the epoch alone would miss, and (archived, on
/// `SessionArchive`) what `validateManifestAgreement` cross-checks a Core's
/// claimed PQ key state against a paired Checkpoint's.
struct GroupKeySetFingerprint: Equatable, Sendable, Codable {
	let current: Data?
	let pending: [PendingFingerprintEntry]

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case current = 0
		case pending = 1
	}
}

extension GroupKeySet {
	var fingerprint: GroupKeySetFingerprint {
		GroupKeySetFingerprint(
			current: current?.signatureKey.data,
			pending: pending.sorted { $0.key.lexicographicallyPrecedes($1.key) }
				.map {
					PendingFingerprintEntry(
						target: $0.key,
						signatureKey: $0.value.signatureKey.data)
				})
	}
}

/// Both PQ trees' epoch, exactly the manifest fields `SessionArchive` itself
/// carries (`sendPQEpoch`/`recvPQEpoch`), plus each PQ key set's own
/// fingerprint — the cheap, tree-hash-free signal both `processIncoming`'s
/// per-call kind derivation and the sticky checkpoint invariant below
/// compare against. A `nil` half compares unequal to any `Some`, so founding
/// OR losing a half counts as a move exactly like an epoch bump does; the
/// fingerprint catches a PQ key-set change an epoch bump alone would not —
/// `pqRekeyApply`'s promotion can move a key without necessarily moving
/// `recvPQEpoch` in a way this manifest would otherwise notice on its own
/// (the epoch DOES move on every rekey today, but the fingerprint is the
/// invariant's actual guarantee, not an accident of today's call sites).
struct PQEpochManifest: Equatable {
	let sendPQEpoch: UInt64?
	let recvPQEpoch: UInt64?
	let sendPQKeys: GroupKeySetFingerprint
	let recvPQKeys: GroupKeySetFingerprint
}

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	var pqEpochManifest: PQEpochManifest {
		PQEpochManifest(
			sendPQEpoch: sendGroup?.pq?.context.epoch,
			recvPQEpoch: recvGroup?.pq?.context.epoch,
			sendPQKeys: leafKeys.sendPQ.fingerprint,
			recvPQKeys: leafKeys.recvPQ.fingerprint)
	}

	/// Bumps `stateSeq` for a fresh state-advancing call. Checked add: past
	/// `UInt64.max` this stops advancing rather than wrapping — an
	/// unreachable session lifetime in practice, kept fail-safe rather than
	/// unchecked.
	mutating func advanceStateSeq() {
		let (next, overflow) = stateSeq.addingReportingOverflow(1)
		if !overflow { stateSeq = next }
	}

	/// Records that a NEW staple/commit was just installed at the CURRENT
	/// `stateSeq` — call only from a path that actually assigns a fresh
	/// `currentStaple`: `committingRound`'s success point, or (slice 11)
	/// `installEstablishmentEnvelope`'s success point, which wraps the bare
	/// `0x01` in the signed `0x0B` handoff. Call after `advanceStateSeq()`.
	mutating func markStapleInstalled() {
		currentStapleSeq = stateSeq
	}

	/// This call's own `StateUpdate`, at the CURRENT `stateSeq`. Every caller
	/// bumps first (`advanceStateSeq()`) except the establishment baseline,
	/// which mints one at the starting `stateSeq` (0) instead.
	///
	/// The sticky checkpoint invariant: several PQ-tree-moving methods
	/// (`applyBind` riding `processIncoming`; the bootstrap-join and re-key-
	/// apply PQ commits) move a PQ tree on `self` and only THEN run a further
	/// throwing step (`unprotect`/`decodeProposalSection`/`hash` in
	/// `processIncoming`; `owePQBind` in the other two) before this function
	/// is ever reached. Return-on-success-only means a throw there discards
	/// the `StateUpdate` entirely — no Checkpoint ever captures that move,
	/// yet the move already landed on `self`. Left alone, the next `.core`
	/// this session mints would carry a PQ-epoch manifest already ahead of
	/// the last real Checkpoint, which `restore` can never reconcile
	/// (`archiveInvalid` on every future restore until the next PQ op).
	/// Guarding against that here — comparing the CURRENT live manifest
	/// against the manifest as of the last `.checkpoint` this session
	/// actually minted, and upgrading a `.core` request when they disagree —
	/// closes every such site at the one choke point every `StateUpdate`
	/// passes through, rather than each call site individually. Comparing
	/// manifests (not a deeper tree hash) also means the bind-discharge
	/// round's PQ exporter-component consumption — which never moves an
	/// epoch — does not spuriously upgrade it.
	mutating func stateUpdate(kind: BlobKind) throws -> StateUpdate {
		// The live choke point runs FIRST — fail-closed, `.credentialUnknown`,
		// before the kind is even decided — then the sticky kind upgrade,
		// then the encode, and only once that has succeeded is the checkpoint
		// manifest stamped. A violation here mints nothing and stamps
		// nothing.
		try assertLeafKeysPresented()
		var kind = kind
		if kind == .core, pqEpochManifest != lastCheckpointedManifest {
			kind = .checkpoint
		}
		let archive = try makeSessionArchive(kind: kind)
		if kind == .checkpoint {
			lastCheckpointedManifest = pqEpochManifest
		}
		let update = StateUpdate(kind: kind, stateSeq: stateSeq, archive: archive)
		#if DEBUG
			TwoMLSSessionTestHooks.notifyStateUpdate(self)
		#endif
		return update
	}
}
