import Foundation
import SecretBytes

// MARK: - Return-cadence plumbing (slice 8a, PR2)
//
// No push/sink (Mark decision B): every state-advancing method bumps
// `stateSeq` and returns its own `StateUpdate` (`archive` from PR1's
// `makeSessionArchive`, now reading the live `stateSeq` field rather than
// taking it as a parameter) alongside its normal output. Return-on-success
// only: a throwing mutation returns nothing, so the live struct can run
// ahead of the last blob the app actually saved — a later `restore` just
// rewinds to that last consistent state (documented, accepted behavior).

/// One state-advancing call's persistable output: `kind` says which slot
/// (Core/Checkpoint) the app should file `archive` under, keyed by
/// `stateSeq` — the latest of each kind is what `restore` reconciles from.
public struct StateUpdate: Sendable {
	public let kind: BlobKind
	public let stateSeq: UInt64
	public let archive: SecretArchive
}

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Bumps `stateSeq` for a fresh state-advancing call. Checked add: past
	/// `UInt64.max` this stops advancing rather than wrapping — an
	/// unreachable session lifetime in practice, kept fail-safe rather than
	/// unchecked.
	mutating func advanceStateSeq() {
		let (next, overflow) = stateSeq.addingReportingOverflow(1)
		if !overflow { stateSeq = next }
	}

	/// Records that a NEW staple/commit was just installed at the CURRENT
	/// `stateSeq` — call only from the one path that actually assigns a fresh
	/// `currentStaple` (`committingRound`'s success point), after
	/// `advanceStateSeq()`.
	mutating func markStapleInstalled() {
		currentStapleSeq = stateSeq
	}

	/// This call's own `StateUpdate`, at the CURRENT `stateSeq` — every
	/// caller bumps first (`advanceStateSeq()`) except the establishment
	/// baseline, which mints one at the starting `stateSeq` (0) instead.
	func stateUpdate(kind: BlobKind) throws -> StateUpdate {
		StateUpdate(
			kind: kind, stateSeq: stateSeq, archive: try makeSessionArchive(kind: kind))
	}
}
