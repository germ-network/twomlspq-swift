import Foundation

/// Which of the two behavior profiles a session runs (protocol doc §5):
/// `.correct` is the book plus D1–D6, with nothing kept only for the
/// deployed engine; `.deployedCompatible` adds C1 (this file) and C2. Every
/// session is deployed-compatible until sessions carry a real profile
/// (recorded in the group at creation, per KeyPackage capability
/// negotiation) — `TwoMLSSession.profile` fixes it here as the seam that
/// stored value replaces.
enum SessionProfile: Sendable, Equatable {
	case correct
	case deployedCompatible
}

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Every session is deployed-compatible until profiles exist (protocol
	/// doc §5: "every session created before profiles exist" is this
	/// profile) — a future change replaces this computed constant with the
	/// value recorded in the group.
	var profile: SessionProfile { .deployedCompatible }

	/// C1 (protocol doc §4): the §A.5 `Upd′`'s authenticated data. Empty
	/// under `.correct`, and empty for a key-only move under either
	/// profile — sent only on a `.deployedCompatible` move that changes the
	/// credential id, matching the deployed engine's own trigger shape
	/// (`pq_ops.rs:390-397`). Pure, so both branches are unit-testable
	/// without a DEBUG switch.
	static func rekeyAnnouncement(oldID: Data, newID: Data, profile: SessionProfile) -> Data {
		guard profile == .deployedCompatible, oldID != newID else { return Data() }
		return newID
	}
}
