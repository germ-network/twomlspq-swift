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

	/// Whether the send-driven trigger opens an A.5 catch-up instead of a
	/// plain A.4 ratchet. Our own leaf lagging opens the round once the
	/// peer has folded our target (the own-arm gate,
	/// `TwoMLSSession+Ratchet.swift`'s `rekeyDue`) — under BOTH profiles.
	/// The peer's leaf lagging opens the reciprocal round too, but under
	/// the deployed-compatible profile only once the peer's own A.5 has
	/// already landed (protocol doc §4 C2); the correct profile needs no
	/// such deferral. Pure, so every input combination is unit-testable
	/// without a DEBUG switch.
	static func opensRekey(
		ownLeafLags: Bool, ownTargetFolded: Bool, peerLeafLags: Bool, peerOwnA5Landed: Bool,
		profile: SessionProfile
	) -> Bool {
		if ownLeafLags { return ownTargetFolded }
		guard peerLeafLags else { return false }
		return profile == .correct || peerOwnA5Landed
	}
}
