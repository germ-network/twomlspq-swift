import Foundation
import MLSCodec
import MLSProfileRFC9420

/// Which of the two behavior profiles a session runs (protocol doc §5; book
/// group-rules.md rule 9): `.correct` is the book plus D1–D6, with nothing
/// kept only for the deployed engine; `.deployedCompatible` adds C1 (this
/// file) and C2. Chosen once per session from the two classical key
/// packages and recorded in both classical halves; the default records
/// nothing. `TwoMLSSession.profile` reads the recorded value off the send
/// group.
enum SessionProfile: Sendable, Equatable {
	case correct
	case deployedCompatible

	/// Every non-default profile this engine recognizes, newest first. Also
	/// the total order `negotiate` intersects against, so a future profile
	/// added here keeps the intersection rule stable.
	static let recognized: [SessionProfile] = [.correct]

	/// `CorrectProfile` (`0xF0A3`, book wire-format.md): the leaf capability
	/// entry and the GroupContext extension that records the profile. The
	/// default profile has none.
	var extensionType: MLS.RFC9420.ExtensionType? {
		switch self {
		case .correct: MLS.RFC9420.ExtensionType(rawValue: 0xF0A3)
		case .deployedCompatible: nil
		}
	}

	/// The profiles a leaf advertises, in `recognized` order.
	static func advertised(by leaf: MLS.RFC9420.LeafNode) -> [SessionProfile] {
		recognized.filter { profile in
			profile.extensionType.map { leaf.capabilities.extensions.contains($0) } ?? false
		}
	}

	/// The newest profile both classical key-package leaves advertise, else
	/// the default (book group-rules.md rule 9).
	static func negotiate(
		own: MLS.RFC9420.LeafNode, their: MLS.RFC9420.LeafNode
	) -> SessionProfile {
		let theirs = advertised(by: their)
		return advertised(by: own).first { theirs.contains($0) } ?? .deployedCompatible
	}

	/// The classical half's creation-time GroupContext extensions that
	/// record this profile: one empty extension of its type, or none.
	var recordExtensions: [MLS.RFC9420.Extension] {
		extensionType.map { [MLS.RFC9420.Extension(type: $0, data: Data())] } ?? []
	}

	/// The profile a GroupContext records — `.deployedCompatible` when none
	/// is. Throws `.sessionProfileMismatch` when more than one profile type
	/// is present, or one is present with non-empty contents.
	static func recorded(in context: MLS.RFC9420.GroupContext) throws -> SessionProfile {
		let matches = recognized.flatMap { profile in
			context.extensions.filter { $0.type == profile.extensionType }.map { (profile, $0) }
		}
		guard let (profile, ext) = matches.first else { return .deployedCompatible }
		guard matches.count == 1, ext.data.isEmpty else {
			throw TwoMLSError.sessionProfileMismatch
		}
		return profile
	}

	/// A leaf in a profile-carrying group must keep advertising the recorded
	/// type (book group-rules.md rule 9's tail, mirrors the AppBinding leaf
	/// gate).
	func ensureAdvertised(by leaf: MLS.RFC9420.LeafNode) throws {
		guard let type = extensionType else { return }
		guard leaf.capabilities.extensions.contains(type) else {
			throw TwoMLSError.leafCapabilityUnadvertised
		}
	}
}

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// The profile recorded in this session's send group's classical half —
	/// re-derived on every read rather than stored (no archive key).
	/// Swallows a malformed record to `.deployedCompatible`: unreachable
	/// today (archives are sealed, the migration mint refuses any record,
	/// and establishment validates the record before it is ever claimed —
	/// restore re-derives from the already-validated send group and adds no
	/// separate check of its own).
	var profile: SessionProfile {
		guard let context = sendGroup?.classical.context,
			let recorded = try? SessionProfile.recorded(in: context)
		else { return .deployedCompatible }
		return recorded
	}

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
