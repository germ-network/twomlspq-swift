import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420

// Restore and migration mint re-run the gates a live session enforces as its
// state is built, so neither an altered archive nor unauthenticated legacy
// input can hold a state no live path writes. Every failure is
// `.archiveInvalid`.
@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Group-context invariants fixed at creation: every present tree is
	/// two-party, both PQ halves are unbound and deployed-compatible, and the
	/// two classical halves carry the same AppBinding and profile. Per-leaf
	/// adverts are not checked here: a peer's commit path leaf is never
	/// capability-checked live, so a restore check on it would be
	/// peer-breakable.
	static func validateRestoredGroups(
		sendClassical: MLS.RFC9420.Group, sendPQ: MLS.RFC9420.Group?,
		recvClassical: MLS.RFC9420.Group?, recvPQ: MLS.RFC9420.Group?
	) throws {
		fatalError("unimplemented")
	}

	/// Each party's history holds 1...`credentialHistoryWindow` distinct ids,
	/// and no id in one party's history or `authorizedNext` is in the other's.
	static func validateAuthShape(_ auth: AuthCore) throws {
		fatalError("unimplemented")
	}

	/// A session owes the establishment envelope exactly when it is a
	/// dedicated acceptor still on its `0x01` staple: the send-classical own
	/// leaf presents an id newer in `mineHistory` than the recv-classical own
	/// leaf (an id evicted from `mineHistory` counts as oldest). This catches
	/// a flipped flag; it trusts the order of `mineHistory`.
	static func validateEstablishmentOwed(
		_ owes: Bool, initiated: Bool, currentStaple: Data,
		sendClassical: MLS.RFC9420.Group, recvClassical: MLS.RFC9420.Group?,
		mineHistory: [Data]
	) throws {
		fatalError("unimplemented")
	}

	/// No window entry is keyed above its group's current epoch, and the PQ
	/// window is empty while there is no send PQ group.
	static func validateWindowEpochs(
		listenRendezvous: some Collection<UInt64>,
		recvHeaderKeys: some Collection<UInt64>,
		recvHeaderKeysPQ: some Collection<UInt64>,
		sendClassicalEpoch: UInt64, sendPQEpoch: UInt64?
	) throws {
		fatalError("unimplemented")
	}
}

@available(iOS 26, macOS 26, *)
extension SessionMigration {
	/// Every leaf of every migrated tree advertises the APQ capabilities, and
	/// every leaf of a bound classical half advertises the AppBinding.
	static func validateMigratedLeafAdverts(
		sendClassical: MLS.RFC9420.Group, sendPQ: MLS.RFC9420.Group?,
		recvClassical: MLS.RFC9420.Group?, recvPQ: MLS.RFC9420.Group?
	) throws {
		fatalError("unimplemented")
	}
}
