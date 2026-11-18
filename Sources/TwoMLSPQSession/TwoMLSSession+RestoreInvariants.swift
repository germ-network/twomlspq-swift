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
		do {
			for group in [sendClassical, sendPQ, recvClassical, recvPQ].compactMap({
				$0
			}) {
				try TwoPartyRules.ensureTwoParty(group)
			}
			try verifyPQHalfUnbound(sendPQ)
			try verifyPQHalfUnbound(recvPQ)
			let sendBinding = try AppBinding.read(
				fromExtensionsOf: sendClassical.context)
			let sendProfile = try SessionProfile.recorded(in: sendClassical.context)
			if let recvClassical {
				guard
					try AppBinding.read(fromExtensionsOf: recvClassical.context)
						== sendBinding,
					try SessionProfile.recorded(in: recvClassical.context)
						== sendProfile
				else { throw TwoMLSError.archiveInvalid }
			}
		} catch {
			throw TwoMLSError.archiveInvalid
		}
	}

	/// Each party's history holds 1...`credentialHistoryWindow` distinct ids,
	/// and no id in one party's history or `authorizedNext` is in the other's.
	static func validateAuthShape(_ auth: AuthCore) throws {
		for party in [auth.mine, auth.theirs] {
			guard
				(1...PartySequence.credentialHistoryWindow).contains(
					party.history.count),
				Set(party.history).count == party.history.count
			else { throw TwoMLSError.archiveInvalid }
		}
		let mine = Set(auth.mine.history).union(auth.mine.authorizedNext)
		let theirs = Set(auth.theirs.history).union(auth.theirs.authorizedNext)
		guard mine.isDisjoint(with: theirs) else { throw TwoMLSError.archiveInvalid }
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
		var shouldOwe = false
		if !initiated && currentStaple.first == Frames.apqWelcomeTag {
			do {
				guard let recvClassical else { throw TwoMLSError.archiveInvalid }
				let sendID = try basicIdentifier(
					Self.ownLeaf(of: sendClassical).credential)
				let recvID = try basicIdentifier(
					Self.ownLeaf(of: recvClassical).credential)
				if let sendIndex = mineHistory.firstIndex(of: sendID) {
					shouldOwe =
						mineHistory.firstIndex(of: recvID).map {
							sendIndex > $0
						} ?? true
				}
			} catch {
				throw TwoMLSError.archiveInvalid
			}
		}
		guard owes == shouldOwe else { throw TwoMLSError.archiveInvalid }
	}

	/// No window entry is keyed above its group's current epoch, and the PQ
	/// window is empty while there is no send PQ group.
	static func validateWindowEpochs(
		listenRendezvous: some Collection<UInt64>,
		recvHeaderKeys: some Collection<UInt64>,
		recvHeaderKeysPQ: some Collection<UInt64>,
		sendClassicalEpoch: UInt64, sendPQEpoch: UInt64?
	) throws {
		guard listenRendezvous.allSatisfy({ $0 <= sendClassicalEpoch }),
			recvHeaderKeys.allSatisfy({ $0 <= sendClassicalEpoch }),
			sendPQEpoch.map({ epoch in recvHeaderKeysPQ.allSatisfy { $0 <= epoch } })
				?? recvHeaderKeysPQ.isEmpty
		else { throw TwoMLSError.archiveInvalid }
	}
}

@available(iOS 26, macOS 26, *)
extension SessionMigration {
	/// Every non-blank leaf of every migrated tree advertises the APQ
	/// capabilities, and every one of a bound classical half advertises the
	/// AppBinding.
	static func validateMigratedLeafAdverts(
		sendClassical: MLS.RFC9420.Group, sendPQ: MLS.RFC9420.Group?,
		recvClassical: MLS.RFC9420.Group?, recvPQ: MLS.RFC9420.Group?
	) throws {
		do {
			let halves: [(group: MLS.RFC9420.Group, isClassical: Bool)] =
				[
					(sendClassical, true), (recvClassical, true),
					(sendPQ, false), (recvPQ, false),
				]
				.compactMap { group, isClassical in group.map { ($0, isClassical) }
				}
			for (group, isClassical) in halves {
				let bound =
					try isClassical
					&& AppBinding.read(fromExtensionsOf: group.context) != nil
				for entry in group.tree.nonBlankLeaves() {
					let leaf = try MLS.RFC9420.LeafNode(
						mlsEncoded: entry.record.encoded)
					try TwoPartyRules.ensureAdvertisesAPQCapabilities(
						leaf, codepoints: .deployed)
					if bound { try ensureAppBindingCreatorLeafAdvert(leaf) }
				}
			}
		} catch {
			throw TwoMLSError.archiveInvalid
		}
	}
}
