import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Slice 9 (PR1): rendezvous routing — `sendRendezvous`/`shouldListenOn`,
/// the `listenRendezvous` capture/retention, and its archive round-trip.
/// Mirrors `FoldTests`' full routine round to drive repeated classical
/// commits (session-lifecycle.md, "Routing").
@available(iOS 26, macOS 26, *)
final class RoutingTests: XCTestCase {
	// MARK: - Helpers

	/// One full offer→approve→commit→catch-up round on the classical group
	/// `approver` commits into (its own send group, which is `proposer`'s
	/// recv group): `proposer` stages a fresh `Upd(self)`, `approver`
	/// approves and folds it (advancing `approver.sendGroup.classical`'s
	/// epoch by exactly one), and `proposer` then applies `approver`'s
	/// commit so both copies stay in sync for a subsequent round. Returns
	/// `approver.sendGroup.classical`'s epoch after the round.
	@discardableResult
	private func fullFoldRound(
		proposer: inout TwoMLSSession, approver: inout TwoMLSSession, round: Int
	) throws -> UInt64 {
		_ = try proposer.prepareToEncrypt()
		let offerFrame = try proposer.encrypt(Data("offer-\(round)".utf8)).frame
		let decrypted = try approver.processIncomingDecrypted(offerFrame)
		_ = try approver.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try approver.prepareToEncrypt()
		let commitFrame = try approver.encrypt(Data("commit-\(round)".utf8)).frame
		_ = try proposer.processIncomingDecrypted(commitFrame)
		return try XCTUnwrap(approver.sendGroup?.classical.context.epoch)
	}

	// MARK: - 1. Both ends derive the same address

	/// `alice.sendRendezvous()` posts to Bob's own listen set (her recv
	/// group IS Bob's send group), and vice versa — session-lifecycle.md's
	/// "Routing" identity, checked both directions right after
	/// establishment (the birth-epoch capture, `recordListenRendezvous`
	/// called from `initiate`/`receive`).
	func testBothEndsDeriveSameRendezvousAddress() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let aliceSend = try XCTUnwrap(alice.sendRendezvous())
		let bobEpoch = try XCTUnwrap(bob.sendGroup?.classical.context.epoch)
		let bobEntry = try XCTUnwrap(
			bob.shouldListenOn().rendezvousByEpoch.first { $0.epoch == bobEpoch })
		XCTAssertEqual(aliceSend, bobEntry.rendezvousId)

		let bobSend = try XCTUnwrap(bob.sendRendezvous())
		let aliceEpoch = try XCTUnwrap(alice.sendGroup?.classical.context.epoch)
		let aliceEntry = try XCTUnwrap(
			alice.shouldListenOn().rendezvousByEpoch.first { $0.epoch == aliceEpoch })
		XCTAssertEqual(bobSend, aliceEntry.rendezvousId)
	}

	// MARK: - 2. Retained window after several commits

	/// After more commits than the retention depth, `shouldListenOn()`
	/// carries exactly the trailing `depth + 1` contiguous epochs — every
	/// epoch below that floor (here the birth epoch and the one after it)
	/// pruned away — mirroring the swift-mls `resumptionPskDepth` knob.
	func testShouldListenOnCoversRetainedClassicalEpochWindowAfterSeveralCommits() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let depth = try XCTUnwrap(alice.sendGroup?.classical.retention.resumptionPskDepth)

		var lastEpoch: UInt64 = 0
		for round in 0..<(depth + 2) {
			lastEpoch = try fullFoldRound(
				proposer: &bob, approver: &alice, round: round)
		}

		let listen = alice.shouldListenOn()
		let epochs = Set(listen.rendezvousByEpoch.map { $0.epoch })
		let expectedFloor = lastEpoch - UInt64(depth)
		XCTAssertEqual(epochs, Set(expectedFloor...lastEpoch))
		XCTAssertEqual(listen.rendezvousByEpoch.count, depth + 1)
	}

	// MARK: - 3. `sendRendezvous` targets the recv group's CURRENT epoch

	/// Alice's recv group is Bob's send group — once Bob's own
	/// `committingRound` moves it, Alice's `sendRendezvous()` moves with
	/// it, to exactly the address Bob's own listen map now carries for
	/// that epoch.
	func testSendRendezvousTracksRecvGroupCurrentEpoch() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let before = try XCTUnwrap(alice.sendRendezvous())

		_ = try fullFoldRound(proposer: &alice, approver: &bob, round: 0)

		let after = try XCTUnwrap(alice.sendRendezvous())
		XCTAssertNotEqual(before, after)

		let bobEpoch = try XCTUnwrap(bob.sendGroup?.classical.context.epoch)
		let bobEntry = try XCTUnwrap(
			bob.shouldListenOn().rendezvousByEpoch.first { $0.epoch == bobEpoch })
		XCTAssertEqual(after, bobEntry.rendezvousId)
	}

	// MARK: - 4. Restore carries the listen map

	/// Archive → seal → open → restore round-trips `listenRendezvous`
	/// (SessionArchive CodingKey 33): the restored session's
	/// `shouldListenOn()` matches the pre-restore live session's exactly.
	func testRestoreCarriesListenRendezvousMap() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		for round in 0..<3 {
			_ = try fullFoldRound(proposer: &bob, approver: &alice, round: round)
		}
		let before = alice.shouldListenOn()
		XCTAssertGreaterThan(before.rendezvousByEpoch.count, 1)

		let key = SecretBytes(randomByteCount: 32)
		let aad = Data("routing-tests".utf8)
		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		let sealed = try archive.seal(with: key, aad: aad)
		let opened = try SecretArchive.open(sealed, with: key, aad: aad)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		XCTAssertEqual(restored.shouldListenOn(), before)
	}
}
