import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import XCTest
import Testing

@testable import TwoMLSPQSession

// Book group-rules.md rule 9 / session-lifecycle.md "Session profiles":
// end-to-end coverage of the correct profile once a host opts in via
// `Principal.advertisesCorrectProfile`, complementing `SessionProfileTests`'s
// unit-shaped C1/C2 cases. The cold-lifecycle and born-dedicated-catch-up
// coverage lives with the tests they parameterize (`LifecycleE2ETests`,
// `BornDedicatedTests`); this file carries the one scenario that needs its
// own fixture: two parties racing a classical rotation each, under the
// correct profile's immediate reciprocal.

@available(iOS 26, macOS 26, *)
final class SessionProfileLifecycleTests: XCTestCase {
	/// The non-self leaf of a 2-member group, decoded — mirrors
	/// `ReciprocalCatchUpConformanceTests`'s own private helper of the same
	/// name/shape.
	private func peerLeaf(in group: MLS.RFC9420.Group) throws -> MLS.RFC9420.LeafNode {
		let entry = try XCTUnwrap(
			group.tree.nonBlankLeaves().first { $0.index != group.myLeafIndex })
		return try MLS.RFC9420.LeafNode(mlsEncoded: entry.record.encoded)
	}

	/// Both parties rotate before either PQ leaf has moved, under the
	/// correct profile. Bob's fold of alice's rotation opens the reciprocal
	/// A.5 at once (C2 off), so bob's own rotation lands while that same-id
	/// Upd′ is in flight and is not re-minted; the round still completes,
	/// and the next two turns' triggers finish the catch-up. Three rounds,
	/// every AD empty, no stall (book session-lifecycle.md: "a race costs
	/// one extra round"). This replaces an earlier, incorrectly-scaffolded
	/// version of this test: its `discardIncidentalSelfDrive`-style reset
	/// only cleared a plain `.initiating` A.4, but under the correct
	/// profile bob's fold-send self-drives the reciprocal A.5 immediately,
	/// so silently discarding that parked round (rather than driving it)
	/// produced a spurious "double-rotation never converges" reading — a
	/// test-construction bug, not an engine defect (confirmed identical
	/// behavior on main with the correct profile forced).
	func testDoubleRotationConvergesWithTheReciprocalOpenedAtOnce() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob(profile: .correct)
		let alice2 = Data("alice-2".utf8), bob2 = Data("bob-2".utf8)

		_ = try alice.prepareToEncrypt(rotating: alice2)
		let aliceOffer = try bob.processIncomingDecrypted(
			try alice.encrypt(Data("a-offer".utf8)).frame)
		_ = try bob.queueProposal(digest: aliceOffer.queuedProposal.digest)
		XCTAssertTrue(try bob.prepareToEncrypt().didCommit)
		let aliceFold = try bob.encrypt(Data("a-fold".utf8)).frame
		guard case .rekeyInitiated = bob.pqInflight else {
			return XCTFail("correct profile: the fold's send opens the reciprocal at once")
		}
		_ = try alice.processIncomingDecrypted(aliceFold)

		_ = try bob.prepareToEncrypt(rotating: bob2)  // lands while the Upd' is in flight
		let bobOffer = try alice.processIncomingDecrypted(
			try bob.encrypt(Data("b-offer".utf8)).frame)
		_ = try alice.queueProposal(digest: bobOffer.queuedProposal.digest)
		XCTAssertTrue(try alice.prepareToEncrypt().didCommit)
		_ = try bob.processIncomingDecrypted(try alice.encrypt(Data("b-fold".utf8)).frame)
		XCTAssertEqual(bob.myPrincipalState, .sync(bob2))

		var rounds: [Data?] = []
		for i in 0..<3 {
			if bob.myPQTurn {
				rounds.append(try driveA5(holder: &bob, peer: &alice, tag: i))
			} else {
				rounds.append(try driveA5(holder: &alice, peer: &bob, tag: i))
			}
		}
		XCTAssertEqual(rounds, [nil, alice2, bob2])
		for (g, own, peer) in [
			(alice.sendGroup?.pq, alice2, bob2), (alice.recvGroup?.pq, alice2, bob2),
			(bob.sendGroup?.pq, bob2, alice2), (bob.recvGroup?.pq, bob2, alice2),
		] {
			let group = try XCTUnwrap(g)
			XCTAssertEqual(try basicIdentifier(TwoMLSSession.ownLeaf(of: group).credential), own)
			XCTAssertEqual(try basicIdentifier(peerLeaf(in: group).credential), peer)
		}
	}

	/// The holder's next send must open an A.5; drive it to the bind.
	/// Returns the responder's `rotatedCredential`; asserts the Upd′
	/// announces nothing (the correct profile's C1).
	private func driveA5(
		holder: inout TwoMLSSession, peer: inout TwoMLSSession, tag: Int
	) throws -> Data? {
		_ = try holder.prepareToEncrypt()
		_ = try peer.processIncomingDecrypted(try holder.encrypt(Data("open-\(tag)".utf8)).frame)
		_ = try peer.prepareToEncrypt()  // fresh evidence for the discharge
		_ = try holder.processIncomingDecrypted(try peer.encrypt(Data("ack-\(tag)".utf8)).frame)
		guard case .rekeyInitiated = holder.pqInflight else {
			XCTFail("expected an A.5")
			return nil
		}
		let upd = try XCTUnwrap(holder.pqPendingOutbound())
		let updBytes = try Frames.decodePQRekeyUpd(peer.openOrRaw(upd))
		guard case .publicMessage(let pub) = try MLS.RFC9420.Message(mlsEncoded: updBytes) else {
			XCTFail("expected a publicMessage Upd'")
			return nil
		}
		XCTAssertEqual(pub.content.authenticatedData, Data())
		let response = try peer.pqRekeyRespond(upd)
		_ = try holder.pqRekeyApply(response.frame)
		XCTAssertTrue(try holder.prepareToEncrypt().didCommit)
		_ = try peer.processIncomingDecrypted(try holder.encrypt(Data("bound-\(tag)".utf8)).frame)
		return response.rotatedCredential
	}
}
