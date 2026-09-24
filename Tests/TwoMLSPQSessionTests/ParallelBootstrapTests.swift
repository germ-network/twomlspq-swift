import Foundation
import MLSCodec
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// The acceptor's §A.3 re-serve rule: a validated KP′ re-serves only while
/// its own round is open (book protocol-flows.md §A.3).
@available(iOS 26, macOS 26, *)
final class ParallelBootstrapTests: XCTestCase {
	private typealias Support = SessionTestSupport

	func testRespondReServesOnlyWhileItsRoundIsOpen() throws {
		var (alice, bob) = try Support.establishedAndExchanged()
		let kp = try alice.pqBootstrapBegin().frame
		let first = try bob.pqBootstrapRespond(kp)

		// Round open: the SAME Welcome′ again.
		let again = try bob.pqBootstrapRespond(kp)
		XCTAssertEqual(alice.openOrRaw(first.frame), alice.openOrRaw(again.frame))
		XCTAssertEqual(first.update.kind, .checkpoint)
		XCTAssertEqual(again.update.kind, .core)

		// Garbage or a wrong KP′ never earns a re-serve.
		let seq = bob.stateSeq
		XCTAssertThrowsError(try bob.pqBootstrapRespond(Data([0x42, 0x01])))
		XCTAssertThrowsError(
			try bob.pqBootstrapRespond(Frames.encodePQBootstrapKP(Data("other".utf8)))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .bootstrapKPMismatch)
		}
		XCTAssertEqual(bob.stateSeq, seq)

		_ = try alice.pqBootstrapJoin(first.frame)
		_ = try alice.prepareToEncrypt()
		_ = try bob.processIncomingDecrypted(try alice.encrypt(Data("bind".utf8)).frame)
		XCTAssertNil(bob.pqInflight)

		// Round closed: refused, with nothing moved.
		let closedSeq = bob.stateSeq
		XCTAssertThrowsError(try bob.pqBootstrapRespond(kp)) { error in
			XCTAssertEqual(error as? TwoMLSError, .duplicateSideBand)
		}
		XCTAssertEqual(bob.stateSeq, closedSeq)

		// The next round opened on bob's send: still refused, and the parked
		// leg is not handed out as if it answered the KP′.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("b2".utf8))
		let parked = try XCTUnwrap(bob.pendingSideBand)
		XCTAssertThrowsError(try bob.pqBootstrapRespond(kp)) { error in
			XCTAssertEqual(error as? TwoMLSError, .duplicateSideBand)
		}
		XCTAssertEqual(bob.pendingSideBand, parked)
	}

	/// An initiator handed her own reflected KP′ (her founded send-PQ half
	/// used to route this into the re-serve branch, handing back her own
	/// `0x13`) — she is never a responder, so the commitment check always
	/// fails closed instead.
	func testInitiatorRefusesItsOwnReflectedKP() throws {
		var (alice, bob) = try Support.establishedAndExchanged()
		_ = try alice.pqBootstrapBegin()
		let ownFrame = try XCTUnwrap(alice.pendingSideBand)
		let pendingBefore = alice.pendingSideBand
		let seqBefore = alice.stateSeq

		XCTAssertThrowsError(try alice.pqBootstrapRespond(ownFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .bootstrapKPMismatch)
		}
		XCTAssertEqual(alice.pendingSideBand, pendingBefore)
		XCTAssertEqual(alice.stateSeq, seqBefore)
		_ = bob
	}
}
