import Foundation
import MLSCodec
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// §A.3 parallel pre-delivery (book protocol-flows.md §A.1 "Envelope
/// framing & parallel KP′ delivery", §A.3 "Parallel pre-delivery") and the
/// acceptor's re-serve rule.
@available(iOS 26, macOS 26, *)
final class ParallelBootstrapTests: XCTestCase {
	private typealias Support = SessionTestSupport

	private func initiateAgainstInvitation(lastResort: Bool = false) throws -> (
		initiated: EstablishResult, invitation: Invitation
	) {
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8), classicalProvider: Support.classicalProvider,
			pqProvider: Support.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8), classicalProvider: Support.classicalProvider,
			pqProvider: Support.pqProvider)
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: lastResort)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal,
			their: try XCTUnwrap(invitation.combinerKeyPackage))
		return (initiated, invitation)
	}

	private func receive(
		_ initiated: EstablishResult, into invitation: inout Invitation
	) throws -> TwoMLSSession {
		try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: Support.classicalProvider.randomBytes(16)
		).session
	}

	func testInitiateRegistersTheRoundAroundTheCommittedKP() throws {
		let (initiated, invitation) = try initiateAgainstInvitation()
		let alice = initiated.session
		guard case .bootstrapInitiated = alice.pqInflight else {
			return XCTFail("expected .bootstrapInitiated at initiate")
		}
		let kp = try XCTUnwrap(alice.bootstrapKPBytes())
		XCTAssertEqual(alice.pendingSideBand, Frames.encodePQBootstrapKP(kp))
		XCTAssertEqual(
			try Support.classicalProvider.hash(kp), try alice.bootstrapKPCommitment())

		guard
			case .bootstrapKP(let beforeRestartFrame) = try invitation.openInitial(
				try XCTUnwrap(alice.pqBootstrapEnvelope()))
		else { return XCTFail("expected .bootstrapKP") }

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: initiated.baseline.archive,
			classicalProvider: Support.classicalProvider, pqProvider: Support.pqProvider
		)
		guard case .bootstrapInitiated = restored.pqInflight else {
			return XCTFail("expected the registered round to ride the baseline")
		}
		XCTAssertEqual(restored.pendingSideBand, alice.pendingSideBand)

		// The restored pre-join initiator can still ship the parked KP′ —
		// it opens (with the acceptor's own invitation opener) to the same
		// `[0x13][KP′]` frame it produced before the restart.
		guard
			case .bootstrapKP(let afterRestoreFrame) = try invitation.openInitial(
				try XCTUnwrap(restored.pqBootstrapEnvelope()))
		else { return XCTFail("expected .bootstrapKP") }
		XCTAssertEqual(afterRestoreFrame, beforeRestartFrame)
	}

	func testEnvelopeIsAPureFreshlySealedReadOfTheRetainedFrame() throws {
		var (initiated, invitation) = try initiateAgainstInvitation()
		let alice = initiated.session
		let seqBefore = alice.stateSeq
		let first = try XCTUnwrap(alice.pqBootstrapEnvelope())
		let second = try XCTUnwrap(alice.pqBootstrapEnvelope())
		XCTAssertNotEqual(first, second)
		XCTAssertEqual(alice.stateSeq, seqBefore)
		for blob in [first, second] {
			guard case .bootstrapKP(let frame) = try invitation.openInitial(blob) else {
				return XCTFail("expected .bootstrapKP")
			}
			XCTAssertEqual(frame, alice.pendingSideBand)
		}
		// The reply and the KP′ share one outer shape; only the inner tag
		// tells them apart.
		guard case .establishment = try invitation.openInitial(try alice.pendingOutbound())
		else { return XCTFail("expected .establishment") }

		var bob = try receive(initiated, into: &invitation)
		XCTAssertNil(bob.pqBootstrapEnvelope())
		_ = try bob.prepareToEncrypt()
		_ = bob
	}

	func testEnvelopeStopsAtTheCutoverAndTheSideBandTakesOver() throws {
		var (initiated, invitation) = try initiateAgainstInvitation()
		var alice = initiated.session
		var bob = try receive(initiated, into: &invitation)
		XCTAssertNil(alice.pqPendingOutbound())
		_ = try bob.prepareToEncrypt()
		_ = try alice.processIncomingDecrypted(try bob.encrypt(Data("b1".utf8)).frame)

		XCTAssertNil(alice.pqBootstrapEnvelope())
		let steady = try XCTUnwrap(alice.pqPendingOutbound())
		XCTAssertEqual(bob.openOrRaw(steady), alice.pendingSideBand)
		let begun = try alice.pqBootstrapBegin()
		XCTAssertEqual(bob.openOrRaw(begun.frame), alice.pendingSideBand)
		XCTAssertEqual(begun.update.kind, .core)
	}

	func testEarlyWelcomeIsRetriableUntilTheGroupBJoin() throws {
		var (initiated, invitation) = try initiateAgainstInvitation()
		var alice = initiated.session
		guard
			case .bootstrapKP(let held) = try invitation.openInitial(
				try XCTUnwrap(alice.pqBootstrapEnvelope()))
		else { return XCTFail("expected .bootstrapKP") }
		var bob = try receive(initiated, into: &invitation)
		XCTAssertEqual(
			invitation.bootstrapKPGroupID(kpFrame: held),
			bob.recvGroup?.classical.context.groupID)

		let welcome = try bob.pqBootstrapRespond(held)
		XCTAssertEqual(welcome.update.kind, .checkpoint)

		// Opens under alice's own Group_A.pq window, but there is nothing to
		// join into yet.
		let opened = try XCTUnwrap(alice.openIncoming(welcome.frame))
		XCTAssertEqual(opened.kind, .pqSideBand(.bootstrapWelcome))
		let seqBefore = alice.stateSeq
		XCTAssertThrowsError(try alice.pqBootstrapJoin(opened.frame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
		XCTAssertEqual(alice.stateSeq, seqBefore)
		XCTAssertNotNil(alice.bootstrapKPSecret)

		_ = try bob.prepareToEncrypt()
		_ = try alice.processIncomingDecrypted(try bob.encrypt(Data("b1".utf8)).frame)
		_ = try alice.pqBootstrapJoin(opened.frame)
		XCTAssertTrue(alice.isFullyEstablished)
		XCTAssertTrue(bob.isFullyEstablished)

		_ = try alice.prepareToEncrypt()
		let bound = try alice.encrypt(Data("a1".utf8))
		XCTAssertNil(alice.owedBind)
		let applied = try bob.processIncomingDecrypted(bound.frame)
		XCTAssertTrue(applied.didApplyRemoteCommit)
		XCTAssertTrue(bob.myPQTurn)
	}

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
