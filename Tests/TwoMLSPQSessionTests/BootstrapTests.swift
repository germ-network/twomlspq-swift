import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// §A.3: KP′ exchange + Bob founds Group_B.pq + Alice joins (chunk A), then
/// the bind — Alice's owed PQ commit discharged against a licensed classical
/// commit, stapled `0x05`, turn returned to Bob (chunk B).
@available(iOS 26, macOS 26, *)
final class BootstrapTests: XCTestCase {
	func testFullBootstrapRoundReachesFullyEstablished() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertTrue(alice.myPQTurn)
		XCTAssertFalse(bob.myPQTurn)
		XCTAssertFalse(alice.isFullyEstablished)
		XCTAssertFalse(bob.isFullyEstablished)

		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		XCTAssertTrue(bob.isFullyEstablished)
		XCTAssertFalse(alice.isFullyEstablished)

		try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(alice.isFullyEstablished)
	}

	/// The joined Group_B.pq's mirror `APQInfo` and epoch land where §3
	/// specifies: `pqEpoch == 1`, `tEpoch` unbound, and both rosters are 2.
	func testJoinedPQHalfHasMirrorAPQInfoAndEpochOne() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		let alicePQ = try XCTUnwrap(alice.recvGroup?.pq)
		let bobPQ = try XCTUnwrap(bob.sendGroup?.pq)
		XCTAssertEqual(alicePQ.context.epoch, 1)
		XCTAssertEqual(bobPQ.context.epoch, 1)
		XCTAssertEqual(alicePQ.tree.nonBlankLeaves().count, 2)
		XCTAssertEqual(bobPQ.tree.nonBlankLeaves().count, 2)

		let info = try XCTUnwrap(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: alicePQ.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))
		XCTAssertEqual(info.tEpoch, epochUnbound)
		XCTAssertEqual(info.pqEpoch, 1)
		XCTAssertEqual(info.pqSessionGroupID, alicePQ.context.groupID)
	}

	// MARK: - Negatives

	func testReceiveRejectsNonThirtyTwoByteCommitment() throws {
		let alice = try SessionTestSupport.identity("alice")
		let bob = try SessionTestSupport.identity("bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: Data([1, 2, 3]),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .bootstrapKPMismatch)
		}
	}

	func testRespondRejectsWrongCommitment() throws {
		let alice = try SessionTestSupport.identity("alice")
		let bob = try SessionTestSupport.identity("bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		// A commitment of the right length but the wrong value.
		let wrongCommitment = Data(repeating: 0xAB, count: 32)
		let received = try TwoMLSSession.receive(
			identity: bob, welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.keyPackage.classical,
			bootstrapKPCommitment: wrongCommitment,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		var (aliceSession, bobSession) = (initiated.session, received.session)
		_ = try bobSession.prepareToEncrypt()
		let frame = try bobSession.encrypt(Data("bob-hello".utf8))
		_ = try aliceSession.processIncoming(frame)

		let kpFrame = try aliceSession.pqBootstrapBegin()
		XCTAssertThrowsError(try bobSession.pqBootstrapRespond(kpFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .bootstrapKPMismatch)
		}
	}

	func testBeginRejectsWhenNotMyTurn() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertThrowsError(try bob.pqBootstrapBegin()) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
	}

	// MARK: - Chunk B: the bind

	/// The full A.3 round: KP′ exchange, the bind's discharge (licensed by
	/// Bob's establishment-time frame, per §11 #8), and the turn returning to
	/// Bob. Asserts the exact epoch positions §11 #10 calls out: only
	/// Group_A.pq (ASG-PQ) moves 1 -> 2; Group_B's halves stay where the
	/// bootstrap left them.
	func testFullBootstrapRoundBindsAndReturnsTurn() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		XCTAssertTrue(bob.isFullyEstablished)

		try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(alice.isFullyEstablished)
		XCTAssertNotNil(alice.owedBind)

		// Bob's establishment-time frame already licensed Alice (§11 #8), so
		// the very next `prepareToEncrypt` discharges immediately.
		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		XCTAssertNil(alice.owedBind)
		let frame = try alice.encrypt(Data("bound".utf8))

		let (staple, _, _) = try Frames.decodeMessageFrame(frame)
		XCTAssertEqual(Frames.stapleKind(staple.first!), .apqPrivateMessage)

		let decrypted = try bob.processIncoming(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
		XCTAssertTrue(bob.myPQTurn)

		let alicePQEpoch = try XCTUnwrap(alice.sendGroup?.pq?.context.epoch)
		let bobRecvPQEpoch = try XCTUnwrap(bob.recvGroup?.pq?.context.epoch)
		let aliceClassicalEpoch = try XCTUnwrap(alice.sendGroup?.classical.context.epoch)
		let bobRecvClassicalEpoch = try XCTUnwrap(bob.recvGroup?.classical.context.epoch)
		let bobSendPQEpoch = try XCTUnwrap(bob.sendGroup?.pq?.context.epoch)
		let aliceRecvPQEpoch = try XCTUnwrap(alice.recvGroup?.pq?.context.epoch)
		XCTAssertEqual(alicePQEpoch, 2)
		XCTAssertEqual(bobRecvPQEpoch, 2)
		XCTAssertEqual(aliceClassicalEpoch, 2)
		XCTAssertEqual(bobRecvClassicalEpoch, 2)
		XCTAssertEqual(bobSendPQEpoch, 1)
		XCTAssertEqual(aliceRecvPQEpoch, 1)
	}

	/// §11 #2: the `0x05` staple re-rides every Alice→Bob frame until her next
	/// commit. A second frame after the bind must decrypt without re-applying
	/// (no throw, no double epoch-advance, no re-consuming the spent PSKs).
	func testSecondFrameAfterBindIsIdempotent() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8))
		_ = try bob.processIncoming(boundFrame)

		let secondPrepared = try alice.prepareToEncrypt()
		XCTAssertFalse(secondPrepared.didCommit)
		let secondFrame = try alice.encrypt(Data("again".utf8))

		let decrypted = try bob.processIncoming(secondFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("again".utf8))

		let bobRecvPQEpoch = try XCTUnwrap(bob.recvGroup?.pq?.context.epoch)
		let bobRecvClassicalEpoch = try XCTUnwrap(bob.recvGroup?.classical.context.epoch)
		XCTAssertEqual(bobRecvPQEpoch, 2)
		XCTAssertEqual(bobRecvClassicalEpoch, 2)
	}

	// MARK: - Chunk B negatives

	/// Discharge attempted before the license: `owedBind` stays parked and the
	/// staple is not re-stapled `0x05` until Bob's inbound Upd has evidenced
	/// applying Alice's current send epoch.
	func testDischargeWithoutLicenseDoesNotCommit() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertNotNil(alice.owedBind)

		// Simulate Bob's licensing Upd never having arrived.
		alice.peerAppliedSendEpoch = nil

		let prepared = try alice.prepareToEncrypt()
		XCTAssertFalse(prepared.didCommit)
		XCTAssertNotNil(alice.owedBind)

		let frame = try alice.encrypt(Data("still-owed".utf8))
		let (staple, _, _) = try Frames.decodeMessageFrame(frame)
		XCTAssertNotEqual(Frames.stapleKind(staple.first!), .apqPrivateMessage)
	}

	/// `dischargeOwedBindIfLicensed`'s own re-check catches an `owedBind`
	/// whose parked epochs no longer match the live send groups, before ever
	/// building a wire commit — the guard `verifyFullCommitAttestation`
	/// backstops on the receive side (§11 #9's attestation check is the
	/// combiner's; this is the discharge-side belt).
	func testTamperedOwedBindEpochThrowsEpochDesync() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		alice.owedBind?.pqEpoch += 1

		XCTAssertThrowsError(try alice.prepareToEncrypt()) { error in
			XCTAssertEqual(error as? TwoMLSError, .epochDesync)
		}
	}

	/// A bit-flip inside the `0x05` staple's PQ commit section breaks its
	/// framing signature — `applyBind` must reject it, not silently apply a
	/// forged commit or burn the single-shot cross-party PSK leaf.
	func testCorruptedBindStapleIsRejected() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)
		_ = try alice.prepareToEncrypt()
		let frame = try alice.encrypt(Data("bound".utf8))

		let (staple, proposal, app) = try Frames.decodeMessageFrame(frame)
		let (t, pq) = try Frames.decodeAPQPrivateMessage(staple)
		var corruptedPQ = pq
		corruptedPQ[corruptedPQ.count / 2] ^= 0xFF
		let corruptedStaple = Frames.encodeAPQPrivateMessage(t: t, pq: corruptedPQ)
		let corruptedFrame = Frames.encodeMessageFrame(
			staple: corruptedStaple, proposal: proposal, app: app)

		XCTAssertThrowsError(try bob.processIncoming(corruptedFrame))
	}
}
