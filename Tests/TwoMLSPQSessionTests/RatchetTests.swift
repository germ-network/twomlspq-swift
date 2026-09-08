import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// §A.4: the lightweight ML-KEM EK/CT ratchet, self-driven off `pqTurnMine`
/// and reusing slice 2's bind. After the §A.3 bootstrap completes, the turn
/// is Bob's (`BootstrapTests` asserts `bob.myPQTurn`), so round 1 here is
/// **Bob-initiated**, ratcheting Group_B.pq (`bob.sendGroup.pq` /
/// `alice.recvGroup.pq`) 1 -> 2 — not Group_A.pq, which the A.3 bind already
/// moved.
@available(iOS 26, macOS 26, *)
final class RatchetTests: XCTestCase {
	private func rawBytes(_ secret: SecretBytes) -> Data { secret.withUnsafeBytes { Data($0) } }

	/// `SessionTestSupport.establishedAndExchanged()` plus the full §A.3
	/// bootstrap-and-bind round (mirroring `BootstrapTests`'s own sequence),
	/// landing on a fully-established pair with the turn on Bob.
	private func fullyEstablishedTurnOnBob() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession
	) {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8))
		_ = try bob.processIncoming(boundFrame)

		XCTAssertTrue(bob.myPQTurn)
		XCTAssertFalse(alice.myPQTurn)
		return (alice, bob)
	}

	// MARK: - The full Bob-initiated round

	/// The full A.4 round: Bob self-stages an EK, Alice responds with a CT
	/// (holding `S`), Bob binds (owing the PQ commit into Group_B.pq), Bob
	/// discharges (licensed by Alice's earlier inbound frame), and Alice
	/// applies the bind — landing Group_B.pq at epoch 2 on both sides and
	/// passing the turn back to Alice.
	func testBobInitiatedRatchetRoundAdvancesGroupBPQAndReturnsTurn() throws {
		var (alice, bob) = try fullyEstablishedTurnOnBob()

		XCTAssertEqual(bob.sendGroup?.pq?.context.epoch, 1)
		XCTAssertEqual(alice.recvGroup?.pq?.context.epoch, 1)

		// 1: Bob self-stages an EK.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let (ekTag, _) = try Frames.decodePQLeg(ekFrame)
		XCTAssertEqual(ekTag, Frames.pqEKTag)
		guard case .initiating = bob.pqInflight else {
			XCTFail("expected bob to hold `.initiating` after self-staging")
			return
		}

		// 2: Alice responds with a CT, holding `S`.
		let ctFrame = try alice.pqRatchetRespond(ekFrame)
		let (ctTag, _) = try Frames.decodePQLeg(ctFrame)
		XCTAssertEqual(ctTag, Frames.pqCTTag)
		XCTAssertEqual(alice.pqPendingOutbound(), ctFrame)
		guard case .responding = alice.pqInflight else {
			XCTFail("expected alice to hold `.responding` after sealing")
			return
		}

		// 3: Bob binds — owes the PQ commit into Group_B.pq, immediately
		// applied to his own local copy.
		try bob.pqRatchetBind(ctFrame)
		XCTAssertNotNil(bob.owedBind)
		XCTAssertNil(bob.pqPendingOutbound())
		XCTAssertEqual(bob.sendGroup?.pq?.context.epoch, 2)

		// 4: Bob discharges (already licensed by Alice's earlier "bound"
		// frame, per §11 #8) and Alice applies the `0x05` staple.
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8))

		let decrypted = try alice.processIncoming(boundFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))

		XCTAssertTrue(alice.myPQTurn)
		XCTAssertEqual(bob.sendGroup?.pq?.context.epoch, 2)
		XCTAssertEqual(alice.recvGroup?.pq?.context.epoch, 2)
		// Group_B.classical starts at epoch 1 (its founding create-commit) and
		// the discharge is its first commit since — 1 -> 2, mirroring the A.3
		// bind's own epoch step on Group_A.classical (§11 #10).
		XCTAssertEqual(bob.sendGroup?.classical.context.epoch, 2)
		XCTAssertEqual(alice.recvGroup?.classical.context.epoch, 2)
	}

	// MARK: - Mutation-verify

	/// The exporter both sides derive off Group_B.pq's shared epoch state
	/// (Bob's own copy, Alice's mirror) must agree — the whole seal/open
	/// exchange depends on it.
	func testCrossPartyCtSealPSKMatchesOnGroupBPQMirror() throws {
		let (alice, bob) = try fullyEstablishedTurnOnBob()

		let bobPSK = try CTSeal.ctSealPSK(
			group: try XCTUnwrap(bob.sendGroup?.pq),
			pqProvider: SessionTestSupport.pqProvider)
		let alicePSK = try CTSeal.ctSealPSK(
			group: try XCTUnwrap(alice.recvGroup?.pq),
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(rawBytes(bobPSK), rawBytes(alicePSK))
	}

	/// A wire-tampered CT leg is rejected as the non-fatal `.decryptionFailed`
	/// and burns no durable state: Bob keeps his `.initiating` ephemeral and
	/// the genuine CT still binds afterward. Note the MLS layer authenticates
	/// the whole leg, so a byte-flip is caught at `unprotect` (remapped to
	/// `.decryptionFailed`) before it can reach `CTSeal.open` — the CT-seal's
	/// OWN explicit reject, for a mis-sealed / wrong-`ctSealPSK` CT that only a
	/// validly-framing responder could produce, is pinned in `CTSealTests`.
	func testWireTamperedCTIsRejectedAndDoesNotBurnState() throws {
		var (alice, bob) = try fullyEstablishedTurnOnBob()

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame)

		var tampered = ctFrame
		tampered[tampered.index(before: tampered.endIndex)] ^= 0xFF

		XCTAssertThrowsError(try bob.pqRatchetBind(tampered)) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
		XCTAssertNil(bob.owedBind)
		XCTAssertEqual(bob.sendGroup?.pq?.context.epoch, 1)
		guard case .initiating = bob.pqInflight else {
			XCTFail("expected bob to still hold `.initiating` after a rejected bind")
			return
		}

		// The genuine CT still binds cleanly afterward.
		try bob.pqRatchetBind(ctFrame)
		XCTAssertNotNil(bob.owedBind)
		XCTAssertEqual(bob.sendGroup?.pq?.context.epoch, 2)
	}

	/// An EK leg framed at an epoch strictly below the responder's live
	/// classical epoch is rejected by the floor, not processed — a replay
	/// of Bob's ROUND-1 EK after the round's own bind has advanced Group_B's
	/// classical epoch.
	func testReplayedEKBelowEpochFloorThrowsStaleFrame() throws {
		var (alice, bob) = try fullyEstablishedTurnOnBob()

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let staleEKFrame = try XCTUnwrap(bob.pqPendingOutbound())

		let ctFrame = try alice.pqRatchetRespond(staleEKFrame)
		try bob.pqRatchetBind(ctFrame)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8))
		_ = try alice.processIncoming(boundFrame)

		// Group_B's classical epoch (alice's mirror) has now advanced past
		// the epoch `staleEKFrame` was framed at.
		XCTAssertThrowsError(try alice.pqRatchetRespond(staleEKFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .staleFrame)
		}
	}

	/// The self-drive gate: `encrypt` stages no new EK when it isn't my
	/// turn, and does not overwrite an already-parked side-band leg when it
	/// is.
	func testSelfDriveGateSkipsWhenNotMyTurnOrSideBandBusy() throws {
		var (alice, bob) = try fullyEstablishedTurnOnBob()

		// Not alice's turn: her own send path must not self-stage an EK.
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("alice-not-turn".utf8))
		XCTAssertNil(alice.pqPendingOutbound())

		// Bob's turn, but a side-band leg is already parked: a further
		// `encrypt` must not stage a second round on top of it.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let firstEK = try XCTUnwrap(bob.pqPendingOutbound())

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m2".utf8))
		XCTAssertEqual(bob.pqPendingOutbound(), firstEK)
	}
}
