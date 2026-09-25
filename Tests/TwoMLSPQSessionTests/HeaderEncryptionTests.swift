import Foundation
import SecretBytes
import XCTest
import Testing

@testable import TwoMLSPQSession

/// Header encryption — every outbound blob is one opaque
/// `SealedFrame`; the receiver trial-decrypts over its own windows (book
/// header-encryption.md, "Design"/"Send rule"/"Receive rule"). Every other
/// suite in this module now drives its A.3/A.4/A.5 rounds and message
/// traffic THROUGH the real sealed wire (seal/open are wired into
/// `encrypt`/`processIncoming`/the `pq*` entry points directly, not as an
/// opt-in), so this file covers the header-encryption-specific properties
/// those suites don't otherwise pin: no plaintext framing, fail-closed
/// tampering, window retention/eviction, side-band classification, the
/// pre-A.3 classical fallback, and the archive round-trip of both windows.
@available(iOS 26, macOS 26, *)
final class HeaderEncryptionTests: XCTestCase {
	// MARK: - Helpers

	/// One full offer→approve→commit round, mirroring `RoutingTests`' own
	/// helper: `proposer` stages+sends an `Upd(self)`, `approver` approves
	/// and folds it — advancing `approver.sendGroup.classical`'s epoch by
	/// exactly one.
	private func fullFoldRound(
		proposer: inout TwoMLSSession, approver: inout TwoMLSSession, round: Int = 0
	) throws {
		_ = try proposer.prepareToEncrypt()
		let offerFrame = try proposer.encrypt(Data("offer-\(round)".utf8)).frame
		let decrypted = try approver.processIncomingDecrypted(offerFrame)
		_ = try approver.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try approver.prepareToEncrypt()
		let commitFrame = try approver.encrypt(Data("commit-\(round)".utf8)).frame
		_ = try proposer.processIncomingDecrypted(commitFrame)
	}

	private let testKey = SecretBytes(randomByteCount: 32)
	private let testAAD = Data("header-encryption-tests".utf8)

	private func sealAndOpen(_ archive: SecretArchive) throws -> SecretArchive {
		let sealed = try archive.seal(with: testKey, aad: testAAD)
		return try SecretArchive.open(sealed, with: testKey, aad: testAAD)
	}

	// MARK: - 1. No plaintext framing

	/// A sealed `0x03` message frame does not start with the frame tag, and
	/// the plaintext application payload appears nowhere in its bytes — the
	/// blob is opaque. `openIncoming` recovers the plaintext frame and
	/// classifies it `.message`.
	func testSealedFrameCarriesNoPlaintextFramingAndOpensAsMessage() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try alice.prepareToEncrypt()
		let plaintext = Data("the-quick-brown-fox-0xDEADBEEF".utf8)
		let frame = try alice.encrypt(plaintext).frame

		XCTAssertNotEqual(frame.first, Frames.messageFrameTag)
		XCTAssertNil(frame.range(of: plaintext))

		let opened = try XCTUnwrap(bob.openIncoming(frame))
		XCTAssertEqual(opened.kind, .message)
		XCTAssertEqual(opened.frame.first, Frames.messageFrameTag)
	}

	// MARK: - 2. Fail-closed tampering

	/// A bit flipped in the leading nonce bytes fails every window key —
	/// `tryOpen` returns `nil`, not a decode of garbage.
	func testTamperedNonceFailsToOpen() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try alice.prepareToEncrypt()
		var frame = try alice.encrypt(Data("hello".utf8)).frame
		frame[frame.startIndex] ^= 0xFF
		XCTAssertNil(bob.tryOpen(frame))
	}

	/// A bit flipped in the trailing AEAD tag bytes fails every window key.
	func testTamperedCiphertextFailsToOpen() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try alice.prepareToEncrypt()
		var frame = try alice.encrypt(Data("hello".utf8)).frame
		frame[frame.index(before: frame.endIndex)] ^= 0xFF
		XCTAssertNil(bob.tryOpen(frame))
	}

	// MARK: - 3. Cross-commit-in-flight

	/// A frame sealed under send-group epoch N still opens via the retained
	/// N entry after the sender's peer advances the group to N+1 — the same
	/// reasoning as `sendCrossPSKLedger`, and the reason the window must be
	/// ≥ 2 even in the happy path (book, "Receive rule").
	func testCrossCommitInFlightOpensViaOlderWindowEntry() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try bob.prepareToEncrypt()
		let staleFrame = try bob.encrypt(Data("stale".utf8)).frame

		// Advances Group_A (alice's send group, the group `staleFrame` was
		// sealed against) by exactly one epoch.
		try fullFoldRound(proposer: &bob, approver: &alice)

		let opened = try XCTUnwrap(alice.tryOpen(staleFrame))
		XCTAssertEqual(opened.first, Frames.messageFrameTag)
	}

	// MARK: - 4. Wrong-epoch-outside-window

	/// Once a frame's sealing epoch has aged out of the retention window
	/// (`resumptionPskDepth` behind the current epoch), it no longer opens —
	/// indistinguishable from garbage, by construction.
	func testWrongEpochOutsideWindowReturnsNil() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let depth = try XCTUnwrap(alice.sendGroup?.classical.retention.resumptionPskDepth)

		_ = try bob.prepareToEncrypt()
		let staleFrame = try bob.encrypt(Data("stale".utf8)).frame

		for round in 0..<(depth + 2) {
			try fullFoldRound(proposer: &bob, approver: &alice, round: round)
		}

		XCTAssertNil(alice.tryOpen(staleFrame))
	}

	// MARK: - 5. Side-band classification, full A.3/A.4/A.5 through sealed frames

	/// Drives the complete §A.3 bootstrap, §A.4 ratchet, and §A.5 mechanical
	/// re-key rounds — every side-band frame here is the REAL sealed wire
	/// output (seal/open are wired into the production entry points, not
	/// opt-in) — and pins `openIncoming`'s classification of each of the six
	/// `PqFrameKind`s in turn.
	func testOpenIncomingClassifiesEachSideBandKindAcrossA3A4A5() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		// §A.3: `0x13` (classical fallback — alice's recv-PQ, Group_B.pq,
		// isn't founded until this very bootstrap) then `0x15` (PQ family:
		// bob's recv-PQ, Group_A.pq, already exists from `receive`'s
		// `APQGroup.joinFull` at establishment — not "doesn't exist until
		// Alice's later join" — so the welcome reply seals under
		// `HeaderKeyPQ`, not the classical fallback).
		let kpFrame = try alice.pqBootstrapBegin().frame
		let openedKP = try XCTUnwrap(bob.openIncoming(kpFrame))
		XCTAssertEqual(openedKP.kind, .pqSideBand(.bootstrapKP))

		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		let openedWelcome = try XCTUnwrap(alice.openIncoming(welcomeFrame))
		XCTAssertEqual(openedWelcome.kind, .pqSideBand(.bootstrapWelcome))
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		let bindPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(bindPrepared.didCommit)
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(bob.myPQTurn)

		// §A.4: bob (turn-holder) self-stages an EK (`0x17`); alice responds
		// with the CT (`0x19`).
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let openedEK = try XCTUnwrap(alice.openIncoming(ekFrame))
		XCTAssertEqual(openedEK.kind, .pqSideBand(.ratchetEK))

		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		let openedCT = try XCTUnwrap(bob.openIncoming(ctFrame))
		XCTAssertEqual(openedCT.kind, .pqSideBand(.ratchetCT))
		_ = try bob.pqRatchetBind(ctFrame)

		let ratchetDischarge = try bob.prepareToEncrypt()
		XCTAssertTrue(ratchetDischarge.didCommit)
		let ratchetBoundFrame = try bob.encrypt(Data("ratchet-bound".utf8)).frame
		_ = try alice.processIncomingDecrypted(ratchetBoundFrame)
		XCTAssertTrue(alice.myPQTurn)

		// §A.5: alice (turn-holder) proposes Upd′ (`0x1B`); bob commits
		// (`0x1D`).
		let updFrame = try alice.pqRekeyBegin().frame
		let openedUpd = try XCTUnwrap(bob.openIncoming(updFrame))
		XCTAssertEqual(openedUpd.kind, .pqSideBand(.rekeyUpd))

		let commitFrame = try bob.pqRekeyRespond(updFrame).frame
		let openedCommit = try XCTUnwrap(alice.openIncoming(commitFrame))
		XCTAssertEqual(openedCommit.kind, .pqSideBand(.rekeyCommit))
		_ = try alice.pqRekeyApply(commitFrame)
	}

	// MARK: - 6. Pre-A.3 classical fallback

	/// The initiator's `BOOTSTRAP_KP` (`0x13`) opens via the CLASSICAL
	/// window, never the PQ one — the responder's PQ window is genuinely
	/// empty at this point (his send-PQ half doesn't exist until his own
	/// `pqBootstrapRespond`), so a successful open here could only have come
	/// from the classical fallback.
	func testPreA3BootstrapKPOpensViaClassicalFallbackWindow() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertNil(alice.recvGroup?.pq)

		let kpFrame = try alice.pqBootstrapBegin().frame
		XCTAssertTrue(bob.recvHeaderKeysPQ.isEmpty)

		let opened = try XCTUnwrap(bob.tryOpen(kpFrame))
		XCTAssertEqual(opened.first, Frames.pqBootstrapKPTag)
	}

	// MARK: - 7. Restore carries both windows

	/// A restored session opens BOTH an in-flight message-path frame
	/// (classical family) and an in-flight §A.5 side-band frame (PQ family)
	/// sealed after the archived snapshot but under windows the snapshot
	/// already carries — restore is itself a construction site for both
	/// windows (`recordListenRendezvous`/`recordPQHeaderKey`).
	func testRestoreCarriesBothHeaderKeyWindowsAndOpensInFlightFrames() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		let checkpoint = try sealAndOpen(archive)

		// In flight after the snapshot, both sealed under windows the
		// checkpoint above already carries (alice's send-group/-PQ epochs
		// haven't moved since). `pqRekeyBegin` first, so `encrypt`'s
		// self-drive (`maybeStageNextRound`) sees `pendingSideBand` already
		// occupied and no-ops rather than staging a competing A.4 leg.
		let updFrame = try bob.pqRekeyBegin().frame
		_ = try bob.prepareToEncrypt()
		let messageFrame = try bob.encrypt(Data("in-flight".utf8)).frame

		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let decrypted = try restored.processIncomingDecrypted(messageFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("in-flight".utf8))

		let openedSideBand = try XCTUnwrap(restored.openIncoming(updFrame))
		XCTAssertEqual(openedSideBand.kind, .pqSideBand(.rekeyUpd))
	}

	// MARK: - 8. Establishment round-trip

	/// The acceptor's real first frame — a sealed `0x03` with `APQWelcome_B`
	/// in the staple slot — opens via the initiator's window, captured at
	/// `initiate` before any inbound frame ever arrives.
	func testEstablishmentRoundTripAcceptorsSealedFirstFrameOpensViaInitiatorsWindow() throws {
		var (alice, bob, _, _, _, welcomeB) = try SessionTestSupport.established()
		XCTAssertFalse(alice.isEstablished)
		XCTAssertTrue(bob.isEstablished)

		_ = try bob.prepareToEncrypt()
		let firstFrame = try bob.encrypt(Data("bob-first".utf8)).frame
		XCTAssertNil(firstFrame.range(of: welcomeB))

		let opened = try XCTUnwrap(alice.openIncoming(firstFrame))
		XCTAssertEqual(opened.kind, .message)
		let (staple, _, _) = try Frames.decodeMessageFrame(opened.frame)
		XCTAssertEqual(staple, welcomeB)

		let decrypted = try alice.processIncomingDecrypted(firstFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-first".utf8))
		XCTAssertTrue(alice.isEstablished)
	}

	// MARK: - 9. Key-family isolation

	/// Zero one receive window (`recvHeaderKeys` classical,
	/// `recvHeaderKeysPQ` PQ) on a COPY of `receiver` (`TwoMLSSession` is a
	/// value type, so this never disturbs the live session) and confirm
	/// `frame` opens ONLY with its own family's window intact. Both
	/// `tryOpen`/`openIncoming` trial BOTH windows, so a mis-routed seal
	/// (the wrong family entirely) still passes every existing test — this
	/// is the only place that actually isolates which window did the work.
	private func assertOpensOnlyUnderExpectedFamily(
		_ frame: Data, isPQFamily: Bool, receiver: TwoMLSSession,
		file: StaticString = #filePath, line: UInt = #line
	) {
		var wrongFamilyZeroed = receiver
		if isPQFamily {
			wrongFamilyZeroed.recvHeaderKeys = [:]
		} else {
			wrongFamilyZeroed.recvHeaderKeysPQ = [:]
		}
		XCTAssertNotNil(
			wrongFamilyZeroed.tryOpen(frame),
			"expected the frame to still open with only its own family's window intact",
			file: file, line: line)

		var ownFamilyZeroed = receiver
		if isPQFamily {
			ownFamilyZeroed.recvHeaderKeysPQ = [:]
		} else {
			ownFamilyZeroed.recvHeaderKeys = [:]
		}
		XCTAssertNil(
			ownFamilyZeroed.tryOpen(frame),
			"expected the frame to fail to open once its own family's window is cleared",
			file: file, line: line)
	}

	/// Drives a full §A.3/§A.4/§A.5 round (mirroring
	/// `testOpenIncomingClassifiesEachSideBandKindAcrossA3A4A5` above) and
	/// pins the Send rule's key-family assignment for each of the six
	/// side-band tags: the pre-A.3 `BOOTSTRAP_KP` (`0x13`) and the A.4 legs
	/// (`0x17`/`0x19`) seal CLASSICAL; `0x15`/`0x1B`/`0x1D` seal PQ (book
	/// header-encryption.md, "Send rule"). Before this test, swapping the
	/// two families outright still passed 229/0, because trial decryption
	/// always tries both windows regardless of which one a frame is
	/// "supposed" to use.
	func testSideBandFramesOpenOnlyUnderTheirDocumentedKeyFamily() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		// §A.3: `0x13` — alice's recv-PQ (Group_B.pq) isn't founded until
		// this bootstrap, so this is the pre-A.3 classical fallback.
		let kpFrame = try alice.pqBootstrapBegin().frame
		assertOpensOnlyUnderExpectedFamily(kpFrame, isPQFamily: false, receiver: bob)

		// `0x15` — bob's recv-PQ (Group_A.pq) already exists from
		// `receive`'s `APQGroup.joinFull` at establishment,
		// so this is PQ.
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		assertOpensOnlyUnderExpectedFamily(welcomeFrame, isPQFamily: true, receiver: alice)
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		let bindPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(bindPrepared.didCommit)
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(bob.myPQTurn)

		// §A.4: both legs are classical — their inner MLS message rides the
		// classical groups (book, "Send rule").
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		assertOpensOnlyUnderExpectedFamily(ekFrame, isPQFamily: false, receiver: alice)

		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		assertOpensOnlyUnderExpectedFamily(ctFrame, isPQFamily: false, receiver: bob)
		_ = try bob.pqRatchetBind(ctFrame)

		let ratchetDischarge = try bob.prepareToEncrypt()
		XCTAssertTrue(ratchetDischarge.didCommit)
		let ratchetBoundFrame = try bob.encrypt(Data("ratchet-bound".utf8)).frame
		_ = try alice.processIncomingDecrypted(ratchetBoundFrame)
		XCTAssertTrue(alice.myPQTurn)

		// §A.5: both frames are PQ.
		let updFrame = try alice.pqRekeyBegin().frame
		assertOpensOnlyUnderExpectedFamily(updFrame, isPQFamily: true, receiver: bob)

		let commitFrame = try bob.pqRekeyRespond(updFrame).frame
		assertOpensOnlyUnderExpectedFamily(commitFrame, isPQFamily: true, receiver: alice)
		_ = try alice.pqRekeyApply(commitFrame)
	}

	// MARK: - 10. A.4 survives classical churn; pre-churn bytes do not

	/// `pqPendingOutbound()` re-seals live at the CURRENT recv epoch on
	/// every call (no send-side caching of the outer key), so an A.4 leg
	/// survives classical churn — the peer's ordinary message traffic
	/// moving the classical epoch underneath it — by simply re-sealing on
	/// the next call. The PRE-churn bytes do NOT open once the classical
	/// window evicts their epoch: the accepted cost of keying the A.4 legs
	/// by the classical epoch (book header-encryption.md, "Why the A.4 legs
	/// are the exception").
	func testA4LegSurvivesClassicalChurnViaLiveResealWhileEvictedBytesStopOpening() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let originalEK = try XCTUnwrap(bob.pqPendingOutbound())
		XCTAssertNotNil(alice.tryOpen(originalEK))

		let depth = try XCTUnwrap(alice.sendGroup?.classical.retention.resumptionPskDepth)
		for round in 0..<(depth + 2) {
			try fullFoldRound(proposer: &bob, approver: &alice, round: round)
		}

		// The pre-churn bytes are evicted past the classical family's
		// retention window.
		XCTAssertNil(alice.tryOpen(originalEK))

		// The round itself survives: the NEXT call re-seals live at bob's
		// now-current recv epoch (Group_A, moved by alice's own commits
		// above), which alice's window still holds.
		let resealedEK = try XCTUnwrap(bob.pqPendingOutbound())
		XCTAssertNotNil(alice.tryOpen(resealedEK))
	}

	// MARK: - 11. Restore: an OLDER archived window entry is load-bearing

	/// Unlike `testRestoreCarriesBothHeaderKeyWindowsAndOpensInFlightFrames`
	/// above (which only exercises restore's re-capture of the CURRENT
	/// epoch — dropping the archived window, or its 32-byte validation,
	/// both still passed 229/0), this pins an OLDER window entry as
	/// load-bearing: a frame is sealed at epoch N, the sealing group then
	/// advances past N to N+1 (so N can no longer be the CURRENT epoch —
	/// restore's live re-capture, which can only ever derive the group's
	/// CURRENT epoch, provably cannot reconstruct N), THEN archive+restore,
	/// THEN the restored session still opens the epoch-N frame — which only
	/// works if the ARCHIVE carried N forward. Covers both families: the
	/// classical window (a message frame) and the PQ window (an A.5
	/// `0x1B`).
	func testRestoreCarriesAnOlderArchivedWindowEntryNotJustTheRecapturedCurrentEpoch() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		// --- PQ: seal at Group_A.pq's current pq_epoch N, then advance it
		// to N+1 via a full §A.5 round.
		let stalePQFrame = try bob.pqRekeyBegin().frame
		XCTAssertNotNil(alice.tryOpen(stalePQFrame))

		let commitFrame = try alice.pqRekeyRespond(stalePQFrame).frame
		_ = try bob.pqRekeyApply(commitFrame)
		_ = try bob.prepareToEncrypt()
		let rekeyBoundFrame = try bob.encrypt(Data("rekey-bound".utf8)).frame
		_ = try alice.processIncomingDecrypted(rekeyBoundFrame)
		XCTAssertTrue(alice.myPQTurn)

		// --- Classical: seal at Group_A's current classical epoch N, then
		// advance it to N+1 via a plain fold (bob offers, alice commits).
		_ = try bob.prepareToEncrypt()
		let staleClassicalFrame = try bob.encrypt(Data("stale-classical".utf8)).frame
		XCTAssertNotNil(alice.tryOpen(staleClassicalFrame))

		try fullFoldRound(proposer: &bob, approver: &alice)

		// Both epochs have moved past where each frame was sealed — a LIVE
		// re-capture at restore time could only ever reproduce the NEW
		// current epoch, never these.
		XCTAssertNotNil(alice.tryOpen(stalePQFrame))
		XCTAssertNotNil(alice.tryOpen(staleClassicalFrame))

		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		let checkpoint = try sealAndOpen(archive)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let openedClassical = try XCTUnwrap(restored.openIncoming(staleClassicalFrame))
		XCTAssertEqual(openedClassical.kind, .message)
		let openedPQ = try XCTUnwrap(restored.openIncoming(stalePQFrame))
		XCTAssertEqual(openedPQ.kind, .pqSideBand(.rekeyUpd))
	}

	// MARK: - 12. Fail-closed: a short header-key window entry

	/// Mirrors the archive's other 32-byte-validated fields (e.g.
	/// `SessionArchiveTests.testShortBootstrapCommitmentIsRejected`): a
	/// restored classical header-key window entry shorter than the header
	/// AEAD's 32-byte key size is a corrupt or adversarial archive — fail
	/// closed.
	func testShortHeaderKeyWindowEntryIsRejected() throws {
		let alice = try SessionTestSupport.established().alice
		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		guard let firstEpoch = body.recvHeaderKeys?.entries.keys.first else {
			XCTFail("expected at least one captured classical header-key window entry")
			return
		}
		body.recvHeaderKeys?.entries[firstEpoch] = Data(repeating: 0, count: 31)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - 13. PQ window retention: keep-newest-4

	/// PQ analogue of `3. Cross-commit-in-flight` / `4.
	/// Wrong-epoch-outside-window` above: a side-band frame sealed under one
	/// `pq_epoch` keeps opening as further PQ rounds advance that epoch,
	/// within the flat keep-newest-`pqHeaderWindow` (4) retention — and
	/// stops opening once evicted past it. Every mechanical §A.5 round here
	/// advances BOTH parties' send-PQ groups by exactly one epoch (the
	/// owed-bind cross-commit ties them together), so `alice`'s window for
	/// Group_A.pq — the group bob's `0x1B` seals against — gains exactly
	/// one entry per round.
	func testPQSideBandFrameSurvivesWithinWindowAndIsEvictedBeyondIt() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let capturedEpoch = try XCTUnwrap(alice.sendGroup?.pq?.context.epoch)

		// Round 0: capture the frame at the CURRENT epoch, then complete
		// this exact round with the same (already-staged) frame.
		let updAtCapturedEpoch = try bob.pqRekeyBegin().frame
		XCTAssertNotNil(alice.tryOpen(updAtCapturedEpoch))
		try driveRekeyRound(
			initiator: &bob, committer: &alice, round: 0, preStaged: updAtCapturedEpoch)

		// Rounds 1-2 (3 total so far): the captured epoch stays retained —
		// it is at most the OLDEST of 4 retained entries.
		for round in 1...2 {
			if bob.myPQTurn {
				try driveRekeyRound(
					initiator: &bob, committer: &alice, round: round)
			} else {
				try driveRekeyRound(
					initiator: &alice, committer: &bob, round: round)
			}
		}
		XCTAssertNotNil(alice.tryOpen(updAtCapturedEpoch))

		// Round 3 (4 total): a 5th distinct epoch is captured, evicting the
		// oldest (the captured one) past the flat keep-newest-4 window.
		if bob.myPQTurn {
			try driveRekeyRound(initiator: &bob, committer: &alice, round: 3)
		} else {
			try driveRekeyRound(initiator: &alice, committer: &bob, round: 3)
		}
		XCTAssertNil(alice.tryOpen(updAtCapturedEpoch))
		XCTAssertFalse(alice.recvHeaderKeysPQ.keys.contains(capturedEpoch))
	}

	/// One full mechanical §A.5 round: `initiator` proposes Upd′ (or reuses
	/// `preStaged`, already minted off `initiator`), `committer` folds +
	/// commits, `initiator` applies + owes the bind, and the ack rides
	/// `initiator`'s next classical commit. Mirrors `RekeyTests`'s own
	/// `driveMechanicalRekeyRound`, generalized to either party as
	/// initiator (the turn alternates every round) and to reuse an
	/// already-captured frame for round 0.
	private func driveRekeyRound(
		initiator: inout TwoMLSSession, committer: inout TwoMLSSession, round: Int,
		preStaged: Data? = nil
	) throws {
		let updFrame = try preStaged ?? initiator.pqRekeyBegin().frame
		let commitFrame = try committer.pqRekeyRespond(updFrame).frame
		_ = try initiator.pqRekeyApply(commitFrame)
		_ = try initiator.prepareToEncrypt()
		let boundFrame = try initiator.encrypt(Data("rekey-bound-\(round)".utf8)).frame
		_ = try committer.processIncomingDecrypted(boundFrame)
	}

	// MARK: - 14. Side-band padding (`setPadTarget`)

	/// The header seal's fixed per-frame overhead (book
	/// header-encryption.md, "Sealed frame": 12-byte nonce + 4-byte length
	/// prefix + AEAD tag) — measured off the real provider rather than
	/// hardcoded, so a suite change cannot silently desync this from
	/// production.
	private func measuredSealOverhead() throws -> Int {
		let provider = SessionTestSupport.classicalProvider
		let key = Data(repeating: 0, count: provider.aeadKeySize)
		let nonce = Data(repeating: 0, count: provider.aeadNonceSize)
		let plaintext = Data(repeating: 0, count: 16)
		let sealed = try provider.aeadSeal(
			key: key, nonce: nonce, aad: nil, plaintext: plaintext)
		return provider.aeadNonceSize + 4 + (sealed.count - plaintext.count)
	}

	/// With an effectively unbounded `setPadTarget`, a self-staged EK grows
	/// to EXACTLY its co-stapled message's own sealed length (book
	/// header-encryption.md, "Frame length prefix & padding"), and the
	/// equalized (padded) EK is still decoder-invisible: the peer opens it
	/// and the A.4 round completes exactly as an unpadded one would.
	func testSideBandPaddingEqualizesEKAndMessageFrameLengths() throws {
		let bigApp = Data(repeating: 0x41, count: 8192)

		// Precondition, on an un-targeted sibling: the natural EK is
		// smaller than the message it will be equalized to below —
		// otherwise the growth this test pins would never actually engage,
		// and framing drift (e.g. the KEM's encapsulation-key size, or the
		// message-frame shape) would fail silently rather than loudly.
		var (_, siblingBob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try siblingBob.prepareToEncrypt()
		let siblingMsgFrame = try siblingBob.encrypt(bigApp).frame.count
		let naturalEK = try XCTUnwrap(siblingBob.pqPendingOutbound()).count
		XCTAssertLessThan(naturalEK, siblingMsgFrame)

		// The padded run: an effectively unbounded cap, so the EK grows all
		// the way to match its own co-stapled message.
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		bob.setPadTarget(Int.max)
		_ = try bob.prepareToEncrypt()
		let encrypted = try bob.encrypt(bigApp)
		let paddedEK = try XCTUnwrap(bob.pqPendingOutbound())
		XCTAssertEqual(paddedEK.count, encrypted.frame.count)

		let ctFrame = try alice.pqRatchetRespond(paddedEK).frame
		_ = try bob.pqRatchetBind(ctFrame)
		let discharge = try bob.prepareToEncrypt()
		XCTAssertTrue(discharge.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(boundFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
	}

	/// Absent any `setPadTarget` call, `padTarget` defaults to `nil` and a
	/// self-staged EK goes out at its natural size — smaller than the
	/// message it rides alongside (book header-encryption.md, "Frame length
	/// prefix & padding" — "Absent the intent ... frames go out at their
	/// natural size").
	func testNoPadTargetLeavesSideBandFrameAtNaturalSize() throws {
		var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try bob.prepareToEncrypt()
		let encrypted = try bob.encrypt(Data(repeating: 0x42, count: 8192))
		let ek = try XCTUnwrap(bob.pqPendingOutbound())
		XCTAssertLessThan(ek.count, encrypted.frame.count)
	}

	/// A target set below the natural EK size never shrinks it —
	/// `sideBandPadTo` only ever grows a frame (book header-encryption.md,
	/// "Frame length prefix & padding" — "only ever *grows*"). Measured
	/// twice on the SAME parked leg (`pqPendingOutbound` re-seals live on
	/// every call, never caching), so the comparison needs no cross-session
	/// assumption about matching natural sizes.
	func testPadTargetBelowNaturalEKSizeNeverShrinksIt() throws {
		var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data(repeating: 0x43, count: 4096))
		let naturalEK = try XCTUnwrap(bob.pqPendingOutbound())

		bob.setPadTarget(1)
		let clampedEK = try XCTUnwrap(bob.pqPendingOutbound())
		XCTAssertEqual(clampedEK.count, naturalEK.count)
	}

	/// `sideBandPadTo` at the function level (book header-encryption.md,
	/// "Frame length prefix & padding"): `nil` ⇒ the frame's own length (no
	/// growth); a set intent grows up to `min(target, lastMessageFrameLen)`
	/// but NEVER below the frame's own length. The grow-only floor is pinned
	/// here directly — `sealWith`'s own `max(0, padTo - frame.count)` clamp
	/// masks it end-to-end, so only a unit assertion on the returned target
	/// fails loudly if the floor is dropped.
	func testSideBandPadToGrowsOnlyWithinCap() throws {
		var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		bob.lastMessageFrameLen = 1000

		bob.setPadTarget(nil)
		XCTAssertEqual(bob.sideBandPadTo(frameLen: 300), 300)

		// Generous cap: grow to the co-stapled message's length.
		bob.setPadTarget(5000)
		XCTAssertEqual(bob.sideBandPadTo(frameLen: 300), 1000)

		// Tight cap: grow only to the target.
		bob.setPadTarget(600)
		XCTAssertEqual(bob.sideBandPadTo(frameLen: 300), 600)

		// Never shrink a frame already larger than min(target,
		// lastMessageFrameLen) — the grow-only floor.
		bob.setPadTarget(5000)
		XCTAssertEqual(bob.sideBandPadTo(frameLen: 2000), 2000)
		bob.setPadTarget(600)
		XCTAssertEqual(bob.sideBandPadTo(frameLen: 800), 800)
	}

	/// A cap strictly between the natural EK and the message frame grows
	/// the EK only up to that cap (plus the fixed seal overhead) — not all
	/// the way to the message (book header-encryption.md, "Frame length
	/// prefix & padding" — `min(n, last_message_frame_len)`). Both anchors
	/// and the cap itself are derived by measurement, on the SAME parked
	/// leg, no magic constants.
	func testPadTargetHonorsCapBetweenNaturalEKAndMessageFrame() throws {
		let sealOverhead = try measuredSealOverhead()
		var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try bob.prepareToEncrypt()
		let msgFrame = try bob.encrypt(Data(repeating: 0x44, count: 8192)).frame.count
		let naturalEK = try XCTUnwrap(bob.pqPendingOutbound()).count
		XCTAssertLessThan(naturalEK, msgFrame)

		let naturalEKUnsealed = naturalEK - sealOverhead
		let msgFrameUnsealed = msgFrame - sealOverhead
		let cap = (naturalEKUnsealed + msgFrameUnsealed) / 2
		XCTAssertGreaterThan(cap, naturalEKUnsealed)
		XCTAssertLessThan(cap, msgFrameUnsealed)

		bob.setPadTarget(cap)
		let cappedEK = try XCTUnwrap(bob.pqPendingOutbound())
		XCTAssertEqual(cappedEK.count, cap + sealOverhead)
		XCTAssertLessThan(cappedEK.count, msgFrame)
	}

	/// `padTarget`/`lastMessageFrameLen` are live host plumbing, deliberately
	/// NOT part of the session archive (unlike the header-key windows, which
	/// ARE persisted): a restored session starts back at natural (unpadded)
	/// sizing, and a host that wants padding must call `setPadTarget` again
	/// after restoring.
	func testPadTargetAndLastMessageFrameLenAreLiveOnlyNotArchivedAcrossRestore() throws {
		var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		bob.setPadTarget(4096)
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data(repeating: 0x45, count: 2048))
		XCTAssertNotNil(bob.padTarget)
		XCTAssertGreaterThan(bob.lastMessageFrameLen, 0)

		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		let checkpoint = try sealAndOpen(archive)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		XCTAssertNil(restored.padTarget)
		XCTAssertEqual(restored.lastMessageFrameLen, 0)
	}
}
