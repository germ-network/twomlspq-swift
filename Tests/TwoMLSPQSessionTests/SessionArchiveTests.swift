import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Slice 8a (PR1): the session archive type + encode/decode +
/// restore/reconcile + decode invariants. Every test drives a live session
/// to some state, archives it, round-trips the archive through a test-owned
/// key (`SecretArchive.seal`/`.open` — the app-seal boundary this library
/// itself never crosses), restores, and confirms the restored session
/// continues exactly like the live one it was cloned from.
@available(iOS 26, macOS 26, *)
final class SessionArchiveTests: XCTestCase {
	private let testKey = SecretBytes(randomByteCount: 32)
	private let testAAD = Data("twomlspq-session-archive-tests".utf8)

	/// The app-seal round-trip every test drives an archive through, so
	/// these tests exercise the exact boundary a real caller crosses
	/// (`SecretArchive` in, sealed `Data`, sealed `Data` back to an opened
	/// `SecretArchive`) rather than handing `restore` the unsealed value
	/// `makeSessionArchive` returned.
	private func sealAndOpen(_ archive: SecretArchive) throws -> SecretArchive {
		let sealed = try archive.seal(with: testKey, aad: testAAD)
		return try SecretArchive.open(sealed, with: testKey, aad: testAAD)
	}

	// MARK: - 1. established + exchanged

	func testEstablishedCheckpointRoundTripContinuesSendingAndReceiving() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let archive = try alice.makeSessionArchive(kind: .checkpoint, stateSeq: 1)
		let opened = try sealAndOpen(archive)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("hello".utf8))
		let decrypted = try bob.processIncoming(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("hello".utf8))

		_ = try bob.prepareToEncrypt()
		let reply = try bob.encrypt(Data("hi".utf8))
		let replyDecrypted = try restored.processIncoming(reply)
		XCTAssertEqual(replyDecrypted.applicationMessage, Data("hi".utf8))
	}

	// MARK: - 2. classical fold, then Core@higher-seq over Checkpoint@lower-seq

	/// A Core-kind archive never carries a PQ snapshot (regardless of
	/// whether the live half has one), so a non-nil `sendGroup.pq` after
	/// this restore can only have come from the spliced-in Checkpoint —
	/// that, plus the newer classical epoch, is the proof the splice ran.
	func testCoreNewerThanCheckpointSplicesPQAndContinues() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let checkpointArchive = try alice.makeSessionArchive(
			kind: .checkpoint, stateSeq: 10)

		// A routine classical fold: Bob offers, Alice approves and folds it
		// into her next commit — classical-only, PQ untouched.
		_ = try bob.prepareToEncrypt()
		let offerFrame = try bob.encrypt(Data("offer".utf8))
		_ = try alice.processIncoming(offerFrame)
		let (_, offerProposalSection, _) = try Frames.decodeMessageFrame(offerFrame)
		let (_, offerMessage) = try Frames.decodeProposalSection(offerProposalSection)
		let offerDigest = try SessionTestSupport.classicalProvider.hash(offerMessage)
		try alice.queueProposal(digest: offerDigest)

		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let foldFrame = try alice.encrypt(Data("folded".utf8))
		_ = try bob.processIncoming(foldFrame)

		let coreArchive = try alice.makeSessionArchive(kind: .core, stateSeq: 20)

		let openedCheckpoint = try sealAndOpen(checkpointArchive)
		let openedCore = try sealAndOpen(coreArchive)
		var restored = try TwoMLSSession.restore(
			core: openedCore, checkpoint: openedCheckpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		XCTAssertNotNil(restored.sendGroup?.pq)
		XCTAssertEqual(
			restored.sendGroup?.classical.context.epoch,
			alice.sendGroup?.classical.context.epoch)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("post-restore".utf8))
		let decrypted = try bob.processIncoming(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("post-restore".utf8))
	}

	// MARK: - 3. mid-A.3 (Group_B.pq deferred)

	func testMidA3CheckpointRestoreThenBootstrapCompletes() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		// Mid-A.3: Alice hasn't joined Group_B.pq yet.
		XCTAssertNil(alice.recvGroup?.pq)
		XCTAssertNotNil(alice.bootstrapKPSecret)
		XCTAssertNotNil(alice.pqInflight)

		let archive = try alice.makeSessionArchive(kind: .checkpoint, stateSeq: 1)
		let opened = try sealAndOpen(archive)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		try restored.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(restored.isFullyEstablished)

		let prepared = try restored.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let frame = try restored.encrypt(Data("bound".utf8))
		let decrypted = try bob.processIncoming(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
	}

	// MARK: - 4. mid-A.4 (pqInflight held: the responder's secret + parked CT)

	func testMidA4RespondingCheckpointRestoreThenRoundCompletes() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame)
		guard case .responding = alice.pqInflight else {
			return XCTFail("expected alice to hold `.responding` after sealing")
		}

		let archive = try alice.makeSessionArchive(kind: .checkpoint, stateSeq: 1)
		let opened = try sealAndOpen(archive)
		var restoredAlice = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		try bob.pqRatchetBind(ctFrame)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8))

		let decrypted = try restoredAlice.processIncoming(boundFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
		XCTAssertTrue(restoredAlice.myPQTurn)
	}

	// MARK: - 5. fail-closed: divergent PQ manifest

	func testCoreNewerWithDivergentPQManifestIsRejected() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let checkpointArchive = try alice.makeSessionArchive(kind: .checkpoint, stateSeq: 1)

		// A full PQ round moves Alice's recv PQ epoch — the Checkpoint above
		// never saw it.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame)
		try bob.pqRatchetBind(ctFrame)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8))
		_ = try alice.processIncoming(boundFrame)

		let coreArchive = try alice.makeSessionArchive(kind: .core, stateSeq: 2)

		let openedCheckpoint = try sealAndOpen(checkpointArchive)
		let openedCore = try sealAndOpen(coreArchive)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: openedCore, checkpoint: openedCheckpoint,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - 6. fail-closed: cross-session mispair

	func testCrossSessionMispairIsRejected() throws {
		let aliceA = try SessionTestSupport.established(alice: "alice-a", bob: "bob-a")
			.alice
		let aliceB = try SessionTestSupport.established(alice: "alice-b", bob: "bob-b")
			.alice

		let coreFromA = try aliceA.makeSessionArchive(kind: .core, stateSeq: 5)
		let checkpointFromB = try aliceB.makeSessionArchive(kind: .checkpoint, stateSeq: 1)

		let openedCore = try sealAndOpen(coreFromA)
		let openedCheckpoint = try sealAndOpen(checkpointFromB)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: openedCore, checkpoint: openedCheckpoint,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - 7. fail-closed: header fields

	func testWrongVersionAndSuiteAreRejected() throws {
		let alice = try SessionTestSupport.established().alice
		let archive = try alice.makeSessionArchive(kind: .checkpoint, stateSeq: 1)
		var body = try archive.decode(SessionArchive.self)

		body.version = 2
		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
		body.version = 1

		body.classicalSuite = 0xFFFF
		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	func testKindMismatchIsRejected() throws {
		let alice = try SessionTestSupport.established().alice
		// A Core-kind archive handed in as the (mandatory) Checkpoint slot.
		let coreArchive = try alice.makeSessionArchive(kind: .core, stateSeq: 1)
		let opened = try sealAndOpen(coreArchive)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: opened,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - Decode invariant: the pinned bootstrap commitment length

	func testShortBootstrapCommitmentIsRejected() throws {
		let bob = try SessionTestSupport.establishedAndExchanged().bob
		// Bob is the responder: `expectedBootstrapKPCommitment` is set on him.
		XCTAssertNotNil(bob.expectedBootstrapKPCommitment)

		let archive = try bob.makeSessionArchive(kind: .checkpoint, stateSeq: 1)
		var body = try archive.decode(SessionArchive.self)
		body.expectedBootstrapKPCommitment = Data([1, 2, 3])

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}
}
