import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Slice 8a: the **live** return cadence — `StateUpdate`/`stateSeq`/
/// `dependsOnSeq` driven off the actual public methods, never a
/// directly-constructed archive (that's `SessionArchiveTests`'s own fixed
/// stand-ins). Every save below is a `StateUpdate` a real call returned,
/// sealed through the same app-boundary `SecretArchive.seal`/`.open`.
@available(iOS 26, macOS 26, *)
final class SessionReturnCadenceTests: XCTestCase {
	private let testKey = SecretBytes(randomByteCount: 32)
	private let testAAD = Data("twomlspq-session-return-cadence-tests".utf8)

	private func sealAndOpen(_ archive: SecretArchive) throws -> SecretArchive {
		let sealed = try archive.seal(with: testKey, aad: testAAD)
		return try SecretArchive.open(sealed, with: testKey, aad: testAAD)
	}

	/// Keeps the latest Core and latest Checkpoint blob a session's returned
	/// `StateUpdate`s have produced, each sealed through the app boundary
	/// immediately on save — mirroring how an app would file them, keeping
	/// only the latest of each kind.
	private final class BlobStore {
		private let seal: (SecretArchive) throws -> SecretArchive
		private(set) var core: SecretArchive?
		private(set) var checkpoint: SecretArchive?

		init(seal: @escaping (SecretArchive) throws -> SecretArchive) {
			self.seal = seal
		}

		@discardableResult
		func save(_ update: StateUpdate) throws -> StateUpdate {
			let sealed = try seal(update.archive)
			switch update.kind {
			case .core: core = sealed
			case .checkpoint: checkpoint = sealed
			}
			return update
		}
	}

	// MARK: - 1. Live multi-step round-trip, mid-stream restore

	/// Drives established → routine messages → a classical fold → the §A.3
	/// bootstrap-and-bind, saving every one of ALICE's own returned
	/// `StateUpdate`s into a `BlobStore` exactly as her app would (Bob is
	/// only the wire peer here — his own returns are his own app's concern,
	/// not saved into Alice's store); restores Alice mid-stream from
	/// whatever the store holds at that point, then confirms both directions
	/// still work off the restored session.
	func testLiveRoundTripSavingReturnedUpdatesRestoresMidStreamAndContinues() throws {
		let store = BlobStore(seal: sealAndOpen)

		let aliceIdentity = try SessionTestSupport.identity("alice")
		let bobIdentity = try SessionTestSupport.identity("bob")

		let initiated = try TwoMLSSession.initiate(
			identity: aliceIdentity, their: bobIdentity.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try store.save(initiated.baseline)
		var alice = initiated.session

		let received = try TwoMLSSession.receive(
			identity: bobIdentity, welcome: initiated.welcome,
			theirClassicalKeyPackage: aliceIdentity.keyPackage.classical,
			bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var bob = received.session

		// Bob's first frame establishes Alice (her recvGroup is founded here).
		_ = try bob.prepareToEncrypt()
		let bobHello = try bob.encrypt(Data("bob-hello".utf8))
		let aliceGotHello = try alice.processIncomingDecrypted(bobHello.frame)
		try store.save(aliceGotHello.update)

		// A routine message from Alice.
		_ = try alice.prepareToEncrypt()
		let aliceHello = try alice.encrypt(Data("hello bob".utf8))
		try store.save(aliceHello.update)
		_ = try bob.processIncomingDecrypted(aliceHello.frame)

		// Bob offers a routine Update; Alice approves it (a fold) and folds
		// it into her next commit.
		_ = try bob.prepareToEncrypt()
		let bobOffer = try bob.encrypt(Data("bob-offer".utf8))
		let aliceOffered = try alice.processIncomingDecrypted(bobOffer.frame)
		try store.save(aliceOffered.update)
		try store.save(alice.queueProposal(digest: aliceOffered.queuedProposal.digest))

		let alicePrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(alicePrepared.didCommit)
		try store.save(alicePrepared.update)
		let aliceFolded = try alice.encrypt(Data("folded".utf8))
		try store.save(aliceFolded.update)
		_ = try bob.processIncomingDecrypted(aliceFolded.frame)

		// Alice's fold just advanced her OWN send epoch past the epoch Bob's
		// last-seen offer licensed (the discharge-license gating, book
		// protocol-flows.md:68,93-101) — one more Bob→Alice frame re-stamps
		// the license at the new epoch, or the upcoming bind discharge below
		// has no license to fire on.
		_ = try bob.prepareToEncrypt()
		let bobPostFold = try bob.encrypt(Data("post-fold".utf8))
		try store.save(alice.processIncomingDecrypted(bobPostFold.frame).update)

		// The §A.3 bootstrap-and-bind — a Checkpoint-heavy stretch.
		let kp = try alice.pqBootstrapBegin()
		try store.save(kp.update)
		let welcome = try bob.pqBootstrapRespond(kp.frame)
		let joined = try alice.pqBootstrapJoin(welcome.frame)
		try store.save(joined)

		let boundPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(boundPrepared.didCommit)
		try store.save(boundPrepared.update)
		let boundFrame = try alice.encrypt(Data("bound".utf8))
		try store.save(boundFrame.update)
		_ = try bob.processIncomingDecrypted(boundFrame.frame)

		// Mid-stream restore of Alice from whatever the store holds now.
		let savedCheckpoint = try XCTUnwrap(store.checkpoint)
		var restoredAlice = try TwoMLSSession.restore(
			core: store.core, checkpoint: savedCheckpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertTrue(restoredAlice.isFullyEstablished)

		// Both directions continue off the restored session.
		_ = try restoredAlice.prepareToEncrypt()
		let postRestore = try restoredAlice.encrypt(Data("post-restore".utf8))
		let bobDecrypted = try bob.processIncomingDecrypted(postRestore.frame)
		XCTAssertEqual(bobDecrypted.applicationMessage, Data("post-restore".utf8))

		_ = try bob.prepareToEncrypt()
		let bobReply = try bob.encrypt(Data("reply".utf8))
		let aliceDecrypted = try restoredAlice.processIncomingDecrypted(bobReply.frame)
		XCTAssertEqual(aliceDecrypted.applicationMessage, Data("reply".utf8))
	}

	// MARK: - 2. Cadence correctness: Core vs Checkpoint per method

	/// A classical-only mutation (`prepareToEncrypt`/`encrypt`/`queueProposal`/
	/// `pqBootstrapBegin`/`pqRatchetRespond`) always returns `.core`; a
	/// mutation that moves a PQ ML-KEM tree (`pqBootstrapRespond`/
	/// `pqBootstrapJoin`/`pqRatchetBind`/`pqRekeyBegin`/`pqRekeyRespond`/
	/// `pqRekeyApply`) always returns `.checkpoint` — the static per-site
	/// tags, exercised across a full bootstrap + ratchet + re-key lifecycle.
	func testStaticKindAssignmentsMatchCoreVsCheckpoint() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let alicePrepared = try alice.prepareToEncrypt()
		XCTAssertEqual(alicePrepared.update.kind, .core)
		let aliceHello = try alice.encrypt(Data("hello".utf8))
		XCTAssertEqual(aliceHello.update.kind, .core)
		_ = try bob.processIncomingDecrypted(aliceHello.frame)

		// §A.3 bootstrap: begin (classical-only parking) → .core; respond
		// (founds sendGroup.pq) / join (joins recvGroup.pq) → .checkpoint.
		let kp = try alice.pqBootstrapBegin()
		XCTAssertEqual(kp.update.kind, .core)
		let welcome = try bob.pqBootstrapRespond(kp.frame)
		XCTAssertEqual(welcome.update.kind, .checkpoint)
		let joined = try alice.pqBootstrapJoin(welcome.frame)
		XCTAssertEqual(joined.kind, .checkpoint)

		// Discharge the owed bind: prepareToEncrypt/encrypt stay .core even
		// though committingRound folds the bind's PQ-half commit message —
		// these two methods are tagged statically, deliberately, regardless.
		let boundPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(boundPrepared.didCommit)
		XCTAssertEqual(boundPrepared.update.kind, .core)
		let boundFrame = try alice.encrypt(Data("bound".utf8))
		XCTAssertEqual(boundFrame.update.kind, .core)
		let bobGotBind = try bob.processIncomingDecrypted(boundFrame.frame)
		// `applyBind` rides `processIncoming` and moves Bob's recvGroup.pq —
		// the ONE dynamically-derived kind, covered on its own below.
		XCTAssertEqual(bobGotBind.update.kind, .checkpoint)
		XCTAssertTrue(bob.myPQTurn)

		// §A.4 ratchet: Bob (turn-holder) stages, Alice responds
		// (`pqRatchetRespond`, a classical carrier only → .core), Bob binds
		// (`pqRatchetBind`, owePQBind commits sendGroup.pq → .checkpoint).
		_ = try bob.prepareToEncrypt()
		let stage = try bob.encrypt(Data("stage-ek".utf8))
		_ = try alice.processIncomingDecrypted(stage.frame)
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame)
		XCTAssertEqual(ctFrame.update.kind, .core)
		let bindUpdate = try bob.pqRatchetBind(ctFrame.frame)
		XCTAssertEqual(bindUpdate.kind, .checkpoint)
		let ratchetPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(ratchetPrepared.didCommit)
		let ratchetBound = try bob.encrypt(Data("ratchet-bound".utf8))
		_ = try alice.processIncomingDecrypted(ratchetBound.frame)
		XCTAssertTrue(alice.myPQTurn)

		// §A.5 mechanical re-key: begin (stages Upd′ into recvGroup.pq — no
		// epoch change, but per the map still .checkpoint), respond (commits
		// sendGroup.pq → .checkpoint), apply (commits recvGroup.pq +
		// owePQBind → .checkpoint).
		let updFrame = try alice.pqRekeyBegin()
		XCTAssertEqual(updFrame.update.kind, .checkpoint)
		let commitFrame = try bob.pqRekeyRespond(updFrame.frame)
		XCTAssertEqual(commitFrame.update.kind, .checkpoint)
		let rekeyApplied = try alice.pqRekeyApply(commitFrame.frame)
		XCTAssertEqual(rekeyApplied.kind, .checkpoint)
	}

	/// The idempotent re-serve branches (`pqBootstrapBegin`/
	/// `pqBootstrapRespond`/`pqRekeyBegin`, re-called while their round is
	/// still outstanding) still return a `StateUpdate` of the same kind as a
	/// fresh call, even though nothing about the session actually changed
	/// the second time.
	func testIdempotentResendsStillReturnAStateUpdateOfTheSameKind() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		// PR2: each re-serve re-seals under a fresh nonce, so the SEALED
		// bytes always differ even though the plaintext is idempotent —
		// compare the OPENED plaintexts (via the recipient's window)
		// instead.
		let first = try alice.pqBootstrapBegin()
		let second = try alice.pqBootstrapBegin()
		XCTAssertEqual(bob.openOrRaw(first.frame), bob.openOrRaw(second.frame))
		XCTAssertEqual(second.update.kind, .core)

		let welcome1 = try bob.pqBootstrapRespond(first.frame)
		let welcome2 = try bob.pqBootstrapRespond(first.frame)
		XCTAssertEqual(alice.openOrRaw(welcome1.frame), alice.openOrRaw(welcome2.frame))
		// The re-serve moves nothing group-level (unlike the founding
		// answer above, `welcome1`, which is still `.checkpoint`) — a host
		// attaches the twin on every send instead.
		XCTAssertEqual(welcome2.update.kind, .core)
	}

	/// `processIncoming`'s kind is derived from an actual PQ-tree delta, not
	/// a static tag — REQUIRED because `applyBind` rides this method's staple
	/// dispatch and moves `recvGroup.pq`. Mutation-verify: had
	/// this call instead tagged itself `.core` (so the app never captured a
	/// fresh Checkpoint here), the app's last real Checkpoint — taken just
	/// before the bind landed — paired with ANY later Core would disagree on
	/// the PQ-epoch manifest and `restore` would fail closed. The real
	/// cadence instead hands back `.checkpoint` at exactly this call, and
	/// restoring from THAT succeeds and the PQ round completes.
	func testProcessIncomingOfBindFrameReturnsCheckpointMutationVerified() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kp = try alice.pqBootstrapBegin()
		let welcome = try bob.pqBootstrapRespond(kp.frame)
		_ = try alice.pqBootstrapJoin(welcome.frame)

		// Bob's last Checkpoint BEFORE the bind lands — his recvGroup.pq (the
		// mirror of Alice's Group_A.pq) is still at its pre-bind epoch here.
		let staleCheckpoint = try bob.makeSessionArchive(kind: .checkpoint)

		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let bound = try alice.encrypt(Data("bound".utf8))

		let decrypted = try bob.processIncomingDecrypted(bound.frame)
		XCTAssertEqual(decrypted.update.kind, .checkpoint)

		// Counterfactual: a Core taken from Bob NOW (always PQ-tree-omitting,
		// regardless of any mistagging) paired with the stale pre-bind
		// Checkpoint — exactly what the app would be left holding had this
		// call wrongly returned `.core` instead of `.checkpoint` here.
		let coreTakenNow = try bob.makeSessionArchive(kind: .core)
		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: coreTakenNow, checkpoint: staleCheckpoint,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}

		// The real cadence's own Checkpoint, taken at exactly this call,
		// restores cleanly and the PQ round can still complete.
		let freshCheckpoint = try sealAndOpen(decrypted.update.archive)
		var restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: freshCheckpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertTrue(restoredBob.myPQTurn)

		let rekeyed = try restoredBob.pqRekeyBegin()
		XCTAssertEqual(rekeyed.update.kind, .checkpoint)
	}

	// MARK: - 3. stateSeq monotonicity

	/// `stateSeq` strictly increases across every state-advancing call, and
	/// a restored session's own `stateSeq` equals the reconciled blob's.
	func testStateSeqStrictlyIncreasesAndSurvivesRestore() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let afterEstablish = alice.stateSeq  // baseline (0) + Bob's founding frame

		let prepared = try alice.prepareToEncrypt()
		XCTAssertGreaterThan(prepared.update.stateSeq, afterEstablish)

		let encrypted = try alice.encrypt(Data("hello".utf8))
		XCTAssertGreaterThan(encrypted.update.stateSeq, prepared.update.stateSeq)
		_ = try bob.processIncomingDecrypted(encrypted.frame)

		let kp = try alice.pqBootstrapBegin()
		XCTAssertGreaterThan(kp.update.stateSeq, encrypted.update.stateSeq)
		let welcome = try bob.pqBootstrapRespond(kp.frame)
		let joined = try alice.pqBootstrapJoin(welcome.frame)
		XCTAssertGreaterThan(joined.stateSeq, kp.update.stateSeq)

		XCTAssertEqual(alice.stateSeq, joined.stateSeq)

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: try sealAndOpen(joined.archive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(restored.stateSeq, joined.stateSeq)
	}

	// MARK: - 4. Durability gate (`dependsOnSeq`)

	/// A `prepareToEncrypt` that produces a fresh commit (a fold, here)
	/// reports `dependsOnSeq` equal to the `stateSeq` of its OWN returned
	/// `StateUpdate` — the app must durably save THIS call's update before
	/// transmitting the frame that carries the fresh staple. A later routine
	/// `prepareToEncrypt`/`encrypt` pair (no new key material) reports the
	/// SAME `dependsOnSeq` as before — already durable, no additional wait.
	func testDurabilityGateDependsOnSeqTracksTheLastFreshStaple() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		// Bob offers; Alice approves and folds — a fresh commit/staple.
		_ = try bob.prepareToEncrypt()
		let offer = try bob.encrypt(Data("offer".utf8))
		let offered = try alice.processIncomingDecrypted(offer.frame)
		_ = try alice.queueProposal(digest: offered.queuedProposal.digest)

		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		XCTAssertEqual(foldPrepared.dependsOnSeq, foldPrepared.update.stateSeq)
		let foldFrame = try alice.encrypt(Data("folded".utf8))
		_ = try bob.processIncomingDecrypted(foldFrame.frame)

		// A routine round after that: no new commit, so `dependsOnSeq` stays
		// pinned to the fold's own seq — already durable, no additional wait.
		let routinePrepared = try alice.prepareToEncrypt()
		XCTAssertFalse(routinePrepared.didCommit)
		XCTAssertEqual(routinePrepared.dependsOnSeq, foldPrepared.dependsOnSeq)
		XCTAssertLessThan(routinePrepared.dependsOnSeq, routinePrepared.update.stateSeq)
		_ = try alice.encrypt(Data("routine".utf8))
	}

	/// `restore` seeds `currentStapleSeq` (the durability watermark) from the
	/// reconciled `stateSeq` itself — pin that seed through `dependsOnSeq`: a
	/// routine `prepareToEncrypt` right after restore (nothing queued or
	/// owed, so no fresh commit) reports `dependsOnSeq == restored.stateSeq`.
	func testRestoreSeedsCurrentStapleSeqFromTheReconciledStateSeq() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		// Bob's own `.checkpoint` return (founding `sendGroup.pq`) — restore
		// needs a `.checkpoint`-kind archive in the `checkpoint:` slot.
		let kp = try alice.pqBootstrapBegin()
		let welcome = try bob.pqBootstrapRespond(kp.frame)

		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: try sealAndOpen(welcome.update.archive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		// The seeded value, BEFORE the routine call below bumps `stateSeq`
		// further.
		let seededStateSeq = restored.stateSeq

		let routine = try restored.prepareToEncrypt()
		XCTAssertFalse(routine.didCommit)
		XCTAssertEqual(routine.dependsOnSeq, seededStateSeq)
		_ = try alice.processIncomingDecrypted(
			try restored.encrypt(Data("post-restore".utf8)).frame)
	}

	// MARK: - 5. mid-A.3 / mid-A.4 reached and restored via the live cadence

	/// The live-cadence analogue of `SessionArchiveTests`'
	/// `testMidA3CheckpointRestoreThenBootstrapCompletes`: reach mid-A.3
	/// (Alice's Group_B.pq still deferred) by driving the live methods, save
	/// the returned `StateUpdate`, restore, and complete the bootstrap+bind.
	func testMidA3ReachedViaLiveCadenceRestoresAndCompletes() throws {
		let aliceIdentity = try SessionTestSupport.identity("alice")
		let bobIdentity = try SessionTestSupport.identity("bob")

		// `initiate`'s baseline IS a `.checkpoint` `StateUpdate` — the last
		// (and, here, only) Checkpoint the live cadence has produced by the
		// time mid-A.3 is reached below.
		let initiated = try TwoMLSSession.initiate(
			identity: aliceIdentity, their: bobIdentity.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var alice = initiated.session

		let received = try TwoMLSSession.receive(
			identity: bobIdentity, welcome: initiated.welcome,
			theirClassicalKeyPackage: aliceIdentity.keyPackage.classical,
			bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var bob = received.session

		_ = try bob.prepareToEncrypt()
		let bobHello = try bob.encrypt(Data("bob-hello".utf8))
		_ = try alice.processIncomingDecrypted(bobHello.frame)

		let kp = try alice.pqBootstrapBegin()
		let welcome = try bob.pqBootstrapRespond(kp.frame)

		XCTAssertNil(alice.recvGroup?.pq)
		XCTAssertNotNil(alice.bootstrapKPSecret)

		// `kp.update` (`.core`, mid-A.3) is newer than the baseline
		// Checkpoint — `recvClassicalGroupID` going nil→some on the newer
		// side is exactly the ordinary mid-A.3 transition `restore`
		// tolerates by design (`validateIdentityAgreement`).
		var restoredAlice = try TwoMLSSession.restore(
			core: try sealAndOpen(kp.update.archive),
			checkpoint: try sealAndOpen(initiated.baseline.archive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		// The winning (Core) body's own `stateSeq` is what the restored
		// session's live counter picks up — not the (older) Checkpoint's.
		XCTAssertEqual(restoredAlice.stateSeq, kp.update.stateSeq)

		_ = try restoredAlice.pqBootstrapJoin(welcome.frame)
		XCTAssertTrue(restoredAlice.isFullyEstablished)

		let prepared = try restoredAlice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let bound = try restoredAlice.encrypt(Data("bound".utf8))
		let decrypted = try bob.processIncomingDecrypted(bound.frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
	}

	/// The live-cadence analogue of `SessionArchiveTests`'
	/// `testMidA4RespondingCheckpointRestoreThenRoundCompletes`: reach mid-A.4
	/// (Alice holding `.responding` — her sealed `S`/parked CT) by driving
	/// the live methods, save the returned `StateUpdate`, restore, and finish
	/// the round.
	func testMidA4ReachedViaLiveCadenceRestoresAndCompletes() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kp = try alice.pqBootstrapBegin()
		let welcome = try bob.pqBootstrapRespond(kp.frame)
		// `pqBootstrapJoin`'s own `.checkpoint` return — Alice's PQ trees
		// don't move again until the ratchet round below, so this is the
		// live cadence's own up-to-date Checkpoint for the whole stretch.
		let joined = try alice.pqBootstrapJoin(welcome.frame)

		let boundPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(boundPrepared.didCommit)
		let bound = try alice.encrypt(Data("bound".utf8))
		_ = try bob.processIncomingDecrypted(bound.frame)
		XCTAssertTrue(bob.myPQTurn)

		// §A.4: Bob (turn-holder) stages an EK; Alice responds, sealing `S`
		// and holding `.responding` — classical-only from Alice's side
		// (`pqRatchetRespond` → `.core`), so `ctFrame.update` is newer than
		// (and splices cleanly over) the `joined` Checkpoint above.
		_ = try bob.prepareToEncrypt()
		let staged = try bob.encrypt(Data("m".utf8))
		_ = try alice.processIncomingDecrypted(staged.frame)
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame)
		guard case .responding = alice.pqInflight else {
			return XCTFail("expected alice to hold `.responding` after sealing")
		}

		var restoredAlice = try TwoMLSSession.restore(
			core: try sealAndOpen(ctFrame.update.archive),
			checkpoint: try sealAndOpen(joined.archive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		_ = try bob.pqRatchetBind(ctFrame.frame)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundAgain = try bob.encrypt(Data("bound-again".utf8))

		let decrypted = try restoredAlice.processIncomingDecrypted(boundAgain.frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound-again".utf8))
		XCTAssertTrue(restoredAlice.myPQTurn)
	}

	// MARK: - 6. Regression: an un-checkpointed PQ-tree move survives a later throw

	/// `processIncoming` isn't transactional: `applyBind` (inside
	/// `handleStaple`) advances `recvGroup.pq` on `self` BEFORE the further
	/// throwing steps (`unprotect`/`decodeProposalSection`/`hash`) run. With
	/// return-on-success-only, a throw there — an on-path attacker flipping
	/// one app-section byte, reproduced literally below — leaves
	/// `recvGroup.pq` advanced but returns no `StateUpdate`, so no Checkpoint
	/// ever captures the move. The peer just re-rides the same staple next
	/// (`.skip`, no PQ delta of ITS own), so `processIncoming`'s own
	/// before/after snapshot alone would tag that next call `.core` too —
	/// `stateUpdate(kind:)`'s sticky invariant (comparing the live PQ-epoch
	/// manifest against the manifest as of the last `.checkpoint` this
	/// session actually minted) is what has to catch the drift instead.
	func testUnCheckpointedPQMoveSurvivingAThrowIsRepairedByTheStickyCheckpointInvariant()
		throws
	{
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kp = try alice.pqBootstrapBegin()
		let welcome = try bob.pqBootstrapRespond(kp.frame)
		// Bob's last saved Checkpoint, from before the bind frame ever arrives.
		let lastSavedCheckpoint = try sealAndOpen(welcome.update.archive)

		_ = try alice.pqBootstrapJoin(welcome.frame)
		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let bound = try alice.encrypt(Data("bound".utf8))

		// A tampered COPY of the bind frame: the `0x05` staple rides intact
		// (so `applyBind` still applies and moves Bob's `recvGroup.pq`), one
		// flipped byte in the APP section (so `unprotect` throws AFTER that
		// move).
		// PR2: opened via `bob` (the recipient); the reconstructed
		// `tamperedFrame` below passes straight through `processIncoming`'s
		// `openOrRaw`.
		let (staple, proposal, app) = try Frames.decodeMessageFrame(
			bob.openOrRaw(bound.frame))
		var tamperedApp = app
		tamperedApp[
			tamperedApp.index(tamperedApp.startIndex, offsetBy: tamperedApp.count / 2)] ^=
			0xFF
		let tamperedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: proposal, app: tamperedApp)

		XCTAssertThrowsError(try bob.processIncomingDecrypted(tamperedFrame))
		// The bind already landed on `bob.recvGroup.pq` despite the throw —
		// an un-checkpointed PQ-tree move, with no `StateUpdate` ever
		// returned for it. `advanceStateSeq()` sits AFTER the throwing step
		// too, so Bob's `stateSeq` is still tied with `lastSavedCheckpoint`'s
		// here — a restore right now would just take the Checkpoint outright
		// (the tie rule) and hide the drift; it only surfaces once a LATER
		// successful call moves `stateSeq` past it, below.
		XCTAssertTrue(bob.myPQTurn)

		// The peer just re-rides the SAME staple on its next frame — Bob's
		// `.skip` path applies no further PQ delta of its own, so
		// `processIncoming`'s own before/after snapshot alone would tag this
		// call `.core` too. This is the first call to actually ADVANCE
		// `stateSeq` since the un-checkpointed move.
		_ = try alice.prepareToEncrypt()
		let nextFrame = try alice.encrypt(Data("next".utf8))
		let decrypted = try bob.processIncomingDecrypted(nextFrame.frame)

		// The sticky invariant catches the manifest drift and upgrades this
		// call's own kind, even though its own before/after snapshot saw
		// none — this assertion is exactly what would fail without it.
		XCTAssertEqual(decrypted.update.kind, .checkpoint)

		// What the app would be left holding WITHOUT the sticky invariant:
		// the SAME live state as `decrypted.update`, but encoded as a bare
		// `.core` (bypassing `stateUpdate`'s upgrade) — its manifest already
		// reflects the moved tree, newer (by `stateSeq`) than the last real
		// Checkpoint above, which is still pre-bind. Pairing them is exactly
		// the un-reconcilable state the blocker described.
		let coreWithoutStickyFix = try bob.makeSessionArchive(kind: .core)
		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: coreWithoutStickyFix, checkpoint: lastSavedCheckpoint,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}

		// The real cadence's own return instead restores cleanly, and the
		// session continues.
		var restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: try sealAndOpen(decrypted.update.archive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertTrue(restoredBob.isFullyEstablished)

		_ = try restoredBob.prepareToEncrypt()
		let post = try restoredBob.encrypt(Data("post-repair".utf8))
		let final = try alice.processIncomingDecrypted(post.frame)
		XCTAssertEqual(final.applicationMessage, Data("post-repair".utf8))
	}
}
