import Foundation
import MLSCodec
import MLSCombiner
import MLSProfileRFC9420
import SecretBytes
import XCTest

@testable import TwoMLSPQSession

/// Slice 8b: `Principal`/`Invitation`, the four tables, single-use vs
/// last-resort, and `Session.forwarded(spawnToken:)` — the app-facing
/// 3-object model layered over the existing identity-based establishment
/// (book concepts.md, session-lifecycle.md's "Invitations & replayed
/// initial frames").
@available(iOS 26, macOS 26, *)
final class InvitationTests: XCTestCase {
	private func makePrincipal(_ name: String) throws -> Principal {
		try Principal.generate(
			clientID: Data(name.utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	private func freshSpawnToken() -> Data {
		SessionTestSupport.classicalProvider.randomBytes(16)
	}

	/// Runs one `initiate` -> `receive` round against `invitation`, returning
	/// everything a caller might want to assert on.
	private func acceptOneWelcome(
		from initiator: Principal, into invitation: inout Invitation
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, welcome: Data, spawnToken: Data,
		bootstrapKPCommitment: Data, archive: SecretArchive, baseline: StateUpdate
	) {
		let theirCombinerKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: initiator, their: theirCombinerKP)
		let commitment = try initiated.session.bootstrapKPCommitment()
		let spawnToken = freshSpawnToken()
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: commitment, spawnToken: spawnToken)
		return (
			alice: initiated.session, bob: received.session, welcome: initiated.welcome,
			spawnToken: spawnToken, bootstrapKPCommitment: commitment,
			archive: received.archive, baseline: received.baseline
		)
	}

	// MARK: - Happy path

	/// A principal mints an invitation; a peer initiates to its published
	/// combiner KP; `Invitation.receive` yields a working session in both
	/// directions, and A.3 completes.
	func testInvitationReceiveYieldsAWorkingSessionBothDirectionsAndA3Completes() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)

		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		var alice = round.alice
		var bob = round.bob
		XCTAssertTrue(bob.isEstablished)
		XCTAssertFalse(alice.isEstablished)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobFrame)
		XCTAssertTrue(alice.isEstablished)

		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-hello".utf8)).frame
		let aliceDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		XCTAssertEqual(aliceDecrypted.applicationMessage, Data("alice-hello".utf8))

		_ = try bob.prepareToEncrypt()
		let bobReply = try bob.encrypt(Data("bob-reply".utf8)).frame
		let bobDecrypted = try alice.processIncomingDecrypted(bobReply)
		XCTAssertEqual(bobDecrypted.applicationMessage, Data("bob-reply".utf8))

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(alice.isFullyEstablished)
		XCTAssertTrue(bob.isFullyEstablished)
	}

	// MARK: - Dedup

	func testRedeliveringTheExactSameWelcomeIsDuplicateWelcome() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		let expectedGroupID = try XCTUnwrap(round.bob.recvGroup?.classical.context.groupID)

		XCTAssertThrowsError(
			try invitation.receive(
				welcome: round.welcome,
				theirClassicalKeyPackage: round.alice.identity.keyPackage.classical,
				bootstrapKPCommitment: round.bootstrapKPCommitment,
				spawnToken: round.spawnToken)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .duplicateWelcome)
		}

		XCTAssertEqual(
			invitation.processedWelcomeGroupID(welcome: round.welcome), expectedGroupID)
		XCTAssertEqual(
			invitation.forwardGroupID(spawnToken: round.spawnToken), expectedGroupID)

		// `bootstrapKPGroupID` resolves whether the frame arrives tagged
		// (the `0x13` side-band wire shape) or already untagged (the same
		// preimage `bootstrapKPCommitment()` hashes).
		let untaggedKP = try XCTUnwrap(round.alice.bootstrapKPBytes())
		XCTAssertEqual(invitation.bootstrapKPGroupID(kpFrame: untaggedKP), expectedGroupID)
		XCTAssertEqual(
			invitation.bootstrapKPGroupID(
				kpFrame: Frames.encodePQBootstrapKP(untaggedKP)),
			expectedGroupID)
	}

	/// A second, DIFFERENT welcome from the same remote (the same principal
	/// initiating a second time) is also `.duplicateWelcome` — the
	/// consumed-remote guard, not the content-keyed one.
	func testASecondDifferentWelcomeFromTheSameRemoteIsDuplicateWelcome() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		_ = try acceptOneWelcome(from: alicePrincipal, into: &invitation)

		// A second `initiate` from the SAME principal mints a fresh Group_A
		// (a genuinely different welcome) but carries the same clientID.
		XCTAssertThrowsError(try acceptOneWelcome(from: alicePrincipal, into: &invitation))
		{
			error in
			XCTAssertEqual(error as? TwoMLSError, .duplicateWelcome)
		}
	}

	// MARK: - Single-use vs last-resort

	func testSingleUseInvitationIsSpentAfterOneWelcomeAndDropsItsKPMaterialOnRestore() throws {
		let alicePrincipal = try makePrincipal("alice")
		let carolPrincipal = try makePrincipal("carol")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		// Captured before consumption — mirrors two remotes racing to
		// initiate against the same not-yet-consumed published KP; whichever
		// welcome `receive` sees second finds the KP already gone.
		let publishedKP = try XCTUnwrap(invitation.combinerKeyPackage)

		let firstRound = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		XCTAssertNil(invitation.combinerKeyPackage)

		let carolInitiated = try TwoMLSSession.initiate(
			principal: carolPrincipal, their: publishedKP)
		XCTAssertThrowsError(
			try invitation.receive(
				welcome: carolInitiated.welcome,
				theirClassicalKeyPackage: carolInitiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try carolInitiated.session
					.bootstrapKPCommitment(),
				spawnToken: freshSpawnToken())
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invitationSpent)
		}

		let restored = try Invitation.restore(
			archive: firstRound.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertNil(restored.combinerKeyPackage)
	}

	func testLastResortInvitationServicesMultipleDistinctRemotes() throws {
		let alicePrincipal = try makePrincipal("alice")
		let carolPrincipal = try makePrincipal("carol")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)

		_ = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		XCTAssertNotNil(invitation.combinerKeyPackage)
		_ = try acceptOneWelcome(from: carolPrincipal, into: &invitation)
		XCTAssertNotNil(invitation.combinerKeyPackage)
	}

	// MARK: - Restore

	func testAllFourTablesSurviveRestore() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		let expectedGroupID = try XCTUnwrap(round.bob.recvGroup?.classical.context.groupID)
		let untaggedKP = try XCTUnwrap(round.alice.bootstrapKPBytes())

		var restored = try Invitation.restore(
			archive: round.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		XCTAssertEqual(
			restored.forwardGroupID(spawnToken: round.spawnToken), expectedGroupID)
		XCTAssertEqual(
			restored.processedWelcomeGroupID(welcome: round.welcome), expectedGroupID)
		XCTAssertEqual(restored.bootstrapKPGroupID(kpFrame: untaggedKP), expectedGroupID)
		XCTAssertNotNil(restored.combinerKeyPackage)

		// The exact same welcome re-delivered is caught by the
		// processed-welcome ledger.
		XCTAssertThrowsError(
			try restored.receive(
				welcome: round.welcome,
				theirClassicalKeyPackage: round.alice.identity.keyPackage.classical,
				bootstrapKPCommitment: round.bootstrapKPCommitment,
				spawnToken: round.spawnToken)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .duplicateWelcome)
		}

		// A NEW, distinct welcome from the SAME remote isolates the
		// consumed-remote set from the processed-welcome ledger: it has a
		// different digest (so the ledger alone would let it through) but
		// the same remote client id, so only a consumed set that itself
		// survived restore can reject it.
		XCTAssertThrowsError(try acceptOneWelcome(from: alicePrincipal, into: &restored)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .duplicateWelcome)
		}
	}

	// MARK: - Init-secret persistence (PR3a)
	//
	// A published `Invitation` is a durable receiving capability: its KP′
	// init secrets must survive restore, or a restored (never-yet-consumed)
	// invitation can't `receive` at all (`TwoMLSIdentity.classicalJoin-
	// Credentials`/`pqJoinCredentials` throw `.sessionNotReady` once their
	// secret is `nil`).

	/// Headline case: a **last-resort** invitation, archived while
	/// un-consumed, then restored, successfully `receive`s a welcome. This
	/// is the case with no coverage before this test existed — the fix is
	/// `IdentityArchive`'s `includeInitSecrets` control (`SessionArchive.swift`).
	func testRestoredLastResortInvitationCanReceiveAWelcome() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)

		// Archived BEFORE any welcome — the durable, "not yet used" state a
		// freshly-published invitation sits in for most of its life.
		let archive = try invitation.makeInvitationArchive()
		var restored = try Invitation.restore(
			archive: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let round = try acceptOneWelcome(from: alicePrincipal, into: &restored)
		XCTAssertTrue(round.bob.isEstablished)
		XCTAssertFalse(round.alice.isEstablished)
	}

	/// A **single-use** invitation, archived BEFORE its first receive, then
	/// restored, also successfully `receive`s — its init secrets survived
	/// even though the invitation is single-use (not yet consumed, so
	/// nothing has nil'd `identity` yet).
	func testRestoredSingleUseInvitationCanReceiveBeforeItsFirstWelcome() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)

		let archive = try invitation.makeInvitationArchive()
		var restored = try Invitation.restore(
			archive: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let round = try acceptOneWelcome(from: alicePrincipal, into: &restored)
		XCTAssertTrue(round.bob.isEstablished)
		XCTAssertNil(restored.combinerKeyPackage)
	}

	/// A **single-use** invitation that has `receive`d once (consumed —
	/// `identity` nil'd on consume, `Invitation.swift`) still cannot
	/// `receive` again after being archived + restored — the book's
	/// spent-can't-replay property survives restore, `includeInitSecrets`
	/// notwithstanding (there is no identity left to archive secrets from).
	func testRestoredSingleUseInvitationCannotReceiveAgainAfterConsumption() throws {
		let alicePrincipal = try makePrincipal("alice")
		let carolPrincipal = try makePrincipal("carol")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		// Captured before consumption, so a second party can still attempt
		// to initiate against the now-spent published KP.
		let publishedKP = try XCTUnwrap(invitation.combinerKeyPackage)

		let firstRound = try acceptOneWelcome(from: alicePrincipal, into: &invitation)

		var restored = try Invitation.restore(
			archive: firstRound.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertNil(restored.combinerKeyPackage)

		let carolInitiated = try TwoMLSSession.initiate(
			principal: carolPrincipal, their: publishedKP)
		XCTAssertThrowsError(
			try restored.receive(
				welcome: carolInitiated.welcome,
				theirClassicalKeyPackage: carolInitiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try carolInitiated.session
					.bootstrapKPCommitment(),
				spawnToken: freshSpawnToken())
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invitationSpent)
		}
	}

	/// Round-trip functional proof: an un-consumed invitation's archive
	/// carries BOTH KP′ init secrets (`receive` needs both — Group_A is
	/// always a dual-tree `APQGroup.joinFull` join, `classicalJoinCredentials`
	/// AND `pqJoinCredentials`). Drives a restored invitation all the way
	/// through a full bidirectional exchange plus A.3 bootstrap, mirroring
	/// the live happy-path test, so a missing half (only one secret
	/// persisted) would surface here even if it happened to not fail the
	/// simpler headline check.
	func testRestoredInvitationArchiveCarriesBothInitSecretsFullRoundTrip() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)

		let archive = try invitation.makeInvitationArchive()
		var restored = try Invitation.restore(
			archive: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let round = try acceptOneWelcome(from: alicePrincipal, into: &restored)
		var alice = round.alice
		var bob = round.bob
		XCTAssertTrue(bob.isEstablished)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobFrame)
		XCTAssertTrue(alice.isEstablished)

		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-hello".utf8)).frame
		let aliceDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		XCTAssertEqual(aliceDecrypted.applicationMessage, Data("alice-hello".utf8))

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(alice.isFullyEstablished)
		XCTAssertTrue(bob.isFullyEstablished)
	}

	// MARK: - open_initial (slice 9, PR3b)
	//
	// The round-trip, AAD-downgrade, and codec tests live in
	// `EnvelopeTests.swift`; these cover `Invitation.openInitial`'s own
	// decrypt-only / no-consume contract.

	/// `openInitial` is decrypt-only: opening a single-use invitation's
	/// envelope does NOT consume it — `combinerKeyPackage` stays non-nil,
	/// and the invitation is still able to `receive` the very welcome the
	/// opened envelope carried.
	func testOpenInitialDoesNotConsumeASingleUseInvitation() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		let envelope = try initiated.session.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		XCTAssertNotNil(invitation.combinerKeyPackage, "openInitial must not consume")

		var mutableInvitation = invitation
		let returnKP = try MLS.RFC9420.KeyPackage(
			mlsEncoded: try XCTUnwrap(frame.returnKeyPackage))
		let received = try mutableInvitation.receive(
			welcome: try XCTUnwrap(frame.welcome), theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: freshSpawnToken())
		XCTAssertTrue(received.session.isEstablished)
	}

	/// A spent single-use invitation (`identity` nil'd on consume) fails
	/// `openInitial` cleanly with `.invitationSpent`, rather than crash.
	func testOpenInitialFailsCleanlyOnASpentSingleUseInvitation() throws {
		let alicePrincipal = try makePrincipal("alice")
		let carolPrincipal = try makePrincipal("carol")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		// Captured before consumption, so a second party's envelope can
		// still be sealed against the now-spent published KP.
		let publishedKP = try XCTUnwrap(invitation.combinerKeyPackage)
		_ = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		XCTAssertNil(invitation.combinerKeyPackage)

		let carolInitiated = try TwoMLSSession.initiate(
			principal: carolPrincipal, their: publishedKP)
		let envelope = try carolInitiated.session.pendingOutbound()

		XCTAssertThrowsError(try invitation.openInitial(envelope)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invitationSpent)
		}
	}

	/// PR3a made this hold: a restored last-resort invitation's PQ init
	/// secret survives, so a restored (never-yet-consumed) invitation can
	/// both `openInitial` a fresh envelope AND `receive` off it.
	func testRestoredLastResortInvitationCanOpenInitialAndReceive() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)

		let archive = try invitation.makeInvitationArchive()
		var restored = try Invitation.restore(
			archive: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)
		let envelope = try initiated.session.pendingOutbound()

		guard case .establishment(let frame) = try restored.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		let returnKP = try MLS.RFC9420.KeyPackage(
			mlsEncoded: try XCTUnwrap(frame.returnKeyPackage))
		let received = try restored.receive(
			welcome: try XCTUnwrap(frame.welcome), theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: freshSpawnToken())
		XCTAssertTrue(received.session.isEstablished)
	}

	// MARK: - forwarded(spawnToken:)

	func testForwardedSpawnTokenRoutesCorrectlyAndRejectsAMismatch() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)

		XCTAssertNoThrow(try round.bob.forwarded(spawnToken: round.spawnToken))

		let wrongToken = freshSpawnToken()
		XCTAssertThrowsError(try round.bob.forwarded(spawnToken: wrongToken)) { error in
			XCTAssertEqual(error as? TwoMLSError, .misroutedSpawnToken)
		}
	}

	// MARK: - Acceptor baseline restorability

	/// `receive`'s returned `baseline` is a genuine restorable checkpoint the
	/// moment `receive` returns — before any further state-advancing call on
	/// the spawned session, not just a decodable blob.
	func testAcceptorBaselineAloneRestoresAWorkingSession() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)

		XCTAssertEqual(round.baseline.kind, .checkpoint)
		XCTAssertEqual(round.baseline.stateSeq, round.bob.stateSeq)

		var restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: round.baseline.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var alice = round.alice

		let restoredPrepared = try restoredBob.prepareToEncrypt()
		XCTAssertEqual(restoredPrepared.dependsOnSeq, round.baseline.stateSeq)
		let bobFrame = try restoredBob.encrypt(Data("bob-hello".utf8)).frame
		let bobDecrypted = try alice.processIncomingDecrypted(bobFrame)
		XCTAssertEqual(bobDecrypted.applicationMessage, Data("bob-hello".utf8))

		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-hello".utf8)).frame
		let aliceDecrypted = try restoredBob.processIncomingDecrypted(aliceFrame)
		XCTAssertEqual(aliceDecrypted.applicationMessage, Data("alice-hello".utf8))
	}

	/// Baseline PLUS the born-dedicated `installEstablishmentEnvelope` `.core`
	/// splice. `installEstablishmentEnvelope` returns its `.core` at
	/// `baseline.stateSeq + 1`; `restore` (checkpoint older than core)
	/// splices the checkpoint's PQ halves into the newer core, keeping the
	/// rest of core. The acceptor joins Group_A as a full pair
	/// (`APQGroup.joinFull`), so the baseline's `recvGroup.pq` is already
	/// present — only `sendGroup.pq` is nil pre-A.3 — and a `.core` never
	/// carries PQ trees at all, so the splice is what gives the restored
	/// session back Group_A's PQ half. The restored session already has the
	/// handoff installed and owes nothing.
	func testBornDedicatedAcceptorBaselinePlusInstallSpliceRestoresAWorkingSession() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let theirCombinerKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let dedicatedClientID = Data("bob-dedicated".utf8)
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: freshSpawnToken(), newClientID: dedicatedClientID)
		var bob = received.session
		XCTAssertTrue(bob.owesEstablishmentEnvelope)

		let envelope = Data("fake-signed-handoff".utf8)
		let installUpdate = try bob.installEstablishmentEnvelope(envelope)
		XCTAssertEqual(installUpdate.kind, .core)
		XCTAssertEqual(installUpdate.stateSeq, received.baseline.stateSeq + 1)

		var restoredBob = try TwoMLSSession.restore(
			core: installUpdate.archive, checkpoint: received.baseline.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertFalse(restoredBob.owesEstablishmentEnvelope)
		XCTAssertEqual(restoredBob.currentStaple.first, Frames.establishmentHandoffTag)
		// The splice, proven directly: Group_A's PQ half (spliced in from the
		// checkpoint) is back, while Group_B's (never in a `.core`, and nil in
		// the checkpoint too pre-A.3) stays nil.
		XCTAssertNotNil(restoredBob.recvGroup?.pq)
		XCTAssertNil(restoredBob.sendGroup?.pq)

		// Nothing of the peer's to fold on this first prepare, so it never
		// re-installs a staple: `dependsOnSeq` names the last stateSeq this
		// splice actually reconciled to — the INSTALL update's own (splicing
		// keeps the rest of core), not the earlier baseline's.
		let prepared = try restoredBob.prepareToEncrypt()
		XCTAssertEqual(prepared.dependsOnSeq, installUpdate.stateSeq)

		let bobFrame = try restoredBob.encrypt(Data("bob-hello".utf8)).frame

		var alice = initiated.session
		guard case .pendingEstablishment(let pending) = try alice.processIncoming(bobFrame)
		else {
			return XCTFail("expected a pause on the un-approved 0x0B")
		}
		let (envelopeBytes, welcomeBytes) = try Frames.decodeEstablishmentHandoff(
			restoredBob.currentStaple)
		XCTAssertEqual(pending.envelope, envelopeBytes)

		let envelopeDigest = try SessionTestSupport.classicalProvider.hash(envelopeBytes)
		let welcomeDigest = try SessionTestSupport.classicalProvider.hash(welcomeBytes)
		guard
			case .decrypted(let decrypted) = try alice.processIncomingApproved(
				bobFrame, approvedEnvelopeDigest: envelopeDigest,
				approvedWelcomeDigest: welcomeDigest,
				expectedCreator: dedicatedClientID)
		else {
			return XCTFail("expected .decrypted on the approved re-feed")
		}
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-hello".utf8))
		XCTAssertEqual(decrypted.queuedProposal.context, restoredBob.proposalContext())
	}
}
