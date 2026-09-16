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
		bootstrapKPCommitment: Data, archive: SecretArchive
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
			archive: received.archive
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
}
