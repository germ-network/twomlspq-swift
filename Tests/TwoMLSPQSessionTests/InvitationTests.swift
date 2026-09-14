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
		_ = try alice.processIncoming(bobFrame)
		XCTAssertTrue(alice.isEstablished)

		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-hello".utf8)).frame
		let aliceDecrypted = try bob.processIncoming(aliceFrame)
		XCTAssertEqual(aliceDecrypted.applicationMessage, Data("alice-hello".utf8))

		_ = try bob.prepareToEncrypt()
		let bobReply = try bob.encrypt(Data("bob-reply".utf8)).frame
		let bobDecrypted = try alice.processIncoming(bobReply)
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

		XCTAssertThrowsError(
			try restored.receive(
				welcome: round.welcome,
				theirClassicalKeyPackage: round.alice.identity.keyPackage.classical,
				bootstrapKPCommitment: round.bootstrapKPCommitment,
				spawnToken: round.spawnToken)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .duplicateWelcome)
		}
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
