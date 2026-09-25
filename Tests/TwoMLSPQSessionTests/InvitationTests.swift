import Foundation
import MLSCodec
import MLSCombiner
import MLSProfileRFC9420
import SecretBytes
import Testing

@testable import TwoMLSPQSession

/// `Principal`/`Invitation`, the four tables, single-use vs
/// last-resort, and `Session.forwarded(spawnToken:)` — the app-facing
/// 3-object model layered over the existing identity-based establishment
/// (book concepts.md, session-lifecycle.md's "Invitations & replayed
/// initial frames").
@Suite struct InvitationTests {
	@available(iOS 26, macOS 26, *)
	private func makePrincipal(_ name: String) throws -> Principal {
		try Principal.generate(
			clientID: Data(name.utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	@available(iOS 26, macOS 26, *)
	private func freshSpawnToken() -> Data {
		SessionTestSupport.classicalProvider.randomBytes(16)
	}

	/// Runs one `initiate` -> `receive` round against `invitation`, returning
	/// everything a caller might want to assert on.
	@available(iOS 26, macOS 26, *)
	private func acceptOneWelcome(
		from initiator: Principal, into invitation: inout Invitation
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, welcome: Data, spawnToken: Data,
		bootstrapKPCommitment: Data, archive: SecretArchive, baseline: StateUpdate
	) {
		let theirCombinerKP = try #require(invitation.combinerKeyPackage)
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
	@available(iOS 26, macOS 26, *)
	@Test func invitationReceiveYieldsAWorkingSessionBothDirectionsAndA3Completes() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)

		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		var alice = round.alice
		var bob = round.bob
		#expect(bob.isEstablished)
		#expect(!alice.isEstablished)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobFrame)
		#expect(alice.isEstablished)

		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-hello".utf8)).frame
		let aliceDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		#expect(aliceDecrypted.applicationMessage == Data("alice-hello".utf8))

		_ = try bob.prepareToEncrypt()
		let bobReply = try bob.encrypt(Data("bob-reply".utf8)).frame
		let bobDecrypted = try alice.processIncomingDecrypted(bobReply)
		#expect(bobDecrypted.applicationMessage == Data("bob-reply".utf8))

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		#expect(alice.isFullyEstablished)
		#expect(bob.isFullyEstablished)
	}

	// MARK: - Dedup

	@available(iOS 26, macOS 26, *)
	@Test func redeliveringTheExactSameWelcomeIsDuplicateWelcome() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		let expectedGroupID = try #require(round.bob.recvGroup?.classical.context.groupID)

		#expect(throws: TwoMLSError.duplicateWelcome) {
			try invitation.receive(
				welcome: round.welcome,
				theirClassicalKeyPackage: round.alice.identity.keyPackage.classical,
				bootstrapKPCommitment: round.bootstrapKPCommitment,
				spawnToken: round.spawnToken)
		}

		#expect(
			invitation.processedWelcomeGroupID(welcome: round.welcome)
				== expectedGroupID)
		#expect(
			invitation.forwardGroupID(spawnToken: round.spawnToken) == expectedGroupID)

		// `bootstrapKPGroupID` resolves whether the frame arrives tagged
		// (the `0x13` side-band wire shape) or already untagged (the same
		// preimage `bootstrapKPCommitment()` hashes).
		let untaggedKPRaw = try round.alice.bootstrapKPBytes()
		let untaggedKP = try #require(untaggedKPRaw)
		#expect(invitation.bootstrapKPGroupID(kpFrame: untaggedKP) == expectedGroupID)
		#expect(
			invitation.bootstrapKPGroupID(
				kpFrame: Frames.encodePQBootstrapKP(untaggedKP))
				== expectedGroupID)
	}

	/// A second, DIFFERENT welcome from the same remote (the same principal
	/// initiating a second time) is also `.duplicateWelcome` — the
	/// consumed-remote guard, not the content-keyed one.
	@available(iOS 26, macOS 26, *)
	@Test func aSecondDifferentWelcomeFromTheSameRemoteIsDuplicateWelcome() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		_ = try acceptOneWelcome(from: alicePrincipal, into: &invitation)

		// A second `initiate` from the SAME principal mints a fresh Group_A
		// (a genuinely different welcome) but carries the same clientID.
		#expect(throws: TwoMLSError.duplicateWelcome) {
			try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		}
	}

	// MARK: - Single-use vs last-resort

	@available(iOS 26, macOS 26, *)
	@Test func singleUseInvitationIsSpentAfterOneWelcomeAndDropsItsKPMaterialOnRestore()
		throws
	{
		let alicePrincipal = try makePrincipal("alice")
		let carolPrincipal = try makePrincipal("carol")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		// Captured before consumption — mirrors two remotes racing to
		// initiate against the same not-yet-consumed published KP; whichever
		// welcome `receive` sees second finds the KP already gone.
		let publishedKP = try #require(invitation.combinerKeyPackage)

		let firstRound = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		#expect(invitation.combinerKeyPackage == nil)

		let carolInitiated = try TwoMLSSession.initiate(
			principal: carolPrincipal, their: publishedKP)
		#expect(throws: TwoMLSError.invitationSpent) {
			try invitation.receive(
				welcome: carolInitiated.welcome,
				theirClassicalKeyPackage: carolInitiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try carolInitiated.session
					.bootstrapKPCommitment(),
				spawnToken: freshSpawnToken())
		}

		let restored = try Invitation.restore(
			archive: firstRound.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.combinerKeyPackage == nil)
	}

	@available(iOS 26, macOS 26, *)
	@Test func lastResortInvitationServicesMultipleDistinctRemotes() throws {
		let alicePrincipal = try makePrincipal("alice")
		let carolPrincipal = try makePrincipal("carol")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)

		_ = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		#expect(invitation.combinerKeyPackage != nil)
		_ = try acceptOneWelcome(from: carolPrincipal, into: &invitation)
		#expect(invitation.combinerKeyPackage != nil)
	}

	/// Two sessions accepted off ONE last-resort invitation each found their
	/// own send group on their own fresh leaf: distinct send-classical keys
	/// from the moment each is founded, and — once each independently runs
	/// its own §A.3 — distinct send-PQ keys too. Their RECV keys are equal
	/// by design: both join the SAME invitation KeyPackage, so recv-classical
	/// and recv-PQ share the one published half.
	@available(iOS 26, macOS 26, *)
	@Test func lastResortInvitationSessionsShareNoSendGroupKey() throws {
		let alicePrincipal = try makePrincipal("alice")
		let carolPrincipal = try makePrincipal("carol")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)

		var aliceRound = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		var carolRound = try acceptOneWelcome(from: carolPrincipal, into: &invitation)

		let aliceBobSendKey = try #require(aliceRound.bob.leafKeys.sendClassical.current)
		let carolBobSendKey = try #require(carolRound.bob.leafKeys.sendClassical.current)
		#expect(aliceBobSendKey.signatureKey != carolBobSendKey.signatureKey)

		// recv-classical (the invitation's own published classical half) IS
		// shared, by design.
		#expect(
			aliceRound.bob.leafKeys.recvClassical.current?.signatureKey
				== carolRound.bob.leafKeys.recvClassical.current?.signatureKey)

		// Alice becomes established (and gains a `recvGroup` to run §A.3
		// against) only once she processes bob's first inbound frame.
		_ = try aliceRound.bob.prepareToEncrypt()
		let aliceHello = try aliceRound.bob.encrypt(Data("hi".utf8)).frame
		_ = try aliceRound.alice.processIncomingDecrypted(aliceHello)
		_ = try carolRound.bob.prepareToEncrypt()
		let carolHello = try carolRound.bob.encrypt(Data("hi".utf8)).frame
		_ = try carolRound.alice.processIncomingDecrypted(carolHello)

		// Each session independently runs its own §A.3.
		let aliceKPFrame = try aliceRound.alice.pqBootstrapBegin().frame
		_ = try aliceRound.bob.pqBootstrapRespond(aliceKPFrame)
		let carolKPFrame = try carolRound.alice.pqBootstrapBegin().frame
		_ = try carolRound.bob.pqBootstrapRespond(carolKPFrame)

		let aliceBobSendPQKey = try #require(aliceRound.bob.leafKeys.sendPQ.current)
		let carolBobSendPQKey = try #require(carolRound.bob.leafKeys.sendPQ.current)
		#expect(aliceBobSendPQKey.signatureKey != carolBobSendPQKey.signatureKey)

		// recv-PQ (the invitation's own published PQ half) is shared too.
		#expect(
			aliceRound.bob.leafKeys.recvPQ.current?.signatureKey
				== carolRound.bob.leafKeys.recvPQ.current?.signatureKey)
	}

	// MARK: - Restore

	@available(iOS 26, macOS 26, *)
	@Test func allFourTablesSurviveRestore() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		let expectedGroupID = try #require(round.bob.recvGroup?.classical.context.groupID)
		let untaggedKPRaw = try round.alice.bootstrapKPBytes()
		let untaggedKP = try #require(untaggedKPRaw)

		var restored = try Invitation.restore(
			archive: round.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		#expect(
			restored.forwardGroupID(spawnToken: round.spawnToken) == expectedGroupID)
		#expect(
			restored.processedWelcomeGroupID(welcome: round.welcome) == expectedGroupID)
		#expect(restored.bootstrapKPGroupID(kpFrame: untaggedKP) == expectedGroupID)
		#expect(restored.combinerKeyPackage != nil)

		// The exact same welcome re-delivered is caught by the
		// processed-welcome ledger.
		#expect(throws: TwoMLSError.duplicateWelcome) {
			try restored.receive(
				welcome: round.welcome,
				theirClassicalKeyPackage: round.alice.identity.keyPackage.classical,
				bootstrapKPCommitment: round.bootstrapKPCommitment,
				spawnToken: round.spawnToken)
		}

		// A NEW, distinct welcome from the SAME remote isolates the
		// consumed-remote set from the processed-welcome ledger: it has a
		// different digest (so the ledger alone would let it through) but
		// the same remote client id, so only a consumed set that itself
		// survived restore can reject it.
		#expect(throws: TwoMLSError.duplicateWelcome) {
			try acceptOneWelcome(from: alicePrincipal, into: &restored)
		}
	}

	// MARK: - Init-secret persistence
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
	@available(iOS 26, macOS 26, *)
	@Test func restoredLastResortInvitationCanReceiveAWelcome() throws {
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
		#expect(round.bob.isEstablished)
		#expect(!round.alice.isEstablished)
	}

	/// A **single-use** invitation, archived BEFORE its first receive, then
	/// restored, also successfully `receive`s — its init secrets survived
	/// even though the invitation is single-use (not yet consumed, so
	/// nothing has nil'd `identity` yet).
	@available(iOS 26, macOS 26, *)
	@Test func restoredSingleUseInvitationCanReceiveBeforeItsFirstWelcome() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)

		let archive = try invitation.makeInvitationArchive()
		var restored = try Invitation.restore(
			archive: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let round = try acceptOneWelcome(from: alicePrincipal, into: &restored)
		#expect(round.bob.isEstablished)
		#expect(restored.combinerKeyPackage == nil)
	}

	/// A **single-use** invitation that has `receive`d once (consumed —
	/// `identity` nil'd on consume, `Invitation.swift`) still cannot
	/// `receive` again after being archived + restored — the book's
	/// spent-can't-replay property survives restore, `includeInitSecrets`
	/// notwithstanding (there is no identity left to archive secrets from).
	@available(iOS 26, macOS 26, *)
	@Test func restoredSingleUseInvitationCannotReceiveAgainAfterConsumption() throws {
		let alicePrincipal = try makePrincipal("alice")
		let carolPrincipal = try makePrincipal("carol")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		// Captured before consumption, so a second party can still attempt
		// to initiate against the now-spent published KP.
		let publishedKP = try #require(invitation.combinerKeyPackage)

		let firstRound = try acceptOneWelcome(from: alicePrincipal, into: &invitation)

		var restored = try Invitation.restore(
			archive: firstRound.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.combinerKeyPackage == nil)

		let carolInitiated = try TwoMLSSession.initiate(
			principal: carolPrincipal, their: publishedKP)
		#expect(throws: TwoMLSError.invitationSpent) {
			try restored.receive(
				welcome: carolInitiated.welcome,
				theirClassicalKeyPackage: carolInitiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try carolInitiated.session
					.bootstrapKPCommitment(),
				spawnToken: freshSpawnToken())
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
	@available(iOS 26, macOS 26, *)
	@Test func restoredInvitationArchiveCarriesBothInitSecretsFullRoundTrip() throws {
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
		#expect(bob.isEstablished)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobFrame)
		#expect(alice.isEstablished)

		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-hello".utf8)).frame
		let aliceDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		#expect(aliceDecrypted.applicationMessage == Data("alice-hello".utf8))

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		#expect(alice.isFullyEstablished)
		#expect(bob.isFullyEstablished)
	}

	// MARK: - open_initial
	//
	// The round-trip, AAD-downgrade, and codec tests live in
	// `EnvelopeTests.swift`; these cover `Invitation.openInitial`'s own
	// decrypt-only / no-consume contract.

	/// `openInitial` is decrypt-only: opening a single-use invitation's
	/// envelope does NOT consume it — `combinerKeyPackage` stays non-nil,
	/// and the invitation is still able to `receive` the very welcome the
	/// opened envelope carried.
	@available(iOS 26, macOS 26, *)
	@Test func openInitialDoesNotConsumeASingleUseInvitation() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let theirKP = try #require(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		let envelope = try initiated.session.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope) else {
			Issue.record("expected .establishment")
			return
		}
		#expect(
			invitation.combinerKeyPackage != nil,
			"openInitial must not consume")

		var mutableInvitation = invitation
		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try #require(frame.returnKeyPackage))
		let received = try mutableInvitation.receive(
			welcome: try #require(frame.welcome), theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: freshSpawnToken())
		#expect(received.session.isEstablished)
	}

	/// A spent single-use invitation (`identity` nil'd on consume) fails
	/// `openInitial` cleanly with `.invitationSpent`, rather than crash.
	@available(iOS 26, macOS 26, *)
	@Test func openInitialFailsCleanlyOnASpentSingleUseInvitation() throws {
		let alicePrincipal = try makePrincipal("alice")
		let carolPrincipal = try makePrincipal("carol")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		// Captured before consumption, so a second party's envelope can
		// still be sealed against the now-spent published KP.
		let publishedKP = try #require(invitation.combinerKeyPackage)
		_ = try acceptOneWelcome(from: alicePrincipal, into: &invitation)
		#expect(invitation.combinerKeyPackage == nil)

		let carolInitiated = try TwoMLSSession.initiate(
			principal: carolPrincipal, their: publishedKP)
		let envelope = try carolInitiated.session.pendingOutbound()

		#expect(throws: TwoMLSError.invitationSpent) {
			try invitation.openInitial(envelope)
		}
	}

	/// This holds because invitation archives persist init secrets: a restored last-resort invitation's PQ init
	/// secret survives, so a restored (never-yet-consumed) invitation can
	/// both `openInitial` a fresh envelope AND `receive` off it.
	@available(iOS 26, macOS 26, *)
	@Test func restoredLastResortInvitationCanOpenInitialAndReceive() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try #require(invitation.combinerKeyPackage)

		let archive = try invitation.makeInvitationArchive()
		var restored = try Invitation.restore(
			archive: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)
		let envelope = try initiated.session.pendingOutbound()

		guard case .establishment(let frame) = try restored.openInitial(envelope) else {
			Issue.record("expected .establishment")
			return
		}
		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try #require(frame.returnKeyPackage))
		let received = try restored.receive(
			welcome: try #require(frame.welcome), theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: freshSpawnToken())
		#expect(received.session.isEstablished)
	}

	// MARK: - forwarded(spawnToken:)

	@available(iOS 26, macOS 26, *)
	@Test func forwardedSpawnTokenRoutesCorrectlyAndRejectsAMismatch() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)

		#expect(throws: Never.self) {
			try round.bob.forwarded(spawnToken: round.spawnToken)
		}

		let wrongToken = freshSpawnToken()
		#expect(throws: TwoMLSError.misroutedSpawnToken) {
			try round.bob.forwarded(spawnToken: wrongToken)
		}
	}

	// MARK: - Acceptor baseline restorability

	/// `receive`'s returned `baseline` is a genuine restorable checkpoint the
	/// moment `receive` returns — before any further state-advancing call on
	/// the spawned session, not just a decodable blob.
	@available(iOS 26, macOS 26, *)
	@Test func acceptorBaselineAloneRestoresAWorkingSession() throws {
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let round = try acceptOneWelcome(from: alicePrincipal, into: &invitation)

		#expect(round.baseline.kind == .checkpoint)
		#expect(round.baseline.stateSeq == round.bob.stateSeq)

		var restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: round.baseline.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var alice = round.alice

		let restoredPrepared = try restoredBob.prepareToEncrypt()
		#expect(restoredPrepared.dependsOnSeq == round.baseline.stateSeq)
		let bobFrame = try restoredBob.encrypt(Data("bob-hello".utf8)).frame
		let bobDecrypted = try alice.processIncomingDecrypted(bobFrame)
		#expect(bobDecrypted.applicationMessage == Data("bob-hello".utf8))

		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-hello".utf8)).frame
		let aliceDecrypted = try restoredBob.processIncomingDecrypted(aliceFrame)
		#expect(aliceDecrypted.applicationMessage == Data("alice-hello".utf8))
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
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedAcceptorBaselinePlusInstallSpliceRestoresAWorkingSession()
		throws
	{
		let alicePrincipal = try makePrincipal("alice")
		let bobPrincipal = try makePrincipal("bob")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let theirCombinerKP = try #require(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let dedicatedClientID = Data("bob-dedicated".utf8)
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: freshSpawnToken(), newClientID: dedicatedClientID)
		var bob = received.session
		#expect(bob.owesEstablishmentEnvelope)

		let envelope = Data("fake-signed-handoff".utf8)
		let installUpdate = try bob.installEstablishmentEnvelope(envelope)
		#expect(installUpdate.kind == .core)
		#expect(installUpdate.stateSeq == received.baseline.stateSeq + 1)

		var restoredBob = try TwoMLSSession.restore(
			core: installUpdate.archive, checkpoint: received.baseline.archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(!restoredBob.owesEstablishmentEnvelope)
		#expect(restoredBob.currentStaple.first == Frames.establishmentHandoffTag)
		// The splice, proven directly: Group_A's PQ half (spliced in from the
		// checkpoint) is back, while Group_B's (never in a `.core`, and nil in
		// the checkpoint too pre-A.3) stays nil.
		#expect(restoredBob.recvGroup?.pq != nil)
		#expect(restoredBob.sendGroup?.pq == nil)

		// Nothing of the peer's to fold on this first prepare, so it never
		// re-installs a staple: `dependsOnSeq` names the last stateSeq this
		// splice actually reconciled to — the INSTALL update's own (splicing
		// keeps the rest of core), not the earlier baseline's.
		let prepared = try restoredBob.prepareToEncrypt()
		#expect(prepared.dependsOnSeq == installUpdate.stateSeq)

		let bobFrame = try restoredBob.encrypt(Data("bob-hello".utf8)).frame

		var alice = initiated.session
		guard case .pendingEstablishment(let pending) = try alice.processIncoming(bobFrame)
		else {
			Issue.record("expected a pause on the un-approved 0x0B")
			return
		}
		let (envelopeBytes, welcomeBytes) = try Frames.decodeEstablishmentHandoff(
			restoredBob.currentStaple)
		#expect(pending.envelope == envelopeBytes)

		let envelopeDigest = try SessionTestSupport.classicalProvider.hash(envelopeBytes)
		let welcomeDigest = try SessionTestSupport.classicalProvider.hash(welcomeBytes)
		guard
			case .decrypted(let decrypted) = try alice.processIncomingApproved(
				bobFrame, approvedEnvelopeDigest: envelopeDigest,
				approvedWelcomeDigest: welcomeDigest,
				expectedCreator: dedicatedClientID)
		else {
			Issue.record("expected .decrypted on the approved re-feed")
			return
		}
		#expect(decrypted.applicationMessage == Data("bob-hello".utf8))
		#expect(decrypted.queuedProposal.context == restoredBob.proposalContext())
	}

	// MARK: - D1: a Principal holds no key of its own

	/// A `Principal` mints no key of its own: every `TwoMLSIdentity` it
	/// produces gets its own fresh pair per half. Two invitations from ONE
	/// principal carry four pairwise-distinct KP-half keys (and each
	/// invitation's own classical half is distinct from its own PQ half);
	/// two `initiate(principal:)` sessions from that same principal share no
	/// own-leaf key either.
	@available(iOS 26, macOS 26, *)
	@Test func invitationsFromOnePrincipalShareNoKey() throws {
		let principal = try makePrincipal("carol")

		let (firstInvitation, _) = try principal.generateInvitation(lastResort: false)
		let (secondInvitation, _) = try principal.generateInvitation(lastResort: false)
		let firstKP = try #require(firstInvitation.combinerKeyPackage)
		let secondKP = try #require(secondInvitation.combinerKeyPackage)

		let keys = [
			firstKP.classical.leafNode.signatureKey.data,
			firstKP.pq.leafNode.signatureKey.data,
			secondKP.classical.leafNode.signatureKey.data,
			secondKP.pq.leafNode.signatureKey.data,
		]
		#expect(Set(keys).count == keys.count)

		let bobPrincipal = try makePrincipal("bob-for-carol")
		var (bobInvitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let firstSession = try TwoMLSSession.initiate(
			principal: principal, their: try #require(bobInvitation.combinerKeyPackage)
		)
		_ = try bobInvitation.receive(
			welcome: firstSession.welcome,
			theirClassicalKeyPackage: firstSession.session.identity.keyPackage
				.classical,
			bootstrapKPCommitment: try firstSession.session.bootstrapKPCommitment(),
			spawnToken: freshSpawnToken())

		var (bobInvitation2, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let secondSession = try TwoMLSSession.initiate(
			principal: principal,
			their: try #require(bobInvitation2.combinerKeyPackage))
		_ = try bobInvitation2.receive(
			welcome: secondSession.welcome,
			theirClassicalKeyPackage: secondSession.session.identity.keyPackage
				.classical,
			bootstrapKPCommitment: try secondSession.session.bootstrapKPCommitment(),
			spawnToken: freshSpawnToken())

		let firstOwnKeys = [
			try #require(firstSession.session.leafKeys.sendClassical.current)
				.signatureKey
				.data,
			try #require(firstSession.session.leafKeys.sendPQ.current).signatureKey
				.data,
		]
		let secondOwnKeys = [
			try #require(secondSession.session.leafKeys.sendClassical.current)
				.signatureKey
				.data,
			try #require(secondSession.session.leafKeys.sendPQ.current).signatureKey
				.data,
		]
		#expect(Set(firstOwnKeys).isDisjoint(with: Set(secondOwnKeys)))
	}
}
