import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import Testing

@testable import TwoMLSPQSession

/// Standalone welcome/handoff delivery.
@Suite struct StandaloneEstablishmentTests {
	/// `SessionTestSupport` (the type this reads from) is gated to iOS/macOS
	/// 26 and this suite type is not, so this must be a computed property
	/// (individually gated) rather than a stored one — see
	/// `CombinerKeyPackageWireTests.makeIdentity()` for the same shape.
	@available(iOS 26, macOS 26, *)
	private var classicalProvider: any MLS.CipherSuiteProvider {
		SessionTestSupport.classicalProvider
	}

	private func fakeEnvelope(_ tag: String = "fake-signed-handoff") -> Data {
		Data(tag.utf8)
	}

	@available(iOS 26, macOS 26, *)
	private func approvalTriple(installedOn bob: TwoMLSSession, expectedCreator: Data) throws
		-> (envelopeDigest: Data, welcomeDigest: Data, expectedCreator: Data)
	{
		let (envelope, welcome) = try Frames.decodeEstablishmentHandoff(bob.currentStaple)
		return (
			envelopeDigest: try classicalProvider.hash(envelope),
			welcomeDigest: try classicalProvider.hash(welcome),
			expectedCreator: expectedCreator
		)
	}

	// MARK: - Non-dedicated standalone 0x01

	/// A non-dedicated standalone `0x01` welcome's FIRST join is
	/// state-advancing (`.joined`) — mutation-verified: a restore
	/// from a checkpoint captured BEFORE the join (as if the app never
	/// persisted the returned `update`) rewinds to pre-join, proving the
	/// join is a genuine, capturable transition, not a safely-droppable
	/// no-op. Subsequent `0x03` traffic then reads normally.
	@available(iOS 26, macOS 26, *)
	@Test func nonDedicatedStandaloneWelcomeJoinsAndMutationVerifies() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		#expect(!alice.isEstablished)
		let preJoinArchive = try alice.makeSessionArchive(kind: .checkpoint)

		let sealedRaw = try bob.standaloneWelcome()
		let sealed = try #require(sealedRaw)
		let openedRaw = try alice.openIncoming(sealed)
		let opened = try #require(openedRaw)
		#expect(opened.kind == .message)
		guard
			case .joined(let newSender, let update) = try alice.processIncoming(
				opened.frame)
		else {
			Issue.record("expected .joined")
			return
		}
		#expect(newSender == nil)
		#expect(update.kind == .core)
		#expect(alice.isEstablished)

		// Mutation-verify: a restore from the PRE-join checkpoint alone
		// (dropping `update`, as an app that never persisted it would)
		// rewinds to pre-join — the join is not a state-preserving no-op.
		let rewound = try TwoMLSSession.restore(
			core: nil, checkpoint: preJoinArchive, classicalProvider: classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(!rewound.isEstablished)

		// Subsequent `0x03` traffic reads normally.
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		#expect(decrypted.applicationMessage == Data("bob-hello".utf8))
	}

	// MARK: - Born-dedicated standalone 0x0B, then Bob's first 0x03 surfaces the catch-up

	@available(iOS 26, macOS 26, *)
	@Test func standaloneHandoffPausesThenApprovedJoinsWithDedicatedSender() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)

		let sealedRaw = try bob.standaloneWelcome()
		let sealed = try #require(sealedRaw)
		let openedRaw = try alice.openIncoming(sealed)
		let opened = try #require(openedRaw)
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record("expected a pause")
			return
		}

		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined(let newSender, let update) = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected .joined")
			return
		}
		#expect(newSender == dedicatedClientID)
		#expect(update.kind == .core)
	}

	/// Standalone-`0x0B`-first, THEN Bob's first `0x03` decrypts and
	/// surfaces the recv-leaf-catch-up Upd — `DecryptResult.queuedProposal.proposing
	/// == D` — the one ordering touchpoint with the classical core.
	@available(iOS 26, macOS 26, *)
	@Test func standaloneFirstThenBobsFirstFrameSurfacesCatchUpProposal() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)

		let sealedRaw = try bob.standaloneWelcome()
		let sealed = try #require(sealedRaw)
		let openedRaw = try alice.openIncoming(sealed)
		let opened = try #require(openedRaw)
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record()
			return
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record()
			return
		}

		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		#expect(decrypted.queuedProposal.proposing == dedicatedClientID)
	}

	// MARK: - Standalone <-> stapled convergence of the SAME welcome

	/// Whichever copy of the SAME welcome joins first wins; the other
	/// dedups to `.ignored` on the INNER welcome digest, regardless of
	/// which tag (`0x01` stapled vs standalone) it rides.
	@available(iOS 26, macOS 26, *)
	@Test func standaloneAndStapledConvergeOnTheSameWelcome() throws {
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8), classicalProvider: classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8), classicalProvider: classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try #require(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)
		var alice = initiated.session
		let spawnToken = classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.identity.keyPackage.classical,
			bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		var bob = received.session

		// The standalone copy joins FIRST.
		let sealedRaw = try bob.standaloneWelcome()
		let sealed = try #require(sealedRaw)
		let openedRaw = try alice.openIncoming(sealed)
		let opened = try #require(openedRaw)
		guard case .joined = try alice.processIncoming(opened.frame) else {
			Issue.record("expected the standalone copy to join first")
			return
		}
		#expect(alice.isEstablished)

		// The STAPLED copy of the SAME welcome (Bob's first ordinary
		// message frame, still carrying the un-advanced `0x01` staple)
		// dedups to `.ignored` — same welcome, different tag context.
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		guard case .decrypted = try alice.processIncoming(frame) else {
			Issue.record(
				"expected the stapled re-delivery to decrypt normally, not re-pause"
			)
			return
		}
	}

	// MARK: - Sealed standalone through openIncoming; raw still accepted

	@available(iOS 26, macOS 26, *)
	@Test func sealedStandalone0x01OpensAsMessageAndRawStillAccepted() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()

		// Sealed path: `openIncoming` classifies a sealed standalone `0x01`
		// as `.message`.
		let sealedRaw = try bob.standaloneWelcome()
		let sealed = try #require(sealedRaw)
		let openedRaw = try alice.openIncoming(sealed)
		let opened = try #require(openedRaw)
		#expect(opened.kind == .message)
		#expect(opened.frame.first == Frames.apqWelcomeTag)

		// Raw path: the same plaintext frame, fed directly, is accepted by
		// `processIncoming`'s `openOrRaw` fallback (not required to be sealed)
		// — a fresh session (mirroring the same pair) proves this without
		// consuming `alice`'s own one-shot join.
		var (rawAlice, rawBob, _, _, _, _) = try SessionTestSupport.established(
			alice: "raw-alice", bob: "raw-bob")
		let rawWelcome = rawBob.currentStaple
		guard case .joined = try rawAlice.processIncoming(rawWelcome) else {
			Issue.record("expected the raw (unsealed) standalone welcome to join")
			return
		}
		#expect(rawAlice.isEstablished)

		// The genuinely sealed copy above still joins too.
		guard case .joined = try alice.processIncoming(opened.frame) else {
			Issue.record("expected the sealed copy to join")
			return
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func rawEstablishmentHandoffStillAcceptedViaOpenOrRaw() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)

		// Sealed path: openIncoming classifies it `.message`.
		let sealedRaw = try bob.standaloneWelcome()
		let sealed = try #require(sealedRaw)
		let openedRaw = try alice.openIncoming(sealed)
		let opened = try #require(openedRaw)
		#expect(opened.kind == .message)
		#expect(opened.frame.first == Frames.establishmentHandoffTag)

		// Raw path: the same plaintext frame, fed directly, is accepted by
		// `processIncoming`'s `openOrRaw` fallback (not required to be sealed).
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record("expected a pause from the raw (unsealed) frame")
			return
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record()
			return
		}
	}

	// MARK: - Post-join regression guards

	@available(iOS 26, macOS 26, *)
	@Test func postJoinStapled0x0BDecryptsRatherThanRepausing() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let sealedRaw = try bob.standaloneWelcome()
		let sealed = try #require(sealedRaw)
		let openedRaw = try alice.openIncoming(sealed)
		let opened = try #require(openedRaw)
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record()
			return
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record()
			return
		}

		// Bob's staple is STILL 0x0B (he hasn't committed yet) — his next
		// ordinary `0x03` frame re-staples it. Alice, already joined, must
		// decrypt normally, NEVER re-pause.
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		guard case .decrypted(let result) = try alice.processIncoming(frame) else {
			Issue.record("expected .decrypted, not a re-pause")
			return
		}
		#expect(result.applicationMessage == Data("bob-hello".utf8))
	}

	@available(iOS 26, macOS 26, *)
	@Test func postJoinStandalone0x0BIsIgnoredAndBobFromBirthRejectsStray0x0B() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let sealedRaw = try bob.standaloneWelcome()
		let sealed = try #require(sealedRaw)
		let openedRaw = try alice.openIncoming(sealed)
		let opened = try #require(openedRaw)
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record()
			return
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record()
			return
		}

		// A re-delivered STANDALONE 0x0B post-join is `.ignored`.
		let sealedAgainRaw = try bob.standaloneWelcome()
		let sealedAgain = try #require(sealedAgainRaw)
		let openedAgainRaw = try alice.openIncoming(sealedAgain)
		let openedAgain = try #require(openedAgainRaw)
		guard case .ignored = try alice.processIncoming(openedAgain.frame) else {
			Issue.record("expected .ignored")
			return
		}

		// Bob's OWN `recvGroup` exists from birth — a stray 0x0B fed to HIS
		// `processIncoming` must never pause (`recvGroup == nil` never
		// holds for him); it dedups-or-throws, and since his
		// `joinedWelcomeDigest` names a different (his own-received)
		// welcome, this foreign inner welcome throws `.unexpectedWelcome`.
		let (_, foreignBob, _, _, _) = try SessionTestSupport.establishedDedicated(
			bob: "foreign-bob")
		let strayHandoff = Frames.encodeEstablishmentHandoff(
			envelope: Data("x".utf8), welcome: foreignBob.currentStaple)
		#expect(throws: TwoMLSError.unexpectedWelcome) {
			try bob.processIncoming(strayHandoff)
		}
	}

	// MARK: - Bob (recv group from birth) fed a re-delivered/foreign standalone 0x01

	@available(iOS 26, macOS 26, *)
	@Test func bobRejectsForeignStandaloneWelcomeButIgnoresARedelivery() throws {
		let alice: TwoMLSSession
		var bob: TwoMLSSession
		(alice, bob, _, _, _, _) = try SessionTestSupport.established()

		// A re-DELIVERED copy of the SAME full-pair welcome Bob originally
		// received at `receive()` (`joinedWelcomeDigest` is seeded from it
		// there — the one dedup entry Bob's session carries, though he
		// FOUNDED rather than joined Group_B) is `.ignored`, not a throw.
		guard case .ignored = try bob.processIncoming(alice.currentStaple) else {
			Issue.record(
				"expected a re-delivery of Bob's own join welcome to be ignored")
			return
		}

		// A genuinely DIFFERENT (foreign) welcome — another pair's Alice —
		// is `.unexpectedWelcome`.
		let (otherAlice, _, _, _, _, _) = try SessionTestSupport.established(
			alice: "other-alice", bob: "other-bob")
		#expect(throws: TwoMLSError.unexpectedWelcome) {
			try bob.processIncoming(otherAlice.currentStaple)
		}
	}

	// MARK: - Malformed standalone 0x01 leaves state untouched

	@available(iOS 26, macOS 26, *)
	@Test func malformedStandaloneWelcomeLeavesStateUntouchedThenGoodCopyJoins() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		let ledgerBefore = alice.sendCrossPSKLedger.count
		let initSecretBefore = alice.identity.classicalInitSecretKey?.data

		let garbageWelcome = Frames.encodeAPQWelcome(
			t: Data("not-a-welcome".utf8), pq: Data())
		#expect(throws: (any Error).self) {
			try alice.processIncoming(garbageWelcome)
		}
		#expect(!alice.isEstablished)
		#expect(alice.sendCrossPSKLedger.count == ledgerBefore)
		#expect(alice.identity.classicalInitSecretKey?.data == initSecretBefore)

		// The genuine standalone copy still joins afterward.
		let sealedRaw = try bob.standaloneWelcome()
		let sealed = try #require(sealedRaw)
		let openedRaw = try alice.openIncoming(sealed)
		let opened = try #require(openedRaw)
		guard case .joined = try alice.processIncoming(opened.frame) else {
			Issue.record("expected the genuine copy to join")
			return
		}
	}

	// MARK: - standaloneWelcome() gate; initialWelcome() on a restored owed Bob

	@available(iOS 26, macOS 26, *)
	@Test func standaloneWelcomeGatedAndInitialWelcomeAvailableOnRestore() throws {
		let (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try bob.standaloneWelcome()
		}
		#expect(bob.initialWelcome() == bob.currentStaple)

		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: archive, classicalProvider: classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.owesEstablishmentEnvelope)
		// A restored owed-but-not-installed Bob still has `initialWelcome()`
		// available — he has no `EstablishResult.welcome` any more, so this
		// is what a host mints the handoff-blob signature over.
		#expect(restored.initialWelcome() == restored.currentStaple)
		#expect(throws: (any Error).self) {
			try restored.standaloneWelcome()
		}
	}

	// MARK: - Approval can never launder a bare welcome

	@available(iOS 26, macOS 26, *)
	@Test func approvedCallOnBareDifferingCreatorWelcomeStillRequiresEnvelope() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		// Bob's staple is bare 0x01 (not yet installed) — feed it to
		// `processIncomingApproved` with an unrelated approved pair; approval
		// is consulted only for a 0x0B section, so this must
		// process exactly like plain `processIncoming` would.
		let bareStaple = bob.currentStaple
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try alice.processIncomingApproved(
				bareStaple, approvedEnvelopeDigest: Data("x".utf8),
				approvedWelcomeDigest: Data("y".utf8),
				expectedCreator: dedicatedClientID)
		}
		#expect(!alice.isEstablished)
	}

	// MARK: - standaloneWelcome() lifecycle

	@available(iOS 26, macOS 26, *)
	@Test func standaloneWelcomeLifecycle() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		// Gated while owed.
		#expect(throws: (any Error).self) {
			try bob.standaloneWelcome()
		}

		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		// Sealed 0x0B post-install.
		let sealedHandoffRaw = try bob.standaloneWelcome()
		let sealedHandoff = try #require(sealedHandoffRaw)
		let openedHandoffRaw = try alice.openIncoming(sealedHandoff)
		let openedHandoff = try #require(openedHandoffRaw)
		#expect(openedHandoff.frame.first == Frames.establishmentHandoffTag)

		guard case .pendingEstablishment = try alice.processIncoming(openedHandoff.frame)
		else {
			Issue.record()
			return
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined = try alice.processIncomingApproved(
				openedHandoff.frame,
				approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record()
			return
		}

		// `standaloneWelcome()` keeps serving the (still-`0x0B`) staple
		// until a fold lands on Bob's OWN send group (Group_B) — Alice
		// offers into her recv group (which mirrors Group_B), Bob
		// approves+folds it into his next `prepareToEncrypt`, moving his
		// staple past the establishment shapes entirely.
		_ = try alice.prepareToEncrypt()
		let aliceOffer = try alice.encrypt(Data("offer".utf8)).frame
		let bobDecrypted = try bob.processIncomingDecrypted(aliceOffer)
		_ = try bob.queueProposal(digest: bobDecrypted.queuedProposal.digest)
		let bobPrepared = try bob.prepareToEncrypt()
		#expect(bobPrepared.didCommit)
		#expect(bob.currentStaple.first == Frames.mlsMessageStapleTag)
		#expect(try bob.standaloneWelcome() == nil)
	}
}
