import Foundation
import MLSCodec
import MLSProfileRFC9420
import Testing

@testable import TwoMLSPQSession

/// §A.3 parallel pre-delivery (book protocol-flows.md §A.1 "Envelope
/// framing & parallel KP′ delivery", §A.3 "Parallel pre-delivery") and the
/// acceptor's re-serve rule.
@Suite struct ParallelBootstrapTests {
	@available(iOS 26, macOS 26, *)
	private typealias Support = SessionTestSupport

	@available(iOS 26, macOS 26, *)
	private func initiateAgainstInvitation(lastResort: Bool = false) throws -> (
		initiated: EstablishResult, invitation: Invitation
	) {
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8), classicalProvider: Support.classicalProvider,
			pqProvider: Support.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8), classicalProvider: Support.classicalProvider,
			pqProvider: Support.pqProvider)
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: lastResort)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal,
			their: try #require(invitation.combinerKeyPackage))
		return (initiated, invitation)
	}

	@available(iOS 26, macOS 26, *)
	private func receive(
		_ initiated: EstablishResult, into invitation: inout Invitation
	) throws -> TwoMLSSession {
		try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: Support.classicalProvider.randomBytes(16)
		).session
	}

	@available(iOS 26, macOS 26, *)
	@Test func initiateRegistersTheRoundAroundTheCommittedKP() throws {
		let (initiated, invitation) = try initiateAgainstInvitation()
		let alice = initiated.session
		guard case .bootstrapInitiated = alice.pqInflight else {
			Issue.record("expected .bootstrapInitiated at initiate")
			return
		}
		let rawKP = try alice.bootstrapKPBytes()
		let kp = try #require(rawKP)
		#expect(alice.pendingSideBand == Frames.encodePQBootstrapKP(kp))
		#expect(
			try Support.classicalProvider.hash(kp)
				== (try alice.bootstrapKPCommitment())
		)

		guard
			case .bootstrapKP(let beforeRestartFrame) = try invitation.openInitial(
				try #require(alice.pqBootstrapEnvelope()))
		else {
			Issue.record("expected .bootstrapKP")
			return
		}

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: initiated.baseline.archive,
			classicalProvider: Support.classicalProvider, pqProvider: Support.pqProvider
		)
		guard case .bootstrapInitiated = restored.pqInflight else {
			Issue.record("expected the registered round to ride the baseline")
			return
		}
		#expect(restored.pendingSideBand == alice.pendingSideBand)

		// The restored pre-join initiator can still ship the parked KP′ —
		// it opens (with the acceptor's own invitation opener) to the same
		// `[0x13][KP′]` frame it produced before the restart.
		guard
			case .bootstrapKP(let afterRestoreFrame) = try invitation.openInitial(
				try #require(restored.pqBootstrapEnvelope()))
		else {
			Issue.record("expected .bootstrapKP")
			return
		}
		#expect(afterRestoreFrame == beforeRestartFrame)
	}

	@available(iOS 26, macOS 26, *)
	@Test func envelopeIsAPureFreshlySealedReadOfTheRetainedFrame() throws {
		var (initiated, invitation) = try initiateAgainstInvitation()
		let alice = initiated.session
		let seqBefore = alice.stateSeq
		let first = try #require(alice.pqBootstrapEnvelope())
		let second = try #require(alice.pqBootstrapEnvelope())
		#expect(first != second)
		#expect(alice.stateSeq == seqBefore)
		for blob in [first, second] {
			guard case .bootstrapKP(let frame) = try invitation.openInitial(blob) else {
				Issue.record("expected .bootstrapKP")
				return
			}
			#expect(frame == alice.pendingSideBand)
		}
		// The reply and the KP′ share one outer shape; only the inner tag
		// tells them apart.
		guard case .establishment = try invitation.openInitial(try alice.pendingOutbound())
		else {
			Issue.record("expected .establishment")
			return
		}

		var bob = try receive(initiated, into: &invitation)
		#expect(bob.pqBootstrapEnvelope() == nil)
		_ = try bob.prepareToEncrypt()
		_ = bob
	}

	@available(iOS 26, macOS 26, *)
	@Test func envelopeStopsAtTheCutoverAndTheSideBandTakesOver() throws {
		var (initiated, invitation) = try initiateAgainstInvitation()
		var alice = initiated.session
		var bob = try receive(initiated, into: &invitation)
		#expect(alice.pqPendingOutbound() == nil)
		_ = try bob.prepareToEncrypt()
		_ = try alice.processIncomingDecrypted(try bob.encrypt(Data("b1".utf8)).frame)

		#expect(alice.pqBootstrapEnvelope() == nil)
		let steady = try #require(alice.pqPendingOutbound())
		#expect(bob.openOrRaw(steady) == alice.pendingSideBand)
		let begun = try alice.pqBootstrapBegin()
		#expect(bob.openOrRaw(begun.frame) == alice.pendingSideBand)
		#expect(begun.update.kind == .core)
	}

	@available(iOS 26, macOS 26, *)
	@Test func earlyWelcomeIsRetriableUntilTheGroupBJoin() throws {
		var (initiated, invitation) = try initiateAgainstInvitation()
		var alice = initiated.session
		guard
			case .bootstrapKP(let held) = try invitation.openInitial(
				try #require(alice.pqBootstrapEnvelope()))
		else {
			Issue.record("expected .bootstrapKP")
			return
		}
		var bob = try receive(initiated, into: &invitation)
		#expect(
			invitation.bootstrapKPGroupID(kpFrame: held)
				== bob.recvGroup?.classical.context.groupID)

		let welcome = try bob.pqBootstrapRespond(held)
		#expect(welcome.update.kind == .checkpoint)

		// Opens under alice's own Group_A.pq window, but there is nothing to
		// join into yet.
		let rawOpened = try alice.openIncoming(welcome.frame)
		let opened = try #require(rawOpened)
		#expect(opened.kind == .pqSideBand(.bootstrapWelcome))
		let seqBefore = alice.stateSeq
		#expect(throws: TwoMLSError.sessionNotReady) {
			try alice.pqBootstrapJoin(opened.frame)
		}
		#expect(alice.stateSeq == seqBefore)
		#expect(alice.bootstrapKPSecret != nil)

		_ = try bob.prepareToEncrypt()
		_ = try alice.processIncomingDecrypted(try bob.encrypt(Data("b1".utf8)).frame)
		_ = try alice.pqBootstrapJoin(opened.frame)
		#expect(alice.isFullyEstablished)
		#expect(bob.isFullyEstablished)

		_ = try alice.prepareToEncrypt()
		let bound = try alice.encrypt(Data("a1".utf8))
		#expect(alice.owedBind == nil)
		let applied = try bob.processIncomingDecrypted(bound.frame)
		#expect(applied.didApplyRemoteCommit)
		#expect(bob.myPQTurn)
	}

	@available(iOS 26, macOS 26, *)
	@Test func respondReServesOnlyWhileItsRoundIsOpen() throws {
		var (alice, bob) = try Support.establishedAndExchanged()
		let kp = try alice.pqBootstrapBegin().frame
		let first = try bob.pqBootstrapRespond(kp)

		// Round open: the SAME Welcome′ again.
		let again = try bob.pqBootstrapRespond(kp)
		#expect(alice.openOrRaw(first.frame) == alice.openOrRaw(again.frame))
		#expect(first.update.kind == .checkpoint)
		#expect(again.update.kind == .core)

		// Garbage or a wrong KP′ never earns a re-serve.
		let seq = bob.stateSeq
		#expect(throws: (any Error).self) {
			try bob.pqBootstrapRespond(Data([0x42, 0x01]))
		}
		#expect(throws: TwoMLSError.bootstrapKPMismatch) {
			try bob.pqBootstrapRespond(Frames.encodePQBootstrapKP(Data("other".utf8)))
		}
		#expect(bob.stateSeq == seq)

		_ = try alice.pqBootstrapJoin(first.frame)
		_ = try alice.prepareToEncrypt()
		_ = try bob.processIncomingDecrypted(try alice.encrypt(Data("bind".utf8)).frame)
		#expect(bob.pqInflight == nil)

		// Round closed: refused, with nothing moved.
		let closedSeq = bob.stateSeq
		#expect(throws: TwoMLSError.duplicateSideBand) {
			try bob.pqBootstrapRespond(kp)
		}
		#expect(bob.stateSeq == closedSeq)

		// The next round opened on bob's send: still refused, and the parked
		// leg is not handed out as if it answered the KP′.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("b2".utf8))
		let parked = try #require(bob.pendingSideBand)
		#expect(throws: TwoMLSError.duplicateSideBand) {
			try bob.pqBootstrapRespond(kp)
		}
		#expect(bob.pendingSideBand == parked)
	}

	/// An initiator handed her own reflected KP′ (her founded send-PQ half
	/// used to route this into the re-serve branch, handing back her own
	/// `0x13`) — she is never a responder, so the commitment check always
	/// fails closed instead.
	@available(iOS 26, macOS 26, *)
	@Test func initiatorRefusesItsOwnReflectedKP() throws {
		var (alice, bob) = try Support.establishedAndExchanged()
		_ = try alice.pqBootstrapBegin()
		let ownFrame = try #require(alice.pendingSideBand)
		let pendingBefore = alice.pendingSideBand
		let seqBefore = alice.stateSeq

		#expect(throws: TwoMLSError.bootstrapKPMismatch) {
			try alice.pqBootstrapRespond(ownFrame)
		}
		#expect(alice.pendingSideBand == pendingBefore)
		#expect(alice.stateSeq == seqBefore)
		_ = bob
	}
}
