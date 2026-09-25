import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import Testing

@testable import TwoMLSPQSession

/// Born-dedicated principal + signed delegation handoff. Covers accept,
/// standalone-delivery, and reject/tamper cases for the handoff.
@Suite struct BornDedicatedTests {
	@available(iOS 26, macOS 26, *)
	private var classicalProvider: any MLS.CipherSuiteProvider {
		SessionTestSupport.classicalProvider
	}

	/// A stand-in for the host's signed handoff blob — this
	/// module treats `envelope` as opaque bytes (the signature verification
	/// is the host's job, out of band, before ever calling
	/// `installEstablishmentEnvelope`/`processIncomingApproved`), so any
	/// fixed byte string exercises the wire mechanics faithfully.
	private func fakeEnvelope(_ tag: String = "fake-signed-handoff") -> Data {
		Data(tag.utf8)
	}

	/// The (envelope, welcome) digest pair + creator `processIncomingApproved`
	/// needs, read straight off `bob`'s installed `0x0B` staple.
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

	/// The full round-trip (accept 1) as a shared fixture for the tests that
	/// need a fully-established, D-adopted pair: establish dedicated,
	/// install, deliver standalone, and approve.
	@available(iOS 26, macOS 26, *)
	private func fullyEstablishedDedicated(
		dedicatedClientID: Data = Data("bob-dedicated".utf8),
		profile: SessionProfile = .deployedCompatible
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, invitationClientID: Data,
		dedicatedClientID: Data, envelope: Data
	) {
		try SessionTestSupport.establishedDedicatedAndApproved(
			dedicatedClientID: dedicatedClientID, profile: profile)
	}

	// MARK: - Accept 1: full round-trip

	@available(iOS 26, macOS 26, *)
	@Test func fullBornDedicatedRoundTrip() throws {
		var (alice, bob, _, invitationClientID, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		#expect(bob.owesEstablishmentEnvelope)
		#expect(bob.identity.clientID == invitationClientID)
		#expect(bob.myPrincipalState == .sync(dedicatedClientID))
		#expect(bob.leafKeys.recvClassical.pending[dedicatedClientID] != nil)
		#expect(bob.currentStaple.first == Frames.apqWelcomeTag)

		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		#expect(!bob.owesEstablishmentEnvelope)
		#expect(bob.currentStaple.first == Frames.establishmentHandoffTag)
		let (installedEnvelope, installedWelcome) = try Frames.decodeEstablishmentHandoff(
			bob.currentStaple)
		#expect(installedEnvelope == envelope)
		#expect(installedWelcome.first == Frames.apqWelcomeTag)

		// Bob's 0x0B staple travels stapled on his first frame — but Bob
		// cannot even build one without a proposal staged (`prepareToEncrypt`
		// first); before that, deliver it standalone.
		let standalone = try #require(try bob.standaloneWelcome())
		let opened = try #require(try alice.openIncoming(standalone))
		#expect(opened.kind == .message)
		#expect(opened.frame.first == Frames.establishmentHandoffTag)

		guard
			case .pendingEstablishment(let pending) = try alice.processIncoming(
				opened.frame)
		else {
			Issue.record("expected a pause on the un-approved 0x0B")
			return
		}
		#expect(pending.envelope == envelope)
		#expect(pending.welcome == installedWelcome)
		#expect(!alice.isEstablished)

		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined(let newSender, let update) = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected .joined on the approved re-feed")
			return
		}
		#expect(newSender == dedicatedClientID)
		#expect(update.kind == .core)
		#expect(alice.isEstablished)
		#expect(alice.auth.theirs.current == dedicatedClientID)

		// 0x0B byte-exact round-trip: what Bob installed decodes back to
		// exactly the envelope+welcome pair Alice's pause/approval saw.
		#expect(pending.envelope == installedEnvelope)
		#expect(pending.welcome == installedWelcome)
	}

	// MARK: - Accept 2: degenerate topology unchanged

	@available(iOS 26, macOS 26, *)
	@Test func degenerateNewClientIDMatchesInvitationIsUnchanged() throws {
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		guard let theirCombinerKP = invitation.combinerKeyPackage else {
			Issue.record("expected a combiner key package")
			return
		}
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let spawnToken = classicalProvider.randomBytes(16)

		// `newClientID` explicitly equal to the invitation identity.
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken, newClientID: Data("bob".utf8))
		#expect(!received.session.owesEstablishmentEnvelope)
		#expect(received.session.leafKeys.recvClassical.pending.isEmpty)
		#expect(received.session.currentStaple.first == Frames.apqWelcomeTag)
		#expect(received.session.identity.clientID == Data("bob".utf8))
	}

	@available(iOS 26, macOS 26, *)
	@Test func nilNewClientIDMatchesInvitationIsUnchanged() throws {
		let (_, bob, _, _, _, _) = try SessionTestSupport.established()
		#expect(!bob.owesEstablishmentEnvelope)
		#expect(bob.leafKeys.recvClassical.pending.isEmpty)
		#expect(bob.currentStaple.first == Frames.apqWelcomeTag)
	}

	// MARK: - Accept 3: recv-leaf catch-up

	/// Bob's Group_A CLASSICAL leaf converges inv → D via the first
	/// committed Upd: his own `prepareToEncrypt` implicitly stages the
	/// catch-up, Alice approves+folds it, and Bob's own apply of
	/// that fold canonicalizes his leaf — a no-op-safe `mine.commit`, since
	/// `auth.mine` was already D from `receive`, so it admits cleanly. recv-PQ is NOT caught up by this alone:
	/// `recvGroup.pq`'s leaf still independently presents the invitation
	/// identity until the PQ catch-up moves it.
	@available(iOS 26, macOS 26, *)
	@Test func recvLeafCatchUpConvergesInvToD() throws {
		var (alice, bob, invitationClientID, dedicatedClientID, _) =
			try fullyEstablishedDedicated()
		#expect(bob.leafKeys.recvClassical.pending[dedicatedClientID] != nil)
		#expect(bob.myPrincipalState == .sync(dedicatedClientID))
		let recvClassicalBefore = try #require(bob.recvGroup?.classical)
		let leafBefore = try TwoMLSSession.ownLeaf(of: recvClassicalBefore)
		#expect(try basicIdentifier(leafBefore.credential) == invitationClientID)

		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		#expect(decrypted.queuedProposal.proposing == dedicatedClientID)

		_ = try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		let alicePrepared = try alice.prepareToEncrypt()
		#expect(alicePrepared.didCommit)
		#expect(alicePrepared.committedRemoteClientID == dedicatedClientID)

		let aliceFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		let bobDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		#expect(bobDecrypted.didApplyRemoteCommit)
		#expect(bobDecrypted.ownCredentialCanonicalized)

		let recvPQGroup = try #require(bob.recvGroup?.pq)
		let recvPQLeaf = try TwoMLSSession.ownLeaf(of: recvPQGroup)
		#expect(try basicIdentifier(recvPQLeaf.credential) == invitationClientID)
		let recvClassicalAfter = try #require(bob.recvGroup?.classical)
		let leafAfter = try TwoMLSSession.ownLeaf(of: recvClassicalAfter)
		#expect(try basicIdentifier(leafAfter.credential) == dedicatedClientID)
	}

	// MARK: - Accept 6: A.3 founds Group_B.pq under D

	@available(iOS 26, macOS 26, *)
	@Test func bootstrapFoundsGroupBPQUnderDedicatedPrincipal() throws {
		var (alice, bob, _, dedicatedClientID, _) = try fullyEstablishedDedicated()
		let begin = try alice.pqBootstrapBegin()
		let respond = try bob.pqBootstrapRespond(begin.frame)
		_ = try alice.pqBootstrapJoin(respond.frame)
		#expect(bob.isFullyEstablished)

		let pqGroup = try #require(bob.sendGroup?.pq)
		let creatorLeaf = try TwoMLSSession.ownLeaf(of: pqGroup)
		#expect(try basicIdentifier(creatorLeaf.credential) == dedicatedClientID)
	}

	// MARK: - Accept 7: PQ signing resolver correctness, and the recv-PQ catch-up

	/// Bob's `pqRekeyBegin` proposes into `recvGroup.pq` (Group_A.pq, still
	/// presenting the invitation identity I pre-PQ-catch-up) — the PQ
	/// custody resolver (`recvPQSigningKey`) must sign under the retained
	/// invitation key so Alice's `pqRekeyRespond` verifies it. His own
	/// `auth.mine.current` is already D (the classical side converged at
	/// approval), so the Upd′ now moves the leaf I→D directly — the native
	/// twin of the TwoMLSPQ cross-engine flip. Kills: targeting the
	/// presented id (I) instead of `mine.current` (D); pins not retiring.
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedAcceptorRecvPQCatchesUpToDedicatedID() throws {
		for profile in [SessionProfile.deployedCompatible, .correct] {
			var (alice, bob, invitationClientID, dedicatedClientID, _) =
				try fullyEstablishedDedicated(profile: profile)

			// License Alice + drive Bob's recv-leaf catch-up in one stroke,
			// mirroring `RatchetTests.fullyEstablishedTurnOnBob()`'s own
			// bootstrap-then-license recipe (a queued fold requires
			// Alice to have seen at least one of Bob's send epochs).
			_ = try bob.prepareToEncrypt()
			let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
			let decrypted = try alice.processIncomingDecrypted(bobFrame)
			_ = try alice.queueProposal(digest: decrypted.queuedProposal.digest)
			_ = try alice.prepareToEncrypt()
			let aliceFoldFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
			_ = try bob.processIncomingDecrypted(aliceFoldFrame)

			// Alice's fold above advanced her `sendGroup.classical` epoch, so
			// the earlier license is now stale — Bob sends once more at the
			// NEW epoch to re-stamp `peerAppliedSendEpoch` fresh before the A.3
			// discharge below relies on it.
			_ = try bob.prepareToEncrypt()
			let bobFrame2 = try bob.encrypt(Data("bob-hello-2".utf8)).frame
			_ = try alice.processIncomingDecrypted(bobFrame2)

			let begin = try alice.pqBootstrapBegin()
			let respond = try bob.pqBootstrapRespond(begin.frame)
			_ = try alice.pqBootstrapJoin(respond.frame)
			#expect(bob.isFullyEstablished)

			// Already licensed (Bob's catch-up frame above) — Alice's very next
			// round discharges the owed A.3 bind immediately, flipping the turn.
			_ = try alice.prepareToEncrypt()
			let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
			_ = try bob.processIncomingDecrypted(boundFrame)
			#expect(bob.myPQTurn)

			#expect(bob.auth.mine.current == dedicatedClientID)
			let recvPQGroupBefore = try #require(bob.recvGroup?.pq)
			let recvPQBefore = try TwoMLSSession.ownLeaf(of: recvPQGroupBefore)
			#expect(try basicIdentifier(recvPQBefore.credential) == invitationClientID)

			// Bob's Upd′ proposes into `recvGroup.pq` (Group_A.pq), signed
			// under the retained invitation key `leafKeys.recvPQ.current`
			// still holds, and carries D as the leaf's new credential — Alice's
			// `pqRekeyRespond`, which owns that group as her `sendGroup.pq`,
			// verifies it and reports the move.
			let rekeyBegin = try bob.pqRekeyBegin()
			// C1: only the deployed-compatible profile announces the
			// handed-off id; the correct profile's Upd′ carries none.
			let updBytes = try Frames.decodePQRekeyUpd(
				alice.openOrRaw(rekeyBegin.frame))
			guard
				case .publicMessage(let updPub) = try MLS.RFC9420.Message(
					mlsEncoded: updBytes)
			else {
				Issue.record("expected a publicMessage-framed Upd′")
				return
			}
			#expect(
				updPub.content.authenticatedData
					== (profile == .correct ? Data() : dedicatedClientID),
				"\(profile)")

			let rekeyRespond = try alice.pqRekeyRespond(rekeyBegin.frame)
			#expect(rekeyRespond.rotatedCredential == dedicatedClientID, "\(profile)")

			#expect(throws: Never.self) { try bob.pqRekeyApply(rekeyRespond.frame) }
			let recvPQGroupAfter = try #require(bob.recvGroup?.pq)
			let recvPQAfter = try TwoMLSSession.ownLeaf(of: recvPQGroupAfter)
			#expect(
				try basicIdentifier(recvPQAfter.credential) == dedicatedClientID,
				"\(profile)"
			)

			// Neither side still pins I: bob's send-PQ was founded under D
			// already, and his recv-PQ has now caught up too.
			#expect(!bob.auth.mine.pinned.contains(invitationClientID))
			#expect(!alice.auth.theirs.pinned.contains(invitationClientID))
		}
	}

	// MARK: - Accept 7 (self-driven): the own-arm gate

	/// `fullyEstablishedDedicated()`, licensed and bootstrapped exactly as
	/// `testBornDedicatedAcceptorRecvPQCatchesUpToDedicatedID` does, up to
	/// the point bob holds the PQ turn with his recv-PQ leaf still
	/// presenting the invitation id.
	@available(iOS 26, macOS 26, *)
	private func bobHoldingPQTurnWithRecvPQLaggingInvitationID() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, invitationClientID: Data,
		dedicatedClientID: Data
	) {
		var (alice, bob, invitationClientID, dedicatedClientID, _) =
			try fullyEstablishedDedicated()

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(bobFrame)
		_ = try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let aliceFoldFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(aliceFoldFrame)

		_ = try bob.prepareToEncrypt()
		let bobFrame2 = try bob.encrypt(Data("bob-hello-2".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobFrame2)

		let begin = try alice.pqBootstrapBegin()
		let respond = try bob.pqBootstrapRespond(begin.frame)
		_ = try alice.pqBootstrapJoin(respond.frame)
		#expect(bob.isFullyEstablished)

		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)
		#expect(bob.myPQTurn)

		let recvPQGroup = try #require(bob.recvGroup?.pq)
		let recvPQ = try TwoMLSSession.ownLeaf(of: recvPQGroup)
		#expect(try basicIdentifier(recvPQ.credential) == invitationClientID)

		return (alice, bob, invitationClientID, dedicatedClientID)
	}

	/// Even though bob's own recv-PQ leaf lags, his own catch-up A.5 opens
	/// only once the peer has folded the TARGET his `Upd′` would carry —
	/// observed as his own leaf in `recvGroup.classical` already presenting
	/// `mine.current`. Simulated here with a further bookkeeping-only
	/// classical advance (`auth.mine.commit`, no real peer fold) past the
	/// id alice's classical view of bob actually presents — the same gap a
	/// peer that never folds a catch-up offer leaves forever. Bob's turn
	/// keeps ratcheting A.4 instead of stalling on an A.5 he can never
	/// complete. Kills: removing the own-arm gate.
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedAcceptorKeepsRatchetingA4UntilThePeerFoldsItsTarget() throws {
		var (_, bob, _, _) = try bobHoldingPQTurnWithRecvPQLaggingInvitationID()

		let unfoldedID = Data("bob-not-yet-folded".utf8)
		try bob.auth.mine.commit(unfoldedID)

		_ = try bob.prepareToEncrypt()
		#expect(throws: Never.self) { try bob.encrypt(Data("msg".utf8)) }
		guard case .initiating = bob.pqInflight else {
			Issue.record("expected a plain A.4 — the peer has not folded bob's target")
			return
		}
	}

	/// The literal shape of the gap the own-arm gate closes: a peer that
	/// never folds bob's catch-up offer at all (no `queueProposal`, ever),
	/// not just one whose classical view has fallen bookkeeping-behind.
	/// Bob is fully established and holds the PQ turn; his recv-classical
	/// leaf still presents the invitation id (alice never folded), his
	/// recv-PQ leaf also still presents the invitation id, and
	/// `auth.mine.current` is already the dedicated id. Without the gate,
	/// bob's own recv-PQ lag alone would open the A.5 — an `Upd′` a
	/// non-folding peer refuses forever (its announced id is outside what
	/// it has canonicalized), stalling the PQ ratchet where today it keeps
	/// ratcheting A.4 for life. Kills: removing the own-arm gate.
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedAcceptorNeverFoldedByPeerKeepsRatchetingA4() throws {
		var (alice, bob, invitationClientID, dedicatedClientID, _) =
			try fullyEstablishedDedicated()

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobFrame)
		// alice's host never queues/folds bob's catch-up offer.
		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-no-fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(aliceFrame)

		_ = try bob.prepareToEncrypt()
		let bobFrame2 = try bob.encrypt(Data("bob-hello-2".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobFrame2)

		let begin = try alice.pqBootstrapBegin()
		let respond = try bob.pqBootstrapRespond(begin.frame)
		_ = try alice.pqBootstrapJoin(respond.frame)
		#expect(bob.isFullyEstablished)

		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)
		#expect(bob.myPQTurn)

		let recvPQGroup = try #require(bob.recvGroup?.pq)
		let recvPQ = try TwoMLSSession.ownLeaf(of: recvPQGroup)
		#expect(try basicIdentifier(recvPQ.credential) == invitationClientID)
		let recvClassicalGroup = try #require(bob.recvGroup?.classical)
		let recvClassical = try TwoMLSSession.ownLeaf(of: recvClassicalGroup)
		#expect(
			try basicIdentifier(recvClassical.credential) == invitationClientID,
			"the peer never folded — bob's classical leaf still presents the invitation id"
		)
		#expect(bob.auth.mine.current == dedicatedClientID)

		_ = try bob.prepareToEncrypt()
		#expect(throws: Never.self) { try bob.encrypt(Data("msg".utf8)) }
		guard case .initiating = bob.pqInflight else {
			Issue.record(
				"expected a plain A.4 — the peer has never folded bob's target; got \(String(describing: bob.pqInflight))"
			)
			return
		}
	}

	/// The gate's other half: once the peer HAS folded the target — the
	/// ordinary born-dedicated case, where alice's approval already
	/// canonicalized bob to D — his self-driven catch-up opens for real,
	/// with no host call, and the round completes exactly as the explicit
	/// `pqRekeyBegin` case above does. Book: anomaly #2 "is healed once the
	/// acceptor runs a conforming engine, whose own A.5 fires"
	/// (`session-lifecycle.md`). Kills: an own-arm that never fires for a
	/// born-dedicated acceptor.
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedAcceptorSelfDrivesItsRecvPQCatchUp() throws {
		var (alice, bob, _, dedicatedClientID) =
			try bobHoldingPQTurnWithRecvPQLaggingInvitationID()

		_ = try bob.prepareToEncrypt()
		let selfDriven = try bob.encrypt(Data("msg".utf8))
		#expect(selfDriven.update.kind == .checkpoint)
		guard case .rekeyInitiated(let updBytes) = bob.pqInflight else {
			Issue.record("expected the self-drive to stage `.rekeyInitiated`")
			return
		}
		guard
			case .publicMessage(let updPub) = try MLS.RFC9420.Message(
				mlsEncoded: updBytes)
		else {
			Issue.record("expected a publicMessage-framed Upd′")
			return
		}
		// C1: the deployed-compatible profile announces the handed-off id.
		#expect(updPub.content.authenticatedData == dedicatedClientID)

		let pending = try #require(bob.pqPendingOutbound())
		let rekeyRespond = try alice.pqRekeyRespond(pending)
		#expect(rekeyRespond.rotatedCredential == dedicatedClientID)

		#expect(throws: Never.self) { try bob.pqRekeyApply(rekeyRespond.frame) }
		let recvPQGroupAfter = try #require(bob.recvGroup?.pq)
		let recvPQAfter = try TwoMLSSession.ownLeaf(of: recvPQGroupAfter)
		#expect(try basicIdentifier(recvPQAfter.credential) == dedicatedClientID)
	}

	// MARK: - Accept 8: rotation still available post-born-dedicated

	@available(iOS 26, macOS 26, *)
	@Test func bobCanStillRotateAfterBornDedicated() throws {
		var (alice, bob, invitationClientID, _, _) = try fullyEstablishedDedicated()
		// Drive the recv-leaf catch-up to completion first (own-leaf
		// presentation must reach D before a FURTHER rotation is legitimate
		// — rotating away from an in-flight catch-up is out of scope here).
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		_ = try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(aliceFrame)
		// The CLASSICAL leaf has converged, but the PQ leaf still presents
		// the invitation identity (see `testRecvLeafCatchUpConvergesInvToD`).
		let recvPQGroup = try #require(bob.recvGroup?.pq)
		let recvPQLeaf = try TwoMLSSession.ownLeaf(of: recvPQGroup)
		#expect(try basicIdentifier(recvPQLeaf.credential) == invitationClientID)

		// Now a genuinely NEW rotation must still work — no stale
		// `.rotationInFlight` left over from the catch-up mechanism (which
		// never touches `rotationCandidate`).
		let rotated = try bob.prepareToEncrypt(rotating: Data("bob-rotated".utf8))
		#expect(rotated.proposalMessage.isEmpty == false)
		#expect(
			bob.myPrincipalState
				== .pending(
					old: Data("bob-dedicated".utf8),
					new: Data("bob-rotated".utf8)))
	}

	// MARK: - Accept 4: idempotent install + 0x0B dedup

	@available(iOS 26, macOS 26, *)
	@Test func idempotentInstallAndDedupOnStandalone0x0B() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let stapleAfterFirst = bob.currentStaple
		let seqAfterFirst = bob.stateSeq

		// Idempotent same-bytes re-install: no-op (staple byte-identical),
		// still bumps `stateSeq` like every other idempotent re-send here.
		let second = try bob.installEstablishmentEnvelope(envelope)
		#expect(bob.currentStaple == stapleAfterFirst)
		#expect(bob.stateSeq > seqAfterFirst)
		#expect(second.kind == .core)

		let standalone = try #require(try bob.standaloneWelcome())
		let opened = try #require(try alice.openIncoming(standalone))
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected .joined")
			return
		}

		// Re-delivered `0x0B` dedups on the INNER welcome digest — a fresh
		// seal of the SAME plaintext still resolves to `.ignored`.
		let standaloneAgain = try #require(try bob.standaloneWelcome())
		let openedAgain = try #require(try alice.openIncoming(standaloneAgain))
		guard case .ignored = try alice.processIncoming(openedAgain.frame) else {
			Issue.record("expected .ignored on re-delivery")
			return
		}
	}

	// MARK: - Accept 5: restore

	@available(iOS 26, macOS 26, *)
	@Test func restoreOwedButNotInstalledStillOwes() throws {
		let (_, bob, _, invitationClientID, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.owesEstablishmentEnvelope)
		#expect(restored.leafKeys.recvClassical.pending[dedicatedClientID] != nil)
		#expect(restored.identity.clientID == invitationClientID)
		#expect(restored.myPrincipalState == .sync(dedicatedClientID))
		#expect(restored.currentStaple.first == Frames.apqWelcomeTag)
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try restored.encrypt(Data())
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func restorePostInstallReemitsThe0x0BStaple() throws {
		var (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(!restored.owesEstablishmentEnvelope)
		#expect(restored.currentStaple.first == Frames.establishmentHandoffTag)
		let (restoredEnvelope, _) = try Frames.decodeEstablishmentHandoff(
			restored.currentStaple)
		#expect(restoredEnvelope == envelope)
	}

	// MARK: - Accept 14: invalid client id

	@available(iOS 26, macOS 26, *)
	@Test func emptyNewClientIDIsRejected() throws {
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		guard let theirCombinerKP = invitation.combinerKeyPackage else {
			Issue.record("expected a combiner key package")
			return
		}
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let spawnToken = classicalProvider.randomBytes(16)
		#expect(throws: TwoMLSError.invalidClientID) {
			try invitation.receive(
				welcome: initiated.welcome,
				theirClassicalKeyPackage: initiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				spawnToken: spawnToken, newClientID: Data())
		}
	}

	// MARK: - Reject/tamper 9: bare undelegated welcome

	/// A bare (un-enveloped) `0x01` welcome whose creator is the dedicated
	/// principal D — exactly Bob's own `currentStaple` while still owed —
	/// is indistinguishable from an impersonation without the signed
	/// handoff, so Alice's plain `processIncoming` refuses it with
	/// `.establishmentEnvelopeRequired`, burning nothing (the one-shot
	/// `0xFF02` exporter leaf stays unspent, matching the existing
	/// malformed-welcome contract). A later, properly-delivered-and-approved
	/// handoff still joins afterward.
	@available(iOS 26, macOS 26, *)
	@Test func bareUndelegatedWelcomeBurnsNothingAndLaterHandoffStillJoins() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let bareStaple = bob.currentStaple
		#expect(bareStaple.first == Frames.apqWelcomeTag)

		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try alice.processIncoming(bareStaple)
		}
		#expect(!alice.isEstablished)
		#expect(alice.recvGroup == nil)
		#expect(alice.joinedWelcomeDigest == nil)
		#expect(alice.sendCrossPSKLedger.isEmpty)

		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try #require(try bob.standaloneWelcome())
		let opened = try #require(try alice.openIncoming(standalone))
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record("expected a pause")
			return
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined(let newSender, _) = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected the genuine handoff to still join")
			return
		}
		#expect(newSender == dedicatedClientID)
	}

	// MARK: - Reject/tamper 10: the emit door stays closed while owed

	@available(iOS 26, macOS 26, *)
	@Test func emitDoorClosedWhileOwed() throws {
		var (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try bob.encrypt(Data())
		}
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try bob.prepareToEncrypt()
		}
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try bob.pqBootstrapBegin()
		}
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try bob.pqBootstrapRespond(Data([0x13]))
		}
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try bob.pqRekeyBegin()
		}
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try bob.standaloneWelcome()
		}
	}

	// MARK: - Reject/tamper 11: install edge cases

	@available(iOS 26, macOS 26, *)
	@Test func installEdgeCases() throws {
		var (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try bob.installEstablishmentEnvelope(Data())
		}
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		#expect(throws: TwoMLSError.establishmentEnvelopeConflict) {
			try bob.installEstablishmentEnvelope(fakeEnvelope("different"))
		}

		// Not owed at all (the degenerate, non-dedicated topology).
		var (_, degenerateBob, _, _, _, _) = try SessionTestSupport.established()
		#expect(throws: TwoMLSError.sessionNotReady) {
			try degenerateBob.installEstablishmentEnvelope(envelope)
		}

		// Staple moved past the establishment staples entirely (a fold on
		// Bob's OWN send group, Group_B, has landed) — fail-closed, never
		// re-wrap a routine commit staple. Alice offers the Upd (staged into
		// HER recv group, which mirrors Bob's send group); Bob approves and
		// folds it into his own next `prepareToEncrypt`, moving HIS staple.
		var (alice, movedBob, _, _, _) = try fullyEstablishedDedicated()
		_ = try alice.prepareToEncrypt()
		let aliceOfferFrame = try alice.encrypt(Data("offer".utf8)).frame
		let bobDecrypted = try movedBob.processIncomingDecrypted(aliceOfferFrame)
		_ = try movedBob.queueProposal(digest: bobDecrypted.queuedProposal.digest)
		let bobPrepared = try movedBob.prepareToEncrypt()
		#expect(bobPrepared.didCommit)
		#expect(movedBob.currentStaple.first == Frames.mlsMessageStapleTag)
		#expect(throws: TwoMLSError.sessionNotReady) {
			try movedBob.installEstablishmentEnvelope(fakeEnvelope())
		}
	}

	// MARK: - Reject/tamper 12: tampered re-feed re-pauses; a later matching frame heals

	@available(iOS 26, macOS 26, *)
	@Test func tamperedApprovalRepausesAndLaterMatchingFrameHeals() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone1 = try #require(try bob.standaloneWelcome())
		let opened1 = try #require(try alice.openIncoming(standalone1))
		guard case .pendingEstablishment = try alice.processIncoming(opened1.frame) else {
			Issue.record("expected a pause")
			return
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)

		guard
			case .pendingEstablishment = try alice.processIncomingApproved(
				opened1.frame, approvedEnvelopeDigest: Data("garbage".utf8),
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected re-pause on a tampered envelope digest")
			return
		}
		#expect(!alice.isEstablished)

		guard
			case .pendingEstablishment = try alice.processIncomingApproved(
				opened1.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: Data("garbage".utf8),
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected re-pause on a tampered welcome digest")
			return
		}
		#expect(!alice.isEstablished)

		// A LATER frame carrying the SAME approved pair still heals: a
		// fresh standalone re-seal of the identical plaintext pair.
		let standalone2 = try #require(try bob.standaloneWelcome())
		let opened2 = try #require(try alice.openIncoming(standalone2))
		guard
			case .joined(let newSender, _) = try alice.processIncomingApproved(
				opened2.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected the later frame to heal and join")
			return
		}
		#expect(newSender == dedicatedClientID)
	}

	// MARK: - Reject/tamper 13: approved creator mismatch discards the join

	@available(iOS 26, macOS 26, *)
	@Test func approvedJoinCreatorMismatchDiscardsJoinWhole() throws {
		var (alice, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try #require(try bob.standaloneWelcome())
		let opened = try #require(try alice.openIncoming(standalone))
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record("expected a pause")
			return
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: Data("someone-else".utf8))
		#expect(throws: TwoMLSError.establishmentCreatorMismatch) {
			try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		}
		#expect(!alice.isEstablished)
		#expect(alice.recvGroup == nil)
		#expect(alice.joinedWelcomeDigest == nil)
	}

	// MARK: - Reject/tamper 15: pause purity

	@available(iOS 26, macOS 26, *)
	@Test func pausePurity() throws {
		var (alice, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try #require(try bob.standaloneWelcome())
		let opened = try #require(try alice.openIncoming(standalone))

		let stateSeqBefore = alice.stateSeq
		let classicalInitSecretBefore = alice.identity.classicalInitSecretKey?.data
		let sendLedgerCountBefore = alice.sendCrossPSKLedger.count
		let offeredBefore = alice.offeredProposal?.digest

		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record("expected a pause")
			return
		}
		#expect(alice.stateSeq == stateSeqBefore)
		#expect(alice.recvGroup == nil)
		#expect(alice.joinedWelcomeDigest == nil)
		#expect(alice.sendCrossPSKLedger.count == sendLedgerCountBefore)
		#expect(alice.offeredProposal?.digest == offeredBefore)
		#expect(
			alice.identity.classicalInitSecretKey?.data == classicalInitSecretBefore)

		// An unapproved re-feed re-pauses, never joins.
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record("expected a second pause")
			return
		}
	}

	// MARK: - M-1: stapled 0x03+0x0B (the book's PRIMARY born-dedicated delivery)

	/// Every other case in this file exercises the STANDALONE `0x0B` — but the
	/// book's PRIMARY delivery is Bob's first `0x03` message frame STAPLING
	/// the handoff (`prepareToEncrypt`/`encrypt` produce it directly once
	/// installed, with no separate standalone send needed). This pins that
	/// path end-to-end: pause, tamper (envelope digest, then welcome digest),
	/// wrong creator, approve, a later standalone re-delivery dedups, and
	/// Bob's own recv-leaf (Group_A) converges to D off Alice's fold.
	@available(iOS 26, macOS 26, *)
	@Test func stapledEstablishmentHandoffFullPath() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)

		// Bob's first frame carries the 0x0B staple directly (`prepareToEncrypt`
		// stages nothing to fold/discharge yet, so his own staple never moves
		// off the just-installed handoff).
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let opened = try #require(try alice.openIncoming(frame))
		#expect(opened.kind == .message)
		let decodedFrame = try Frames.decodeMessageFrame(opened.frame)
		#expect(decodedFrame.staple.first == Frames.establishmentHandoffTag)

		// Pure parse: an un-approved pause never touches `stateSeq`/`recvGroup`.
		let stateSeqBefore = alice.stateSeq
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record("expected a pause on the stapled, un-approved 0x0B")
			return
		}
		#expect(alice.stateSeq == stateSeqBefore)
		#expect(alice.recvGroup == nil)

		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)

		// Tampered envelope digest: re-pauses, never joins.
		guard
			case .pendingEstablishment = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: Data("garbage".utf8),
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected re-pause on a tampered envelope digest")
			return
		}
		#expect(alice.recvGroup == nil)

		// Tampered welcome digest: re-pauses, never joins.
		guard
			case .pendingEstablishment = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: Data("garbage".utf8),
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected re-pause on a tampered welcome digest")
			return
		}
		#expect(alice.recvGroup == nil)

		// Wrong expectedCreator: throws, discards the join whole — the
		// cross-party PSK ledger stays unspent.
		#expect(throws: TwoMLSError.establishmentCreatorMismatch) {
			try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: Data("someone-else".utf8))
		}
		#expect(alice.recvGroup == nil)
		#expect(alice.sendCrossPSKLedger.isEmpty)

		// Approved re-feed: joins and decrypts in one step.
		guard
			case .decrypted(let decrypted) = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			Issue.record("expected .decrypted on the approved stapled re-feed")
			return
		}
		#expect(decrypted.applicationMessage == Data("bob-hello".utf8))
		#expect(decrypted.newSender == dedicatedClientID)
		#expect(!decrypted.didApplyRemoteCommit)
		#expect(decrypted.queuedProposal.proposing == dedicatedClientID)
		#expect(alice.isEstablished)

		// A LATER standalone re-delivery of the same welcome dedups.
		let standaloneAgain = try #require(try bob.standaloneWelcome())
		let openedAgain = try #require(try alice.openIncoming(standaloneAgain))
		guard case .ignored = try alice.processIncoming(openedAgain.frame) else {
			Issue.record("expected .ignored on a later standalone re-delivery")
			return
		}

		// Alice's fold converges Bob's own recv-leaf (Group_A) to D.
		_ = try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		let alicePrepared = try alice.prepareToEncrypt()
		#expect(alicePrepared.didCommit)
		#expect(alicePrepared.committedRemoteClientID == dedicatedClientID)
		let aliceFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		let bobDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		#expect(bobDecrypted.didApplyRemoteCommit)
		#expect(bobDecrypted.ownCredentialCanonicalized)
		let recvClassicalGroup = try #require(bob.recvGroup?.classical)
		let leafAfter = try TwoMLSSession.ownLeaf(of: recvClassicalGroup)
		#expect(try basicIdentifier(leafAfter.credential) == dedicatedClientID)
	}

	// MARK: - m-5: defense-in-depth adoption screen

	/// A host blunder that hands back one of Alice's OWN known ids as the
	/// dedicated principal must never be adopted — `auth.mine.knownIDs`
	/// screens the approved join before it ever commits into `auth.theirs`.
	/// White-box (`@testable import`): the public API can never itself put an
	/// id into `auth.mine.knownIDs` before Alice's own first join (there is
	/// no `recvGroup` yet for `prepareToEncrypt(rotating:)` to run against),
	/// so this simulates the id already being known some other way — the
	/// guard is defense-in-depth precisely for a case this specific, not
	/// reachable through today's flow alone.
	@available(iOS 26, macOS 26, *)
	@Test func approvedJoinRejectsCreatorEqualToOwnKnownID() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		alice.auth.mine.authorize(dedicatedClientID)
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try #require(try bob.standaloneWelcome())
		let opened = try #require(try alice.openIncoming(standalone))
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record("expected a pause")
			return
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		#expect(throws: TwoMLSError.invalidSuccession) {
			try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		}
		#expect(!alice.isEstablished)
		#expect(alice.recvGroup == nil)
	}

	/// `receive` rejects a `newClientID` equal to the remote/initiator's own
	/// id outright — a dedicated principal can never legitimately be the
	/// very peer it is meant to be dedicated FOR.
	@available(iOS 26, macOS 26, *)
	@Test func newClientIDEqualToPeerIDIsRejected() throws {
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		guard let theirCombinerKP = invitation.combinerKeyPackage else {
			Issue.record("expected a combiner key package")
			return
		}
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let spawnToken = classicalProvider.randomBytes(16)
		#expect(throws: TwoMLSError.invalidClientID) {
			try invitation.receive(
				welcome: initiated.welcome,
				theirClassicalKeyPackage: initiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				spawnToken: spawnToken, newClientID: Data("alice".utf8))
		}
	}

	// MARK: - The generalized trigger

	/// The generalized rule-4 trigger (Messaging.swift's `recvClassical.
	/// pending[mine.current]` predicate) reads only `leafKeys`, never any
	/// born-dedicated-only custody record. Kills a revert to a trigger keyed
	/// on some other live field the rule-4 pin would depend on.
	@available(iOS 26, macOS 26, *)
	@Test func generalizedCatchUpReadsOnlyLeafKeys() throws {
		var (alice, bob, invitationClientID, dedicatedClientID, _) =
			try SessionTestSupport.establishedDedicatedAndApproved()
		let recvClassicalBefore = try #require(bob.recvGroup?.classical)
		let leafBefore = try TwoMLSSession.ownLeaf(of: recvClassicalBefore)
		#expect(try basicIdentifier(leafBefore.credential) == invitationClientID)

		_ = try bob.prepareToEncrypt()
		#expect(bob.pendingProposal?.proposing == dedicatedClientID)
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		#expect(decrypted.queuedProposal.proposing == dedicatedClientID)
		try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		let bobDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		#expect(bobDecrypted.didApplyRemoteCommit)
		let recvClassicalAfter = try #require(bob.recvGroup?.classical)
		let leafAfter = try TwoMLSSession.ownLeaf(of: recvClassicalAfter)
		#expect(try basicIdentifier(leafAfter.credential) == dedicatedClientID)
	}

	/// D's rule-4 catch-up key (`recvClassical.pending[D]`) is minted
	/// separately from D's founding leaf key (`sendClassical.current`) —
	/// never the same pair. Proved both before and after the catch-up fold
	/// actually lands, so all four of D's own-leaf keys stay pairwise
	/// distinct throughout.
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedCatchUpKeyIsIndependent() throws {
		var (alice, bob, _, dedicatedClientID, _) =
			try SessionTestSupport.establishedDedicatedAndApproved(
				dedicatedClientID: Data("d1-independent".utf8))

		let catchUpKeyBefore = try #require(
			bob.leafKeys.recvClassical.pending[dedicatedClientID])
		let sendClassicalKeyBefore = try #require(bob.leafKeys.sendClassical.current)
		#expect(
			catchUpKeyBefore.signatureKey != sendClassicalKeyBefore.signatureKey)

		// §A.3, so all four of D's own-leaf groups exist.
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		// Drive the rule-4 catch-up fold (mirrors
		// `testAcceptCaseXReceiveFoldsTheRuleFourCatchUp` above).
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		let bobDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		#expect(bobDecrypted.didApplyRemoteCommit)
		let recvClassicalGroup = try #require(bob.recvGroup?.classical)
		let leafAfter = try TwoMLSSession.ownLeaf(of: recvClassicalGroup)
		#expect(try basicIdentifier(leafAfter.credential) == dedicatedClientID)

		let sendClassicalCurrent = try #require(bob.leafKeys.sendClassical.current)
		let recvClassicalCurrent = try #require(bob.leafKeys.recvClassical.current)
		let sendPQCurrent = try #require(bob.leafKeys.sendPQ.current)
		let recvPQCurrent = try #require(bob.leafKeys.recvPQ.current)
		let keys = [
			sendClassicalCurrent.signatureKey.data,
			recvClassicalCurrent.signatureKey.data,
			sendPQCurrent.signatureKey.data,
			recvPQCurrent.signatureKey.data,
		]
		#expect(Set(keys).count == keys.count)
	}
}
