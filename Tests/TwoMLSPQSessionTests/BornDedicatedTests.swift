import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// Slice 11: born-dedicated principal + contract-26 signed delegation
/// handoff. Test matrix per the slice plan §F — accept cases 1-8, standalone
/// delivery S1-S9/T1-T9, and reject/tamper cases 9-16 (16 itself is the
/// build/format/full-suite gate, not a unit test here).
@available(iOS 26, macOS 26, *)
final class BornDedicatedTests: XCTestCase {
	private let classicalProvider = SessionTestSupport.classicalProvider

	/// A stand-in for the host's signed contract-26 handoff blob — this
	/// module treats `envelope` as opaque bytes (the signature verification
	/// is the host's job, out of band, before ever calling
	/// `installEstablishmentEnvelope`/`processIncomingApproved`), so any
	/// fixed byte string exercises the wire mechanics faithfully.
	private func fakeEnvelope(_ tag: String = "fake-signed-handoff") -> Data {
		Data(tag.utf8)
	}

	/// The (envelope, welcome) digest pair + creator `processIncomingApproved`
	/// needs, read straight off `bob`'s installed `0x0B` staple.
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
	private func fullyEstablishedDedicated(
		dedicatedClientID: Data = Data("bob-dedicated".utf8)
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, invitationClientID: Data,
		dedicatedClientID: Data, envelope: Data
	) {
		try SessionTestSupport.establishedDedicatedAndApproved(
			dedicatedClientID: dedicatedClientID)
	}

	// MARK: - Accept 1: full round-trip

	func testFullBornDedicatedRoundTrip() throws {
		var (alice, bob, _, invitationClientID, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		XCTAssertTrue(bob.owesEstablishmentEnvelope)
		XCTAssertEqual(bob.identity.clientID, invitationClientID)
		XCTAssertEqual(bob.myPrincipalState, .sync(dedicatedClientID))
		XCTAssertNotNil(bob.leafKeys.recvClassical.pending[dedicatedClientID])
		XCTAssertEqual(bob.currentStaple.first, Frames.apqWelcomeTag)

		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		XCTAssertFalse(bob.owesEstablishmentEnvelope)
		XCTAssertEqual(bob.currentStaple.first, Frames.establishmentHandoffTag)
		let (installedEnvelope, installedWelcome) = try Frames.decodeEstablishmentHandoff(
			bob.currentStaple)
		XCTAssertEqual(installedEnvelope, envelope)
		XCTAssertEqual(installedWelcome.first, Frames.apqWelcomeTag)

		// Bob's 0x0B staple travels stapled on his first frame — but Bob
		// cannot even build one without a proposal staged (`prepareToEncrypt`
		// first); before that, deliver it standalone.
		let standalone = try XCTUnwrap(try bob.standaloneWelcome())
		let opened = try XCTUnwrap(try alice.openIncoming(standalone))
		XCTAssertEqual(opened.kind, .message)
		XCTAssertEqual(opened.frame.first, Frames.establishmentHandoffTag)

		guard
			case .pendingEstablishment(let pending) = try alice.processIncoming(
				opened.frame)
		else {
			return XCTFail("expected a pause on the un-approved 0x0B")
		}
		XCTAssertEqual(pending.envelope, envelope)
		XCTAssertEqual(pending.welcome, installedWelcome)
		XCTAssertFalse(alice.isEstablished)

		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined(let newSender, let update) = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			return XCTFail("expected .joined on the approved re-feed")
		}
		XCTAssertEqual(newSender, dedicatedClientID)
		XCTAssertEqual(update.kind, .core)
		XCTAssertTrue(alice.isEstablished)
		XCTAssertEqual(alice.auth.theirs.current, dedicatedClientID)

		// 0x0B byte-exact round-trip: what Bob installed decodes back to
		// exactly the envelope+welcome pair Alice's pause/approval saw.
		XCTAssertEqual(pending.envelope, installedEnvelope)
		XCTAssertEqual(pending.welcome, installedWelcome)
	}

	// MARK: - Accept 2: degenerate topology unchanged

	func testDegenerateNewClientIDMatchesInvitationIsUnchanged() throws {
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
			return XCTFail()
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
		XCTAssertFalse(received.session.owesEstablishmentEnvelope)
		XCTAssertTrue(received.session.leafKeys.recvClassical.pending.isEmpty)
		XCTAssertEqual(received.session.currentStaple.first, Frames.apqWelcomeTag)
		XCTAssertEqual(received.session.identity.clientID, Data("bob".utf8))
	}

	func testNilNewClientIDMatchesInvitationIsUnchanged() throws {
		let (_, bob, _, _, _, _) = try SessionTestSupport.established()
		XCTAssertFalse(bob.owesEstablishmentEnvelope)
		XCTAssertTrue(bob.leafKeys.recvClassical.pending.isEmpty)
		XCTAssertEqual(bob.currentStaple.first, Frames.apqWelcomeTag)
	}

	// MARK: - Accept 3: recv-leaf catch-up

	/// Bob's Group_A CLASSICAL leaf converges inv → D via the first
	/// committed Upd: his own `prepareToEncrypt` implicitly stages the
	/// catch-up (§C.4), Alice approves+folds it, and Bob's own apply of
	/// that fold canonicalizes his leaf — a no-op-safe `mine.commit`, since
	/// `auth.mine` was already D from `receive` (Fable traced this as
	/// admitting cleanly). recv-PQ is NOT caught up by this alone:
	/// `recvGroup.pq`'s leaf still independently presents the invitation
	/// identity until a later slice's PQ catch-up.
	func testRecvLeafCatchUpConvergesInvToD() throws {
		var (alice, bob, invitationClientID, dedicatedClientID, _) =
			try fullyEstablishedDedicated()
		XCTAssertNotNil(bob.leafKeys.recvClassical.pending[dedicatedClientID])
		XCTAssertEqual(bob.myPrincipalState, .sync(dedicatedClientID))
		let leafBefore = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.classical))
		XCTAssertEqual(try basicIdentifier(leafBefore.credential), invitationClientID)

		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.queuedProposal.proposing, dedicatedClientID)

		_ = try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		let alicePrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(alicePrepared.didCommit)
		XCTAssertEqual(alicePrepared.committedRemoteClientID, dedicatedClientID)

		let aliceFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		let bobDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		XCTAssertTrue(bobDecrypted.didApplyRemoteCommit)
		XCTAssertTrue(bobDecrypted.ownCredentialCanonicalized)

		let recvPQLeaf = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(recvPQLeaf.credential), invitationClientID)
		let leafAfter = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.classical))
		XCTAssertEqual(try basicIdentifier(leafAfter.credential), dedicatedClientID)
	}

	// MARK: - Accept 6: A.3 founds Group_B.pq under D

	func testBootstrapFoundsGroupBPQUnderDedicatedPrincipal() throws {
		var (alice, bob, _, dedicatedClientID, _) = try fullyEstablishedDedicated()
		let begin = try alice.pqBootstrapBegin()
		let respond = try bob.pqBootstrapRespond(begin.frame)
		_ = try alice.pqBootstrapJoin(respond.frame)
		XCTAssertTrue(bob.isFullyEstablished)

		let pqGroup = try XCTUnwrap(bob.sendGroup?.pq)
		let creatorLeaf = try TwoMLSSession.ownLeaf(of: pqGroup)
		XCTAssertEqual(try basicIdentifier(creatorLeaf.credential), dedicatedClientID)
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
	func testBornDedicatedAcceptorRecvPQCatchesUpToDedicatedID() throws {
		var (alice, bob, invitationClientID, dedicatedClientID, _) =
			try fullyEstablishedDedicated()

		// License Alice + drive Bob's recv-leaf catch-up in one stroke,
		// mirroring `RatchetTests.fullyEstablishedTurnOnBob()`'s own
		// bootstrap-then-license recipe (§11 #8: a queued fold requires
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
		XCTAssertTrue(bob.isFullyEstablished)

		// Already licensed (Bob's catch-up frame above) — Alice's very next
		// round discharges the owed A.3 bind immediately, flipping the turn.
		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(bob.myPQTurn)

		XCTAssertEqual(bob.auth.mine.current, dedicatedClientID)
		let recvPQBefore = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(recvPQBefore.credential), invitationClientID)

		// Bob's Upd′ proposes into `recvGroup.pq` (Group_A.pq), signed
		// under the retained invitation key `leafKeys.recvPQ.current`
		// still holds, and carries D as the leaf's new credential — Alice's
		// `pqRekeyRespond`, which owns that group as her `sendGroup.pq`,
		// verifies it and reports the move.
		let rekeyBegin = try bob.pqRekeyBegin()
		// C1: the deployed-compatible profile announces the handed-off id.
		let updBytes = try Frames.decodePQRekeyUpd(alice.openOrRaw(rekeyBegin.frame))
		guard
			case .publicMessage(let updPub) = try MLS.RFC9420.Message(
				mlsEncoded: updBytes)
		else {
			return XCTFail("expected a publicMessage-framed Upd′")
		}
		XCTAssertEqual(updPub.content.authenticatedData, dedicatedClientID)

		let rekeyRespond = try alice.pqRekeyRespond(rekeyBegin.frame)
		XCTAssertEqual(rekeyRespond.rotatedCredential, dedicatedClientID)

		XCTAssertNoThrow(try bob.pqRekeyApply(rekeyRespond.frame))
		let recvPQAfter = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(recvPQAfter.credential), dedicatedClientID)

		// Neither side still pins I: bob's send-PQ was founded under D
		// already, and his recv-PQ has now caught up too.
		XCTAssertFalse(bob.auth.mine.pinned.contains(invitationClientID))
		XCTAssertFalse(alice.auth.theirs.pinned.contains(invitationClientID))
	}

	// MARK: - Accept 7 (self-driven): the own-arm gate

	/// `fullyEstablishedDedicated()`, licensed and bootstrapped exactly as
	/// `testBornDedicatedAcceptorRecvPQCatchesUpToDedicatedID` does, up to
	/// the point bob holds the PQ turn with his recv-PQ leaf still
	/// presenting the invitation id.
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
		XCTAssertTrue(bob.isFullyEstablished)

		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(bob.myPQTurn)

		let recvPQ = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(recvPQ.credential), invitationClientID)

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
	func testBornDedicatedAcceptorKeepsRatchetingA4UntilThePeerFoldsItsTarget() throws {
		var (_, bob, _, _) = try bobHoldingPQTurnWithRecvPQLaggingInvitationID()

		let unfoldedID = Data("bob-not-yet-folded".utf8)
		try bob.auth.mine.commit(unfoldedID)

		_ = try bob.prepareToEncrypt()
		XCTAssertNoThrow(try bob.encrypt(Data("msg".utf8)))
		guard case .initiating = bob.pqInflight else {
			XCTFail("expected a plain A.4 — the peer has not folded bob's target")
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
	func testBornDedicatedAcceptorNeverFoldedByPeerKeepsRatchetingA4() throws {
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
		XCTAssertTrue(bob.isFullyEstablished)

		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(bob.myPQTurn)

		let recvPQ = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(recvPQ.credential), invitationClientID)
		let recvClassical = try TwoMLSSession.ownLeaf(
			of: XCTUnwrap(bob.recvGroup?.classical))
		XCTAssertEqual(
			try basicIdentifier(recvClassical.credential), invitationClientID,
			"the peer never folded — bob's classical leaf still presents the invitation id"
		)
		XCTAssertEqual(bob.auth.mine.current, dedicatedClientID)

		_ = try bob.prepareToEncrypt()
		XCTAssertNoThrow(try bob.encrypt(Data("msg".utf8)))
		guard case .initiating = bob.pqInflight else {
			XCTFail(
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
	func testBornDedicatedAcceptorSelfDrivesItsRecvPQCatchUp() throws {
		var (alice, bob, _, dedicatedClientID) =
			try bobHoldingPQTurnWithRecvPQLaggingInvitationID()

		_ = try bob.prepareToEncrypt()
		let selfDriven = try bob.encrypt(Data("msg".utf8))
		XCTAssertEqual(selfDriven.update.kind, .checkpoint)
		guard case .rekeyInitiated(let updBytes) = bob.pqInflight else {
			XCTFail("expected the self-drive to stage `.rekeyInitiated`")
			return
		}
		guard
			case .publicMessage(let updPub) = try MLS.RFC9420.Message(
				mlsEncoded: updBytes)
		else {
			XCTFail("expected a publicMessage-framed Upd′")
			return
		}
		// C1: the deployed-compatible profile announces the handed-off id.
		XCTAssertEqual(updPub.content.authenticatedData, dedicatedClientID)

		let pending = try XCTUnwrap(bob.pqPendingOutbound())
		let rekeyRespond = try alice.pqRekeyRespond(pending)
		XCTAssertEqual(rekeyRespond.rotatedCredential, dedicatedClientID)

		XCTAssertNoThrow(try bob.pqRekeyApply(rekeyRespond.frame))
		let recvPQAfter = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(recvPQAfter.credential), dedicatedClientID)
	}

	// MARK: - Accept 8: rotation still available post-born-dedicated

	func testBobCanStillRotateAfterBornDedicated() throws {
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
		let recvPQLeaf = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(recvPQLeaf.credential), invitationClientID)

		// Now a genuinely NEW rotation must still work — no stale
		// `.rotationInFlight` left over from the catch-up mechanism (which
		// never touches `rotationCandidate`).
		let rotated = try bob.prepareToEncrypt(rotating: Data("bob-rotated".utf8))
		XCTAssertEqual(rotated.proposalMessage.isEmpty, false)
		XCTAssertEqual(
			bob.myPrincipalState,
			.pending(old: Data("bob-dedicated".utf8), new: Data("bob-rotated".utf8)))
	}

	// MARK: - Accept 4: idempotent install + 0x0B dedup

	func testIdempotentInstallAndDedupOnStandalone0x0B() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let stapleAfterFirst = bob.currentStaple
		let seqAfterFirst = bob.stateSeq

		// Idempotent same-bytes re-install: no-op (staple byte-identical),
		// still bumps `stateSeq` like every other idempotent re-send here.
		let second = try bob.installEstablishmentEnvelope(envelope)
		XCTAssertEqual(bob.currentStaple, stapleAfterFirst)
		XCTAssertGreaterThan(bob.stateSeq, seqAfterFirst)
		XCTAssertEqual(second.kind, .core)

		let standalone = try XCTUnwrap(try bob.standaloneWelcome())
		let opened = try XCTUnwrap(try alice.openIncoming(standalone))
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			return XCTFail("expected .joined")
		}

		// Re-delivered `0x0B` dedups on the INNER welcome digest — a fresh
		// seal of the SAME plaintext still resolves to `.ignored`.
		let standaloneAgain = try XCTUnwrap(try bob.standaloneWelcome())
		let openedAgain = try XCTUnwrap(try alice.openIncoming(standaloneAgain))
		guard case .ignored = try alice.processIncoming(openedAgain.frame) else {
			return XCTFail("expected .ignored on re-delivery")
		}
	}

	// MARK: - Accept 5: restore

	func testRestoreOwedButNotInstalledStillOwes() throws {
		let (_, bob, _, invitationClientID, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertTrue(restored.owesEstablishmentEnvelope)
		XCTAssertNotNil(restored.leafKeys.recvClassical.pending[dedicatedClientID])
		XCTAssertEqual(restored.identity.clientID, invitationClientID)
		XCTAssertEqual(restored.myPrincipalState, .sync(dedicatedClientID))
		XCTAssertEqual(restored.currentStaple.first, Frames.apqWelcomeTag)
		XCTAssertThrowsError(try restored.encrypt(Data())) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeRequired)
		}
	}

	func testRestorePostInstallReemitsThe0x0BStaple() throws {
		var (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: archive,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertFalse(restored.owesEstablishmentEnvelope)
		XCTAssertEqual(restored.currentStaple.first, Frames.establishmentHandoffTag)
		let (restoredEnvelope, _) = try Frames.decodeEstablishmentHandoff(
			restored.currentStaple)
		XCTAssertEqual(restoredEnvelope, envelope)
	}

	// MARK: - Accept 14: invalid client id

	func testEmptyNewClientIDIsRejected() throws {
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
			return XCTFail()
		}
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let spawnToken = classicalProvider.randomBytes(16)
		XCTAssertThrowsError(
			try invitation.receive(
				welcome: initiated.welcome,
				theirClassicalKeyPackage: initiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				spawnToken: spawnToken, newClientID: Data())
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidClientID)
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
	func testBareUndelegatedWelcomeBurnsNothingAndLaterHandoffStillJoins() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let bareStaple = bob.currentStaple
		XCTAssertEqual(bareStaple.first, Frames.apqWelcomeTag)

		XCTAssertThrowsError(try alice.processIncoming(bareStaple)) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeRequired)
		}
		XCTAssertFalse(alice.isEstablished)
		XCTAssertNil(alice.recvGroup)
		XCTAssertNil(alice.joinedWelcomeDigest)
		XCTAssertTrue(alice.sendCrossPSKLedger.isEmpty)

		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try XCTUnwrap(try bob.standaloneWelcome())
		let opened = try XCTUnwrap(try alice.openIncoming(standalone))
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			return XCTFail("expected a pause")
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		guard
			case .joined(let newSender, _) = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			return XCTFail("expected the genuine handoff to still join")
		}
		XCTAssertEqual(newSender, dedicatedClientID)
	}

	// MARK: - Reject/tamper 10: the emit door stays closed while owed

	func testEmitDoorClosedWhileOwed() throws {
		var (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		XCTAssertThrowsError(try bob.encrypt(Data())) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeRequired)
		}
		XCTAssertThrowsError(try bob.prepareToEncrypt()) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeRequired)
		}
		XCTAssertThrowsError(try bob.pqBootstrapBegin()) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeRequired)
		}
		XCTAssertThrowsError(try bob.pqBootstrapRespond(Data([0x13]))) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeRequired)
		}
		XCTAssertThrowsError(try bob.pqRekeyBegin()) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeRequired)
		}
		XCTAssertThrowsError(try bob.standaloneWelcome()) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeRequired)
		}
	}

	// MARK: - Reject/tamper 11: install edge cases

	func testInstallEdgeCases() throws {
		var (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		XCTAssertThrowsError(try bob.installEstablishmentEnvelope(Data())) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeRequired)
		}
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		XCTAssertThrowsError(
			try bob.installEstablishmentEnvelope(fakeEnvelope("different"))
		) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentEnvelopeConflict)
		}

		// Not owed at all (the degenerate, non-dedicated topology).
		var (_, degenerateBob, _, _, _, _) = try SessionTestSupport.established()
		XCTAssertThrowsError(try degenerateBob.installEstablishmentEnvelope(envelope)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
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
		XCTAssertTrue(bobPrepared.didCommit)
		XCTAssertEqual(movedBob.currentStaple.first, Frames.mlsMessageStapleTag)
		XCTAssertThrowsError(try movedBob.installEstablishmentEnvelope(fakeEnvelope())) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
	}

	// MARK: - Reject/tamper 12: tampered re-feed re-pauses; a later matching frame heals

	func testTamperedApprovalRepausesAndLaterMatchingFrameHeals() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone1 = try XCTUnwrap(try bob.standaloneWelcome())
		let opened1 = try XCTUnwrap(try alice.openIncoming(standalone1))
		guard case .pendingEstablishment = try alice.processIncoming(opened1.frame) else {
			return XCTFail()
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)

		guard
			case .pendingEstablishment = try alice.processIncomingApproved(
				opened1.frame, approvedEnvelopeDigest: Data("garbage".utf8),
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			return XCTFail("expected re-pause on a tampered envelope digest")
		}
		XCTAssertFalse(alice.isEstablished)

		guard
			case .pendingEstablishment = try alice.processIncomingApproved(
				opened1.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: Data("garbage".utf8),
				expectedCreator: approval.expectedCreator)
		else {
			return XCTFail("expected re-pause on a tampered welcome digest")
		}
		XCTAssertFalse(alice.isEstablished)

		// A LATER frame carrying the SAME approved pair still heals: a
		// fresh standalone re-seal of the identical plaintext pair.
		let standalone2 = try XCTUnwrap(try bob.standaloneWelcome())
		let opened2 = try XCTUnwrap(try alice.openIncoming(standalone2))
		guard
			case .joined(let newSender, _) = try alice.processIncomingApproved(
				opened2.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			return XCTFail("expected the later frame to heal and join")
		}
		XCTAssertEqual(newSender, dedicatedClientID)
	}

	// MARK: - Reject/tamper 13: approved creator mismatch discards the join

	func testApprovedJoinCreatorMismatchDiscardsJoinWhole() throws {
		var (alice, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try XCTUnwrap(try bob.standaloneWelcome())
		let opened = try XCTUnwrap(try alice.openIncoming(standalone))
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			return XCTFail()
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: Data("someone-else".utf8))
		XCTAssertThrowsError(
			try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentCreatorMismatch)
		}
		XCTAssertFalse(alice.isEstablished)
		XCTAssertNil(alice.recvGroup)
		XCTAssertNil(alice.joinedWelcomeDigest)
	}

	// MARK: - Reject/tamper 15: pause purity

	func testPausePurity() throws {
		var (alice, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try XCTUnwrap(try bob.standaloneWelcome())
		let opened = try XCTUnwrap(try alice.openIncoming(standalone))

		let stateSeqBefore = alice.stateSeq
		let classicalInitSecretBefore = alice.identity.classicalInitSecretKey?.data
		let sendLedgerCountBefore = alice.sendCrossPSKLedger.count
		let offeredBefore = alice.offeredProposal?.digest

		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			return XCTFail()
		}
		XCTAssertEqual(alice.stateSeq, stateSeqBefore)
		XCTAssertNil(alice.recvGroup)
		XCTAssertNil(alice.joinedWelcomeDigest)
		XCTAssertEqual(alice.sendCrossPSKLedger.count, sendLedgerCountBefore)
		XCTAssertEqual(alice.offeredProposal?.digest, offeredBefore)
		XCTAssertEqual(
			alice.identity.classicalInitSecretKey?.data, classicalInitSecretBefore)

		// An unapproved re-feed re-pauses, never joins.
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			return XCTFail("expected a second pause")
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
	func testStapledEstablishmentHandoffFullPath() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)

		// Bob's first frame carries the 0x0B staple directly (`prepareToEncrypt`
		// stages nothing to fold/discharge yet, so his own staple never moves
		// off the just-installed handoff).
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let opened = try XCTUnwrap(try alice.openIncoming(frame))
		XCTAssertEqual(opened.kind, .message)
		let decodedFrame = try Frames.decodeMessageFrame(opened.frame)
		XCTAssertEqual(decodedFrame.staple.first, Frames.establishmentHandoffTag)

		// Pure parse: an un-approved pause never touches `stateSeq`/`recvGroup`.
		let stateSeqBefore = alice.stateSeq
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			return XCTFail("expected a pause on the stapled, un-approved 0x0B")
		}
		XCTAssertEqual(alice.stateSeq, stateSeqBefore)
		XCTAssertNil(alice.recvGroup)

		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)

		// Tampered envelope digest: re-pauses, never joins.
		guard
			case .pendingEstablishment = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: Data("garbage".utf8),
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			return XCTFail("expected re-pause on a tampered envelope digest")
		}
		XCTAssertNil(alice.recvGroup)

		// Tampered welcome digest: re-pauses, never joins.
		guard
			case .pendingEstablishment = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: Data("garbage".utf8),
				expectedCreator: approval.expectedCreator)
		else {
			return XCTFail("expected re-pause on a tampered welcome digest")
		}
		XCTAssertNil(alice.recvGroup)

		// Wrong expectedCreator: throws, discards the join whole — the
		// cross-party PSK ledger stays unspent.
		XCTAssertThrowsError(
			try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: Data("someone-else".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .establishmentCreatorMismatch)
		}
		XCTAssertNil(alice.recvGroup)
		XCTAssertTrue(alice.sendCrossPSKLedger.isEmpty)

		// Approved re-feed: joins and decrypts in one step.
		guard
			case .decrypted(let decrypted) = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		else {
			return XCTFail("expected .decrypted on the approved stapled re-feed")
		}
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-hello".utf8))
		XCTAssertEqual(decrypted.newSender, dedicatedClientID)
		XCTAssertFalse(decrypted.didApplyRemoteCommit)
		XCTAssertEqual(decrypted.queuedProposal.proposing, dedicatedClientID)
		XCTAssertTrue(alice.isEstablished)

		// A LATER standalone re-delivery of the same welcome dedups.
		let standaloneAgain = try XCTUnwrap(try bob.standaloneWelcome())
		let openedAgain = try XCTUnwrap(try alice.openIncoming(standaloneAgain))
		guard case .ignored = try alice.processIncoming(openedAgain.frame) else {
			return XCTFail("expected .ignored on a later standalone re-delivery")
		}

		// Alice's fold converges Bob's own recv-leaf (Group_A) to D.
		_ = try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		let alicePrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(alicePrepared.didCommit)
		XCTAssertEqual(alicePrepared.committedRemoteClientID, dedicatedClientID)
		let aliceFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		let bobDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		XCTAssertTrue(bobDecrypted.didApplyRemoteCommit)
		XCTAssertTrue(bobDecrypted.ownCredentialCanonicalized)
		let leafAfter = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.classical))
		XCTAssertEqual(try basicIdentifier(leafAfter.credential), dedicatedClientID)
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
	func testApprovedJoinRejectsCreatorEqualToOwnKnownID() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		alice.auth.mine.authorize(dedicatedClientID)
		let envelope = fakeEnvelope()
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try XCTUnwrap(try bob.standaloneWelcome())
		let opened = try XCTUnwrap(try alice.openIncoming(standalone))
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			return XCTFail()
		}
		let approval = try approvalTriple(
			installedOn: bob, expectedCreator: dedicatedClientID)
		XCTAssertThrowsError(
			try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: approval.envelopeDigest,
				approvedWelcomeDigest: approval.welcomeDigest,
				expectedCreator: approval.expectedCreator)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}
		XCTAssertFalse(alice.isEstablished)
		XCTAssertNil(alice.recvGroup)
	}

	/// `receive` rejects a `newClientID` equal to the remote/initiator's own
	/// id outright — a dedicated principal can never legitimately be the
	/// very peer it is meant to be dedicated FOR.
	func testNewClientIDEqualToPeerIDIsRejected() throws {
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
			return XCTFail()
		}
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let spawnToken = classicalProvider.randomBytes(16)
		XCTAssertThrowsError(
			try invitation.receive(
				welcome: initiated.welcome,
				theirClassicalKeyPackage: initiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				spawnToken: spawnToken, newClientID: Data("alice".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidClientID)
		}
	}

	// MARK: - The generalized trigger

	/// The generalized rule-4 trigger (Messaging.swift's `recvClassical.
	/// pending[mine.current]` predicate) reads only `leafKeys`, never any
	/// born-dedicated-only custody record. Kills a revert to a trigger keyed
	/// on some other live field the rule-4 pin would depend on.
	func testGeneralizedCatchUpReadsOnlyLeafKeys() throws {
		var (alice, bob, invitationClientID, dedicatedClientID, _) =
			try SessionTestSupport.establishedDedicatedAndApproved()
		let leafBefore = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.classical))
		XCTAssertEqual(try basicIdentifier(leafBefore.credential), invitationClientID)

		_ = try bob.prepareToEncrypt()
		XCTAssertEqual(bob.pendingProposal?.proposing, dedicatedClientID)
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.queuedProposal.proposing, dedicatedClientID)
		try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		let bobDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		XCTAssertTrue(bobDecrypted.didApplyRemoteCommit)
		let leafAfter = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.classical))
		XCTAssertEqual(try basicIdentifier(leafAfter.credential), dedicatedClientID)
	}

	/// D's rule-4 catch-up key (`recvClassical.pending[D]`) is minted
	/// separately from D's founding leaf key (`sendClassical.current`) —
	/// never the same pair. Proved both before and after the catch-up fold
	/// actually lands, so all four of D's own-leaf keys stay pairwise
	/// distinct throughout.
	func testBornDedicatedCatchUpKeyIsIndependent() throws {
		var (alice, bob, _, dedicatedClientID, _) =
			try SessionTestSupport.establishedDedicatedAndApproved(
				dedicatedClientID: Data("d1-independent".utf8))

		let catchUpKeyBefore = try XCTUnwrap(
			bob.leafKeys.recvClassical.pending[dedicatedClientID])
		let sendClassicalKeyBefore = try XCTUnwrap(bob.leafKeys.sendClassical.current)
		XCTAssertNotEqual(
			catchUpKeyBefore.signatureKey, sendClassicalKeyBefore.signatureKey)

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
		XCTAssertTrue(bobDecrypted.didApplyRemoteCommit)
		let leafAfter = try TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.classical))
		XCTAssertEqual(try basicIdentifier(leafAfter.credential), dedicatedClientID)

		let keys = [
			try XCTUnwrap(bob.leafKeys.sendClassical.current).signatureKey.data,
			try XCTUnwrap(bob.leafKeys.recvClassical.current).signatureKey.data,
			try XCTUnwrap(bob.leafKeys.sendPQ.current).signatureKey.data,
			try XCTUnwrap(bob.leafKeys.recvPQ.current).signatureKey.data,
		]
		XCTAssertEqual(Set(keys).count, keys.count)
	}
}
