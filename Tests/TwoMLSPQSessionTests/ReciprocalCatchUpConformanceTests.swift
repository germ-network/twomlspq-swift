import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// Conformance tests for the book's (TwoMLSPQ `69a9f0e`) reciprocal §A.5
/// credential catch-up: the either-leaf trigger, the head-compare "lags",
/// the two-round reciprocal structure, rule 4's history-window pin, and the
/// race guarantees — `protocol-flows.md:56`/`:704-708`,
/// `group-rules.md:143-158` (rule 4), `session-lifecycle.md:81-97`/
/// `:200-214` and the "Shipped anomalies" section (`:256-`). Where today's engine already
/// conforms, the assertion is a plain regression guard; where it does not,
/// it is wrapped in `XCTExpectFailure` so the run stays green today and
/// turns red once that gap closes — mirrors `SigningKeyProtocolTests`'s and
/// `LifecycleE2ETests`'s own convention.
///
/// Three real-API gaps recur across these tests (each marker below cites
/// whichever it hits):
///  - the trigger (`TwoMLSSession+Ratchet.swift`'s `maybeStageNextRound`)
///    never checks recv-PQ lag — its own doc comment: "the A.5
///    `send_pq_leaf_lags` branch is deferred" — so it always opens A.4;
///  - `pqRekeyBegin()` only ever proposes a same-id refresh (no
///    `newIdentity:` arm), so a rotated opener can never announce its own
///    new id;
///  - `pqRekeyRespond()` never moves the COMMITTER's own leaf (no
///    `newIdentity:` on its `committing` call), so the reciprocal
///    catch-up's own half never happens on the wire.
/// None of these are fabricated for these tests — `handBuildPQLeafMoveUpd`/
/// `handBuildPQRekeyCommitWithCommitterMove` below hand-build exactly the
/// content the real calls are missing, then drive the REST of the round
/// through the real `pqRekeyRespond`/`pqRekeyApply`, which already accept
/// it (SigningKeyProtocolTests §3) — so a plain assertion after a
/// hand-built step documents that only the content/trigger is missing, not
/// the accept/apply mechanics.
@available(iOS 26, macOS 26, *)
final class ReciprocalCatchUpConformanceTests: XCTestCase {

	// MARK: - Shared helpers

	/// Drives whichever side currently holds the PQ turn through one
	/// ordinary, uneventful §A.4 ratchet round (EK/CT/bind/discharge) — a
	/// plain key-only epoch bump, uninvolved with any credential. Used to
	/// pass the PQ turn to a specific party without touching identity
	/// state, mirroring `RatchetTests`'s own full round.
	private func driveOneA4Round(
		initiator: inout TwoMLSSession, responder: inout TwoMLSSession
	) throws {
		XCTAssertTrue(initiator.myPQTurn)
		_ = try initiator.prepareToEncrypt()
		_ = try initiator.encrypt(Data("a4-probe".utf8))
		guard case .initiating = initiator.pqInflight else {
			XCTFail(
				"driveOneA4Round expected a plain A.4 self-drive (.initiating); got \(String(describing: initiator.pqInflight)) instead — this helper only knows how to drive an uneventful A.4 round, never an A.5"
			)
			return
		}
		let ekFrame = try XCTUnwrap(initiator.pqPendingOutbound())
		let ctFrame = try responder.pqRatchetRespond(ekFrame).frame
		_ = try initiator.pqRatchetBind(ctFrame)
		let discharge = try initiator.prepareToEncrypt()
		XCTAssertTrue(discharge.didCommit)
		let boundFrame = try initiator.encrypt(Data("a4-probe-bound".utf8)).frame
		_ = try responder.processIncomingDecrypted(boundFrame)
	}

	/// Discards a §A.4 EK `encrypt` self-drove incidentally (e.g. while
	/// folding a peer's rotation, still holding the PQ turn) — resets to
	/// idle without completing the round, so an explicit `pqRekeyBegin()`
	/// on the SAME turn is unobstructed. Pure test scaffolding
	/// (`@testable`): production code has no way to cancel a self-staged
	/// round, and this never represents real host behavior. Only ever
	/// clears an actual incidental self-drive (`.initiating` — the only
	/// shape `maybeStageNextRound` can produce today): a no-op whenever
	/// `pqInflight` holds anything else, so it never clobbers a
	/// legitimate in-flight round (e.g. `.rekeyResponded`) that merely
	/// happens to still be outstanding at the call site.
	private func discardIncidentalSelfDrive(_ session: inout TwoMLSSession) {
		guard case .initiating = session.pqInflight else { return }
		session.pqInflight = nil
		session.pendingSideBand = nil
	}

	/// Resets straight to idle after a hand-built maneuver that mutates a
	/// group directly (e.g. `handBuildPQRekeyCommitWithCommitterMove` used
	/// to force a leaf move out of the normal round order, so a test can
	/// isolate a specific lag condition) — the maneuver leaves `pqInflight`
	/// pointing at a round with no real counterpart on the other side to
	/// finish, which would otherwise block the session's next legitimate
	/// round. Pure test scaffolding: unlike `discardIncidentalSelfDrive`,
	/// unconditional, since it follows a deliberate construction rather
	/// than an incidental self-drive.
	private func resetToIdle(_ session: inout TwoMLSSession) {
		session.pqInflight = nil
		session.pendingSideBand = nil
	}

	/// The non-self leaf of a 2-member group, decoded — the peer's own
	/// entry, mirrors `LifecycleE2ETests`'s inline construction of the same
	/// thing.
	private func peerLeaf(in group: MLS.RFC9420.Group) throws -> MLS.RFC9420.LeafNode {
		let entry = try XCTUnwrap(
			group.tree.nonBlankLeaves().first { $0.index != group.myLeafIndex })
		return try MLS.RFC9420.LeafNode(mlsEncoded: entry.record.encoded)
	}

	/// The credential a sealed `0x1B` Upd′ frame's proposal presents,
	/// verified against `group` (the PQ group it targets) — the read-only
	/// counterpart of `handBuildPQLeafMoveUpd`, used to inspect what a REAL
	/// `pqRekeyBegin()` call actually proposed.
	private func credentialAnnounced(
		byRekeyUpdFrame frame: Data, opener: TwoMLSSession,
		verifyingAgainst group: MLS.RFC9420.Group
	) throws -> Data {
		let updBytes = try Frames.decodePQRekeyUpd(opener.openOrRaw(frame))
		guard
			case .publicMessage(let updPub) = try MLS.RFC9420.Message(
				mlsEncoded: updBytes)
		else {
			XCTFail("expected a publicMessage-framed Upd′")
			throw TwoMLSError.malformedSideBandMessage
		}
		let verified = try group.verifying(SessionTestSupport.pqProvider, proposal: updPub)
		guard case .update(let leafNode) = verified.proposal else {
			XCTFail("expected an Update proposal")
			throw TwoMLSError.malformedSideBandMessage
		}
		return try basicIdentifier(leafNode.credential)
	}

	/// Hand-builds `proposer`'s own Upd′ into its recv-PQ mirror: `newID` as
	/// the leaf's credential and a freshly minted PQ signature key — the
	/// content a book-conformant `pqRekeyBegin()` would carry when the
	/// opener itself is the rotated party (`protocol-flows.md:56`), which
	/// the real call never produces. Copied from
	/// `SigningKeyProtocolTests.handBuildPQLeafMoveUpd` (private to that
	/// file) rather than shared, to keep edits to that file minimal.
	/// This hand-built Upd′ bypasses `pqRekeyBegin`, which never mints a
	/// rotating key itself today — stage the fresh key so `pqRekeyApply`'s
	/// promotion can find it when this move lands, mirroring the stored-
	/// signing-keys update this same helper got in `SigningKeyProtocolTests`.
	/// A call site needs `OracleCheck.allow([.recvPQ])` only when the
	/// `proposer` it mutates is later reused for a further real,
	/// state-update-producing call in the same test — the oracle fires at
	/// the end of `stateUpdate(kind:)`, so a proposer whose only further use
	/// is being read, or that the test never touches again, never trips it.
	private func handBuildPQLeafMoveUpd(
		proposer: inout TwoMLSSession, newID: Data
	) throws -> (frame: Data, bytes: Data) {
		var mirror = try XCTUnwrap(proposer.recvGroup)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.pq!.proposeUpdate(
			SessionTestSupport.pqProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.pqProvider,
				current: try proposer.recvPQSigningKey(), new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: newID), signatureKey: freshSignatureKey
			))
		proposer.recvGroup = mirror
		try proposer.leafKeys.recvPQ.stage(
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey),
			for: newID)
		let bytes = try message.mlsEncoded()
		return (Frames.encodePQRekeyUpd(bytes), bytes)
	}

	/// Hand-builds the Commit′ that folds `updBytes` into `committer`'s
	/// send-PQ AND moves the COMMITTER's own leaf to `committerNewID` —
	/// the reciprocal catch-up's own half (`protocol-flows.md:696-708`),
	/// which the real `pqRekeyRespond` never builds (no `newIdentity:` on
	/// its `committing` call) — then APPLIES it onto `committer`'s own
	/// `sendGroup.pq`, mirroring what the real call would do to `self`.
	/// Unlike `SigningKeyProtocolTests`'s read-only sibling (which
	/// deliberately leaves the committer's real state untouched so a
	/// later honest round can still use it), this one mutates `committer`
	/// in place — these tests need to assert the committer's OWN
	/// post-round state, not just the applier's acceptance of it.
	///
	/// Key-staging point: the committer both proposes AND applies its own
	/// leaf move in this one local action (unlike the proposer's case,
	/// which stages now and waits for the PEER to apply it later), so the
	/// fresh key is staged into `committer.leafKeys.sendPQ` AND promoted
	/// to `current` immediately, in the same call — mirroring what a real
	/// committer-move `pqRekeyRespond` would do to `self` once it exists.
	/// As with the proposer's helper above, a call site needs
	/// `OracleCheck.allow([.sendPQ])` only when `committer` is later reused
	/// for a further real, state-update-producing call — e.g.
	/// `testResponderCarriesItsCredential` never touches `alice` again
	/// after this call, so it sets no allowance at all.
	private func handBuildPQRekeyCommitWithCommitterMove(
		committer: inout TwoMLSSession, updBytes: Data, committerNewID: Data
	) throws -> Data {
		guard
			case .publicMessage(let updPub) = try MLS.RFC9420.Message(
				mlsEncoded: updBytes)
		else {
			XCTFail("expected a publicMessage-framed Upd′")
			throw TwoMLSError.malformedSideBandMessage
		}
		let sendPQ = try XCTUnwrap(committer.sendGroup?.pq)
		let verified = try sendPQ.verifying(SessionTestSupport.pqProvider, proposal: updPub)
		var proposalStore = MLS.RFC9420.ProposalStore()
		let ref = try proposalStore.insert(verified, SessionTestSupport.pqProvider)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let transition = try sendPQ.committing(
			SessionTestSupport.pqProvider, proposals: [.reference(ref)],
			proposalStore: proposalStore,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.pqProvider,
				current: try committer.sendPQSigningKey(), new: freshSigningKey),
			randomness: try .generate(SessionTestSupport.pqProvider), includePath: true,
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: committerNewID),
				signatureKey: freshSignatureKey))
		let sent = transition.takeOutput()
		let commitBytes = try sent.message.mlsEncoded()
		let pending = sent.takePending()
		let advanced = try pending.apply(onto: sendPQ)
		var send = try XCTUnwrap(committer.sendGroup)
		send.pq = advanced.group
		committer.sendGroup = send
		let freshKey = LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey)
		try committer.leafKeys.sendPQ.stage(freshKey, for: committerNewID)
		try committer.leafKeys.sendPQ.promoted(
			presenting: freshSignatureKey, id: committerNewID)
		let responseFrame = Frames.encodePQRekeyCommit(commitBytes)
		// Mirrors the real `pqRekeyRespond`'s own write-back, so the
		// committer's state is exactly what it would be had this landed
		// for real: the initiator's later ack (`applyBind`) requires
		// `pqInflight == .rekeyResponded` to accept it.
		committer.pqInflight = .rekeyResponded
		committer.pendingSideBand = responseFrame
		return responseFrame
	}

	// MARK: - Two-round catch-up, end to end

	/// `protocol-flows.md:704-708`, `group-rules.md:143-158` (rule 4):
	/// after Alice's classical rotation converges, her own next PQ turn
	/// opens an A.5 whose Upd′ announces her new id onto her leaf in Bob's
	/// send-PQ group (round 1, on [BSG-PQ]); Bob's next PQ turn then opens
	/// the reciprocal A.5 on Alice's OWN send-PQ group ([ASG-PQ]), his
	/// Upd′ a same-id refresh, her responder Commit′ carrying her
	/// credential. Afterward neither trigger fires again — a plain A.4
	/// follows on both sides. Reconciles `LifecycleE2ETests`'s own step
	/// [11], which stops after round 1's trigger marker; this test
	/// completes both rounds by hand-building exactly the content today's
	/// engine is missing (see the header) and driving the rest through the
	/// real accept/apply path. Both leaves genuinely lag right after the
	/// rotation (round 1 hasn't run yet), so its own trigger marker below
	/// can't by itself distinguish the book's recv-PQ-only trigger from
	/// the deployed engine's send-PQ-reading one (book anomaly #1) — that
	/// distinction is `testTriggerIgnoresSendPQLag`'s job.
	func testTwoRoundCatchUpEndToEnd() throws {
		// Both hand-built rounds below mint store-only keys the old
		// resolvers never covered (a PQ leaf move is not a rotation).
		OracleCheck.allow([.recvPQ, .sendPQ])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let aliceOldID = alice.identity.clientID

		// Flip the PQ turn to Alice via one uneventful A.4 first, so her
		// rotation (next) converges with nothing PQ outstanding.
		try driveOneA4Round(initiator: &bob, responder: &alice)
		XCTAssertTrue(alice.myPQTurn)

		// Alice rotates classically. It's her PQ turn, so her own offer's
		// `encrypt` self-drives an incidental A.4 — discard it so round 1
		// below is cleanly isolated to her NEXT turn.
		let alice2ID = Data("alice-two-round-catchup".utf8)
		_ = try alice.prepareToEncrypt(rotating: alice2ID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		discardIncidentalSelfDrive(&alice)

		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(alice2ID))
		XCTAssertTrue(alice.myPQTurn)

		// Round 1's target (Bob's send-PQ / alice's recv-PQ mirror) still
		// presents her OLD id — untouched by the classical-only rotation.
		let aliceRecvPQBefore = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(aliceRecvPQBefore.credential), aliceOldID)

		// Book: her own next `encrypt` should self-drive an A.5 whose
		// Upd′ carries her new id — probed on copies so `alice`/`bob`
		// stay clean for the hand-built round below.
		var triggerProbe = alice
		_ = try triggerProbe.prepareToEncrypt()
		_ = try triggerProbe.encrypt(Data("trigger-probe".utf8))
		let triggerOpensRekey: Bool
		if case .rekeyInitiated = triggerProbe.pqInflight {
			triggerOpensRekey = true
		} else {
			triggerOpensRekey = false
		}
		XCTExpectFailure(
			"protocol-flows.md:56 — the A.4-vs-A.5 trigger never checks recv-PQ lag"
		) {
			XCTAssertTrue(triggerOpensRekey)
		}

		var beginProbe = alice
		let beginResult = try beginProbe.pqRekeyBegin()
		// PR2: opened via `bob` — the frame's addressee.
		let announcedByBegin = try credentialAnnounced(
			byRekeyUpdFrame: beginResult.frame, opener: bob,
			verifyingAgainst: try XCTUnwrap(bob.sendGroup?.pq))
		XCTExpectFailure(
			"protocol-flows.md:56/:704-706 — pqRekeyBegin only ever proposes a same-id refresh"
		) {
			XCTAssertEqual(announcedByBegin, alice2ID)
		}

		// Hand-build round 1's real content and drive it through the REAL
		// commit/apply path — already conforming (plain): `pqRekeyRespond`
		// already accepts a proposer's move onto an already-canonical id
		// (SigningKeyProtocolTests §3).
		let round1 = try handBuildPQLeafMoveUpd(proposer: &alice, newID: alice2ID)
		let round1Commit = try bob.pqRekeyRespond(round1.frame)
		XCTAssertEqual(round1Commit.rotatedCredential, alice2ID)
		alice.pqInflight = .rekeyInitiated(updMessage: round1.bytes)
		alice.pendingSideBand = round1.frame
		XCTAssertNoThrow(try alice.pqRekeyApply(round1Commit.frame))
		XCTAssertNil(alice.pqInflight)

		// Round 1 complete: her leaf in Bob's send-PQ (her recv-PQ mirror)
		// now presents her new id, and Bob's own copy agrees.
		let aliceRecvPQAfterRound1 = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(aliceRecvPQAfterRound1.credential), alice2ID)
		let bobsViewOfAlice = try peerLeaf(in: try XCTUnwrap(bob.sendGroup?.pq))
		XCTAssertEqual(try basicIdentifier(bobsViewOfAlice.credential), alice2ID)

		// Discharge round 1's ack — passes the turn to Bob.
		XCTAssertNotNil(alice.owedBind)
		let dischargePrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame = try alice.encrypt(Data("round1-bound".utf8)).frame
		discardIncidentalSelfDrive(&alice)
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(bob.myPQTurn)
		XCTAssertFalse(alice.myPQTurn)

		// Round 1 (its own one-round outcome) never touched alice's OWN
		// send-PQ leaf (Group_A.pq — round 2's target); it still lags.
		let aliceSendPQBeforeRound2 = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.sendGroup?.pq))
		XCTAssertEqual(try basicIdentifier(aliceSendPQBeforeRound2.credential), aliceOldID)

		// Book: Bob's own next turn should self-drive the reciprocal A.5.
		var round2TriggerProbe = bob
		_ = try round2TriggerProbe.prepareToEncrypt()
		_ = try round2TriggerProbe.encrypt(Data("round2-trigger-probe".utf8))
		let round2OpensRekey: Bool
		if case .rekeyInitiated = round2TriggerProbe.pqInflight {
			round2OpensRekey = true
		} else {
			round2OpensRekey = false
		}
		XCTExpectFailure(
			"protocol-flows.md:56/:704-708 — the reciprocal round's trigger is unimplemented"
		) {
			XCTAssertTrue(round2OpensRekey)
		}

		// Hand-build round 2: Bob's real `pqRekeyBegin` (same-id — he
		// never rotated, matching the book's own shape for this round),
		// then a hand-built committer-move Commit′ carrying alice's
		// current id onto her OWN send-PQ leaf — `pqRekeyRespond` never
		// builds this (marked above), but `pqRekeyApply` already accepts
		// it once built (SigningKeyProtocolTests §3 committer-move case,
		// plain).
		let round2Begin = try bob.pqRekeyBegin()
		guard case .rekeyInitiated(let round2UpdBytes) = bob.pqInflight else {
			XCTFail("expected bob to hold .rekeyInitiated after pqRekeyBegin")
			return
		}
		_ = round2Begin
		let round2CommitFrame = try handBuildPQRekeyCommitWithCommitterMove(
			committer: &alice, updBytes: round2UpdBytes, committerNewID: alice2ID)
		XCTAssertNoThrow(try bob.pqRekeyApply(round2CommitFrame))
		XCTAssertNil(bob.pqInflight)
		XCTAssertNotNil(bob.owedBind)

		// Round 2 complete: alice's OWN send-PQ leaf now presents her new
		// id — the full two-round catch-up has landed.
		let aliceSendPQAfterRound2 = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.sendGroup?.pq))
		XCTAssertEqual(try basicIdentifier(aliceSendPQAfterRound2.credential), alice2ID)

		// Discharge round 2's ack; afterward neither trigger has anything
		// left to fire — the following round is ordinary A.4.
		let round2DischargePrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(round2DischargePrepared.didCommit)
		let round2BoundFrame = try bob.encrypt(Data("round2-bound".utf8)).frame
		discardIncidentalSelfDrive(&bob)
		_ = try alice.processIncomingDecrypted(round2BoundFrame)
		XCTAssertTrue(alice.myPQTurn)

		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("post-catchup".utf8))
		guard case .initiating = alice.pqInflight else {
			XCTFail("expected a plain A.4 once both credential catch-ups have landed")
			return
		}

		// Bob's OWN next trigger, after that A.4 completes and passes the
		// turn back to him, must also stay a plain A.4 — nothing lags
		// anywhere for either party any longer. Completing this round
		// needs alice to sign again in Group_A.pq (`owePQBind`'s
		// `sendPQSigningKey()`) — round 2's hand-built committer-move now
		// stages and promotes that key into `alice.leafKeys.sendPQ`
		// (`handBuildPQRekeyCommitWithCommitterMove`), so this resolves.
		let ekFrame = try XCTUnwrap(alice.pqPendingOutbound())
		let ctFrame = try bob.pqRatchetRespond(ekFrame).frame
		_ = try alice.pqRatchetBind(ctFrame)
		let finalDischarge = try alice.prepareToEncrypt()
		XCTAssertTrue(finalDischarge.didCommit)
		let finalBoundFrame = try alice.encrypt(Data("post-catchup-bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(finalBoundFrame)
		XCTAssertTrue(bob.myPQTurn)

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("bob-post-catchup".utf8))
		guard case .initiating = bob.pqInflight else {
			XCTFail("expected bob's own next turn to also stay a plain A.4")
			return
		}
	}

	// MARK: - Responder carries its credential (unit)

	/// `protocol-flows.md:704-708`: Alice has rotated; her send-PQ leaf
	/// still presents the old id; both ASes are at the new id. Bob opens
	/// an A.5 via the native begin path with a same-id `Upd′`. Alice's
	/// `pqRekeyRespond` `Commit′` must move her own send-PQ leaf to her
	/// current id, with a key different from before (D3). Bob's
	/// `pqRekeyApply` accepts it.
	func testResponderCarriesItsCredential() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let aliceOldID = alice.identity.clientID
		let alice2ID = Data("alice-responder-carries".utf8)

		_ = try alice.prepareToEncrypt(rotating: alice2ID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		discardIncidentalSelfDrive(&bob)
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(alice2ID))
		XCTAssertEqual(bob.theirPrincipalState, .sync(alice2ID))

		let aliceSendPQKeyBefore = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.sendGroup?.pq)
		).signatureKey
		let aliceSendPQIDBefore = try basicIdentifier(
			try TwoMLSSession.ownLeaf(of: try XCTUnwrap(alice.sendGroup?.pq)).credential
		)
		XCTAssertEqual(aliceSendPQIDBefore, aliceOldID)

		XCTAssertTrue(bob.myPQTurn)
		let begin = try bob.pqRekeyBegin()

		// Book: the REAL `pqRekeyRespond` should move alice's own leaf to
		// her current id, with a fresh key (D3) — probed on a copy.
		var realProbe = alice
		_ = try realProbe.pqRekeyRespond(begin.frame)
		let realAliceSendPQLeaf = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(realProbe.sendGroup?.pq))
		let realAliceSendPQID = try basicIdentifier(realAliceSendPQLeaf.credential)
		let realAliceSendPQKey = realAliceSendPQLeaf.signatureKey
		XCTExpectFailure(
			"protocol-flows.md:704-708 — pqRekeyRespond never catches the committer's own leaf up"
		) {
			XCTAssertEqual(realAliceSendPQID, alice2ID)
			// D3: fresh key.
			XCTAssertNotEqual(realAliceSendPQKey, aliceSendPQKeyBefore)
		}

		// Hand-build what a conformant Commit′ carries — mutates `alice`
		// in place, mirroring what `pqRekeyRespond` would do to `self`
		// once this lands. (The id/key changing here is a property of the
		// hand-build itself, not a fact about the engine — the marker
		// above is what documents the real gap.)
		guard case .rekeyInitiated(let updBytes) = bob.pqInflight else {
			XCTFail("expected bob to hold .rekeyInitiated after pqRekeyBegin")
			return
		}
		let handBuiltCommitFrame = try handBuildPQRekeyCommitWithCommitterMove(
			committer: &alice, updBytes: updBytes, committerNewID: alice2ID)
		let aliceSendPQIDAfter = try basicIdentifier(
			try TwoMLSSession.ownLeaf(of: try XCTUnwrap(alice.sendGroup?.pq)).credential
		)
		XCTAssertEqual(aliceSendPQIDAfter, alice2ID)

		// Bob's `pqRekeyApply` accepts it — already conforming (plain):
		// SigningKeyProtocolTests §3's committer-move case (b).
		XCTAssertNoThrow(try bob.pqRekeyApply(handBuiltCommitFrame))
		XCTAssertNil(bob.pqInflight)
		XCTAssertNotNil(bob.owedBind)
	}

	// MARK: - A rotated opener announces its current id (unit)

	/// `protocol-flows.md:56`: after Alice's rotation converges, the A.5
	/// she opens must carry a `Upd′` whose leaf presents her new id.
	func testRotatedOpenerAnnouncesItsCurrentID() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		try driveOneA4Round(initiator: &bob, responder: &alice)
		XCTAssertTrue(alice.myPQTurn)

		let alice2ID = Data("alice-opener-announces".utf8)
		_ = try alice.prepareToEncrypt(rotating: alice2ID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		discardIncidentalSelfDrive(&alice)
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(alice2ID))
		XCTAssertTrue(alice.myPQTurn)

		let begin = try alice.pqRekeyBegin()
		// PR2: opened via `bob` — the frame's addressee.
		let announcedID = try credentialAnnounced(
			byRekeyUpdFrame: begin.frame, opener: bob,
			verifyingAgainst: try XCTUnwrap(bob.sendGroup?.pq))
		XCTExpectFailure(
			"protocol-flows.md:56 — pqRekeyBegin only ever proposes a same-id refresh"
		) {
			XCTAssertEqual(announcedID, alice2ID)
		}
	}

	// MARK: - "Lags" compares against the head

	/// `protocol-flows.md:56`, `group-rules.md:143-158`: a leaf presenting
	/// the owner's CURRENT id under a different key is not a lag — the
	/// next turn opens a plain A.4. A same-id `pqRekeyBegin`/`Respond`
	/// changes no signature key on its own, so the rekey must be
	/// hand-built with a genuinely fresh key (as in
	/// `SigningKeyProtocolTests.testSection3SameIDKeyOnlyPQUpdIsAccepted`)
	/// — and it must land in Group_B.pq (bob's send-PQ / alice's
	/// recv-PQ mirror), the SAME group alice's own trigger reads below;
	/// otherwise the assertion is vacuous.
	func testSameIDDifferentKeyIsNotALag() throws {
		// The hand-built same-id/fresh-key Upd′ below mints a store-only
		// key (a PQ leaf move is not a rotation, so the old resolver has
		// no arm for it regardless of id).
		OracleCheck.allow([.recvPQ])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		// Flip the turn to alice first, so bob (not holding it) can
		// validly commit her hand-built Upd′ below.
		try driveOneA4Round(initiator: &bob, responder: &alice)
		XCTAssertTrue(alice.myPQTurn)

		// A same-id Upd′ with a genuinely FRESH signature key, hand-built
		// into Group_B.pq (alice's recv-PQ mirror) — the group her own
		// trigger reads.
		let aliceRecvPQKeyBefore = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.recvGroup?.pq)
		).signatureKey
		let round = try handBuildPQLeafMoveUpd(
			proposer: &alice, newID: alice.identity.clientID)
		let commit = try bob.pqRekeyRespond(round.frame)
		XCTAssertNil(commit.rotatedCredential)
		alice.pqInflight = .rekeyInitiated(updMessage: round.bytes)
		alice.pendingSideBand = round.frame
		XCTAssertNoThrow(try alice.pqRekeyApply(commit.frame))
		let aliceRecvPQKeyAfter = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.recvGroup?.pq)
		).signatureKey
		XCTAssertNotEqual(aliceRecvPQKeyBefore, aliceRecvPQKeyAfter)

		// Discharge — passes the turn to bob.
		XCTAssertNotNil(alice.owedBind)
		let dischargePrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		discardIncidentalSelfDrive(&alice)
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(bob.myPQTurn)

		// Pass the turn back to alice with one plain, uneventful A.4 —
		// touches Group_B.pq's epoch only, no credential.
		try driveOneA4Round(initiator: &bob, responder: &alice)
		XCTAssertTrue(alice.myPQTurn)

		// Book: her leaf's key changed, but not its id — not a lag. Her
		// own next turn must open a plain A.4.
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("m".utf8))
		guard case .initiating = alice.pqInflight else {
			XCTFail("expected a plain A.4 — a same-id key refresh is never a lag")
			return
		}
	}

	/// A leaf presenting an id in the owner's history but not the head IS
	/// a lag — the next turn must open an A.5. Isolated to ONLY alice's
	/// recv-PQ leaf lagging: her send-PQ leaf (Group_A.pq) is hand-built to
	/// already be current FIRST — the reciprocal half, out of the normal
	/// round order — so this marker can't be satisfied by a wrong,
	/// send-PQ-reading trigger (book anomaly #1); only a trigger that
	/// correctly reads her receive group opens the A.5 this test expects.
	func testHistoryButNotHeadInRecvPQIsALag() throws {
		// The reciprocal-first hand-build mints store-only keys in both
		// bob's recv-PQ (his same-id carrier, orphaned in `pending`) and
		// alice's send-PQ (her committer-move, promoted to `current`).
		OracleCheck.allow([.recvPQ, .sendPQ])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let aliceOldID = alice.identity.clientID
		let alice2ID = Data("alice-recv-only-lag".utf8)

		_ = try alice.prepareToEncrypt(rotating: alice2ID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		discardIncidentalSelfDrive(&bob)
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(alice2ID))

		// Hand-build the reciprocal half FIRST — alice's OWN send-PQ leaf
		// (Group_A.pq) catches up directly, out of the normal round order
		// — so ONLY her recv-PQ leaf (Group_B.pq) still lags below. Bob's
		// same-id carrier is delivered to HIM for real via `pqRekeyApply`
		// (not discarded), so his own state reflects the move too, and his
		// bind discharge below passes the turn honestly — no
		// `resetToIdle`, no manufactured ack, no extra A.4; neither party
		// is left desynced.
		let bobUpd = try handBuildPQLeafMoveUpd(
			proposer: &bob, newID: bob.identity.clientID)
		let reciprocalCommitFrame = try handBuildPQRekeyCommitWithCommitterMove(
			committer: &alice, updBytes: bobUpd.bytes, committerNewID: alice2ID)
		let aliceSendPQID = try basicIdentifier(
			try TwoMLSSession.ownLeaf(of: try XCTUnwrap(alice.sendGroup?.pq)).credential
		)
		XCTAssertEqual(aliceSendPQID, alice2ID)
		let aliceRecvPQID = try basicIdentifier(
			try TwoMLSSession.ownLeaf(of: try XCTUnwrap(alice.recvGroup?.pq)).credential
		)
		XCTAssertEqual(aliceRecvPQID, aliceOldID)

		bob.pqInflight = .rekeyInitiated(updMessage: bobUpd.bytes)
		bob.pendingSideBand = bobUpd.frame
		XCTAssertNoThrow(try bob.pqRekeyApply(reciprocalCommitFrame))
		XCTAssertNil(bob.pqInflight)
		XCTAssertNotNil(bob.owedBind)

		// Fresh evidence bound to bob's current epoch — his own fold above
		// spent the earlier evidence from alice's rotation offer, and the
		// hand-built maneuvers never touch classical state, so nothing
		// else licenses his discharge below. One ordinary frame, not a
		// full A.4 round.
		_ = try alice.prepareToEncrypt()
		let aliceAckFrame = try alice.encrypt(Data("alice-ack".utf8)).frame
		_ = try bob.processIncomingDecrypted(aliceAckFrame)

		let dischargePrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame = try bob.encrypt(Data("reciprocal-bound".utf8)).frame
		discardIncidentalSelfDrive(&bob)
		_ = try alice.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(alice.myPQTurn)

		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("m".utf8))
		let opensRekey: Bool
		if case .rekeyInitiated = alice.pqInflight {
			opensRekey = true
		} else {
			opensRekey = false
		}
		XCTExpectFailure(
			"protocol-flows.md:56 — a leaf presenting a history (non-head) id must open an A.5"
		) {
			XCTAssertTrue(opensRekey)
		}
	}

	/// Book anomaly #1 guard (`session-lifecycle.md:263-273`): the deployed
	/// engine's trigger reads its own SEND-PQ leaf, not its receive group.
	/// Construct the mirror-image state from the test above — ONLY alice's
	/// send-PQ leaf lags, her recv-PQ leaf is current — and assert her next
	/// turn opens a plain A.4. True both because the book's own trigger
	/// only ever reads the receive group, and because today's engine
	/// already does this (still unconditionally) — but this is the
	/// specific state where a wrongly-ported, send-PQ-reading trigger
	/// would incorrectly open an A.5, so it is worth asserting on its own.
	func testTriggerIgnoresSendPQLag() throws {
		// Round 1's hand-built Upd′ mints a store-only key (a PQ leaf move
		// is not a rotation).
		OracleCheck.allow([.recvPQ])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		try driveOneA4Round(initiator: &bob, responder: &alice)
		XCTAssertTrue(alice.myPQTurn)

		let alice2ID = Data("alice-send-only-lag".utf8)
		_ = try alice.prepareToEncrypt(rotating: alice2ID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		discardIncidentalSelfDrive(&alice)
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(alice2ID))
		XCTAssertTrue(alice.myPQTurn)

		// Round 1 only: her recv-PQ leaf (Group_B.pq) catches up to her
		// new id; her send-PQ leaf (Group_A.pq) is left lagging.
		let round1 = try handBuildPQLeafMoveUpd(proposer: &alice, newID: alice2ID)
		let round1Commit = try bob.pqRekeyRespond(round1.frame)
		alice.pqInflight = .rekeyInitiated(updMessage: round1.bytes)
		alice.pendingSideBand = round1.frame
		XCTAssertNoThrow(try alice.pqRekeyApply(round1Commit.frame))
		let aliceRecvPQID = try basicIdentifier(
			try TwoMLSSession.ownLeaf(of: try XCTUnwrap(alice.recvGroup?.pq)).credential
		)
		XCTAssertEqual(aliceRecvPQID, alice2ID)
		let aliceSendPQID = try basicIdentifier(
			try TwoMLSSession.ownLeaf(of: try XCTUnwrap(alice.sendGroup?.pq)).credential
		)
		XCTAssertEqual(aliceSendPQID, alice.identity.clientID)

		let dischargePrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame = try alice.encrypt(Data("round1-bound".utf8)).frame
		discardIncidentalSelfDrive(&alice)
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(bob.myPQTurn)

		// Pass the turn back to alice via a raw `@testable` flip, not a
		// real bob round: under a conforming book-trigger+C2, bob's own
		// next turn would itself see alice's send-PQ leaf lagging (in HIS
		// recv-PQ mirror, Group_A.pq — still untouched above) and open the
		// reciprocal A.5 right here, not a plain A.4. This test only cares
		// about ALICE's own trigger below, so it must not depend on what
		// bob's trigger does at this specific point. Pure test scaffolding
		// — nothing a real host does.
		bob.pqTurnMine = false
		alice.pqTurnMine = true
		XCTAssertTrue(alice.myPQTurn)

		// Her recv-PQ leaf (the only one HER trigger reads) is current;
		// her send-PQ leaf still lags, but that is irrelevant to her own
		// trigger. Plain: true today, and per the book.
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("m".utf8))
		guard case .initiating = alice.pqInflight else {
			XCTFail(
				"expected a plain A.4 — alice's own trigger must ignore her lagging send-PQ leaf"
			)
			return
		}
	}

	// MARK: - Rule-4 pin

	/// `group-rules.md:143-158` (rule 4): "A credential that a live PQ
	/// leaf still presents stays admissible past window eviction until
	/// that leaf catches up." `PartySequence.validSuccessor`'s own
	/// pinned-predecessor mechanics are already covered by
	/// `CredentialAuthenticationTests.testValidatePQLeafMove`
	/// (`CredentialAuthenticationTests.swift:346-406`); nothing here
	/// duplicates that. This exercises the session-level wiring instead:
	/// `pinned` is recomputed automatically at every state update from what
	/// this session's live PQ leaves actually present — never hand-set.
	/// Bob has TWO live PQ leaves (his
	/// send-PQ, Group_B.pq, and his recv-PQ mirror, Group_A.pq); rule 4's
	/// pin must stay held as long as EITHER still presents an evicted id,
	/// and retire only once BOTH have moved.
	func testRule4Pin() throws {
		// F2's one-generation rotation cap makes nine SEQUENTIAL real
		// rotations of the same party architecturally unreachable: once a
		// rotation fully converges (both classical leaves canonicalize),
		// `rotationCandidate` is never cleared, so every LATER
		// `prepareToEncrypt(rotating:)` throws `.rotationInFlight` for the
		// rest of the session's life (`TwoMLSSession+Messaging.swift:157-
		// 180`) — pinned down by `RotationTests.
		// testSecondRotationAfterFullConvergenceIsRotationInFlightAndSessionNotBricked`.
		// So id0's history-window eviction is reached in three phases
		// instead: (1) seed seven steps directly on `alice.auth.theirs`/
		// `bob.auth.mine` (lockstep, real `.commit()`, in place) to bring
		// the window to its edge without yet evicting id0 or touching
		// bob's classical leaves. This leaves bob's classical leaves
		// presenting an id seven steps behind `auth.mine.current` — deeper
		// than a real rotation would ever produce, since classical leaves
		// lag by at most one canonical step — but `PartySequence.
		// validSuccessor` only checks that the presented id is still IN
		// history, so the extra depth is invisible to it; the fixture
		// stays honest where it matters. (2) A REAL classical catch-up
		// round moves both of bob's classical leaves onto that edge id,
		// through the actual generalized-catch-up trigger (Messaging.
		// swift's `rotating == nil` arm) and the actual send-leaf catch-up
		// (`committingRound`'s §3c); (3) a REAL classical rotation, through
		// the engine's own `prepareToEncrypt(rotating:)`/fold/canonicalize
		// path, is what finally evicts id0 — the engine's own
		// canonicalization site. Only bob's PQ leaves are left hand-aged
		// past that point: they never move here, which is the whole
		// premise this test is about.
		OracleCheck.allow([.recvClassical, .sendClassical, .recvPQ, .sendPQ])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let id0 = bob.identity.clientID

		// Phase 1: seed to the window's edge (history = [id0, s1...s7], 8
		// entries — id0 still admissible). Bob's classical leaves still
		// genuinely present id0; only the bookkeeping is aged.
		for step in 1...7 {
			let stepID = Data("bob-step\(step)".utf8)
			try alice.auth.theirs.commit(stepID)
			try bob.auth.mine.commit(stepID)
		}
		let s7 = try XCTUnwrap(bob.auth.mine.current)

		// Phase 2: a REAL classical catch-up to s7, both of bob's leaves,
		// through the actual generalized-catch-up trigger — independently
		// minted keys per classical group (strict per-group independence).
		let (recvSigningKey, recvSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (sendSigningKey, sendSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		bob.leafKeys.recvClassical.pending[s7] = LeafKey(
			signingKey: recvSigningKey, signatureKey: recvSignatureKey)
		bob.leafKeys.sendClassical.pending[s7] = LeafKey(
			signingKey: sendSigningKey, signatureKey: sendSignatureKey)

		// Bob is already LICENSED (`fullyEstablishedTurnOnBob`), so this one
		// `prepareToEncrypt` both commits his own SEND-classical catch-up
		// (§3c, `didCommit`) AND stages a RECV-classical catch-up offer for
		// the very same frame — converges in one round (verified by
		// running it, not assumed).
		let bobRound = try bob.prepareToEncrypt()
		XCTAssertTrue(bobRound.didCommit, "the licensed send-classical catch-up")
		XCTAssertEqual(
			bob.pendingProposal?.proposing, s7, "the staged recv-classical offer")
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.sendGroup?.classical))
					.credential),
			s7, "bob's send-classical leaf has caught up")
		let bobFrame = try bob.encrypt(Data("bob-catchup".utf8)).frame
		let aliceSaw = try alice.processIncomingDecrypted(bobFrame)
		XCTAssertTrue(
			aliceSaw.didApplyRemoteCommit, "bob's send-classical catch-up, mirrored")
		XCTAssertEqual(aliceSaw.queuedProposal.proposing, s7, "bob's recv-classical offer")
		XCTAssertEqual(
			try basicIdentifier(
				peerLeaf(in: XCTUnwrap(alice.recvGroup?.classical)).credential),
			s7, "alice's mirror of bob's send-classical leaf agrees")

		try alice.queueProposal(digest: aliceSaw.queuedProposal.digest)
		let aliceFolded = try alice.prepareToEncrypt()
		XCTAssertTrue(aliceFolded.didCommit)
		let aliceFoldFrame = try alice.encrypt(Data("alice-catchup-fold".utf8)).frame
		let bobAppliedFold = try bob.processIncomingDecrypted(aliceFoldFrame)
		XCTAssertTrue(bobAppliedFold.didApplyRemoteCommit)
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.classical))
					.credential),
			s7, "bob's recv-classical leaf has caught up")

		// Phase 3: a REAL rotation to s8 — bob has no outstanding
		// `rotationCandidate`, so F2's cap does not bite — is what
		// actually evicts id0 from both `PartySequence`s, through the
		// engine's own canonicalization.
		let s8 = Data("bob-step8".utf8)
		_ = try bob.prepareToEncrypt(rotating: s8)
		let rotationOfferFrame = try bob.encrypt(Data("bob-rotate-offer".utf8)).frame
		let aliceSawRotation = try alice.processIncomingDecrypted(rotationOfferFrame)
		XCTAssertEqual(aliceSawRotation.queuedProposal.proposing, s8)
		try alice.queueProposal(digest: aliceSawRotation.queuedProposal.digest)
		let aliceFoldedRotation = try alice.prepareToEncrypt()
		XCTAssertTrue(aliceFoldedRotation.didCommit)
		XCTAssertFalse(
			alice.auth.theirs.history.contains(id0), "alice's own eviction, at her fold"
		)
		let rotationFoldFrame = try alice.encrypt(Data("alice-rotation-fold".utf8)).frame
		let bobAppliedRotation = try bob.processIncomingDecrypted(rotationFoldFrame)
		XCTAssertTrue(bobAppliedRotation.didApplyRemoteCommit)
		XCTAssertTrue(bobAppliedRotation.ownCredentialCanonicalized)

		let currentID = try XCTUnwrap(alice.auth.theirs.current)
		XCTAssertEqual(currentID, s8)
		XCTAssertEqual(bob.auth.mine.current, currentID)
		XCTAssertFalse(alice.auth.theirs.history.contains(id0))
		XCTAssertFalse(bob.auth.mine.history.contains(id0))
		XCTAssertTrue(
			alice.auth.theirs.pinned.contains(id0),
			"evicted from history but still presented by bob's live PQ leaves")
		XCTAssertTrue(
			bob.auth.mine.pinned.contains(id0),
			"bob's own view of himself pins the same evicted-but-presented id")
		// Only the PQ leaves still present id0 past the eviction — the
		// premise the rest of this test exercises.
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq)).credential),
			id0)
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.sendGroup?.pq)).credential),
			id0)

		// Bob's leaf in Group_A.pq (alice's send group, his recv-PQ
		// mirror) still genuinely presents id0 — hand-build his catch-up
		// Upd′ and try the real `pqRekeyRespond`. The engine already pins
		// id0 automatically (asserted above), so this round validates
		// without any hand-applied pin.
		let round = try handBuildPQLeafMoveUpd(proposer: &bob, newID: currentID)
		var respondProbe = alice
		let acceptedWithPin: Bool
		do {
			_ = try respondProbe.pqRekeyRespond(round.frame)
			acceptedWithPin = true
		} catch {
			acceptedWithPin = false
		}
		XCTAssertTrue(
			acceptedWithPin,
			"group-rules.md rule 4 — a credential a live PQ leaf still presents stays admissible past window eviction"
		)

		// Delivered through to BOTH sides for real: alice's response is
		// her own genuine commit on Group_A.pq, and bob's `pqRekeyApply`
		// plus his classical bind discharge complete his half too, so
		// neither party is left desynced going into round 2.
		// `pqRekeyApply`'s own adjudication (`adjudicatePQRekeyEffects`)
		// checks a moved leaf against `auth.mine` on the session whose OWN
		// leaf it is — here that is bob applying HIS OWN leaf's move — so
		// his side relies on the same automatic pin, already present on
		// `bob.auth.mine`.
		let round1Commit = try alice.pqRekeyRespond(round.frame)
		XCTAssertEqual(round1Commit.rotatedCredential, currentID)
		XCTAssertTrue(alice.auth.theirs.pinned.contains(id0))

		bob.pqInflight = .rekeyInitiated(updMessage: round.bytes)
		bob.pendingSideBand = round.frame
		XCTAssertNoThrow(try bob.pqRekeyApply(round1Commit.frame))
		XCTAssertNil(bob.pqInflight)
		XCTAssertNotNil(bob.owedBind)

		let round1DischargePrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(round1DischargePrepared.didCommit)
		let round1BoundFrame = try bob.encrypt(Data("round1-bound".utf8)).frame
		discardIncidentalSelfDrive(&bob)
		_ = try alice.processIncomingDecrypted(round1BoundFrame)
		XCTAssertTrue(alice.myPQTurn)

		// This moved only bob's leaf in Group_A.pq. His OTHER live PQ
		// leaf — his own send-PQ, Group_B.pq — still presents id0,
		// untouched, so rule 4 requires the pin to stay held. True today
		// (plain): nothing retires it regardless, and here that happens
		// to be correct.
		XCTAssertTrue(alice.auth.theirs.pinned.contains(id0))

		// Move bob's OTHER leaf too — his send-PQ, Group_B.pq. This time
		// the carrier is alice's REAL `pqRekeyBegin()` (she holds the turn
		// after round 1's discharge), not hand-built, and bob's
		// committer-move commit is delivered through alice's REAL
		// `pqRekeyApply` — so it is HER OWN `recvGroup.pq` mirror, the
		// copy rule 4's pin actually protects, that genuinely reflects
		// bob's move, not just bob's own tree.
		_ = try alice.pqRekeyBegin()
		guard case .rekeyInitiated(let carrierUpdBytes) = alice.pqInflight else {
			XCTFail("expected alice to hold .rekeyInitiated after pqRekeyBegin")
			return
		}
		let round2CommitFrame = try handBuildPQRekeyCommitWithCommitterMove(
			committer: &bob, updBytes: carrierUpdBytes, committerNewID: currentID)
		XCTAssertNoThrow(try alice.pqRekeyApply(round2CommitFrame))
		XCTAssertNil(alice.pqInflight)
		XCTAssertNotNil(alice.owedBind)

		let bobSendPQID = try basicIdentifier(
			try TwoMLSSession.ownLeaf(of: try XCTUnwrap(bob.sendGroup?.pq)).credential)
		XCTAssertEqual(bobSendPQID, currentID)
		let bobLeafAtAlice = try peerLeaf(in: try XCTUnwrap(alice.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(bobLeafAtAlice.credential), currentID)

		let round2DischargePrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(round2DischargePrepared.didCommit)
		let round2BoundFrame = try alice.encrypt(Data("round2-bound".utf8)).frame
		discardIncidentalSelfDrive(&alice)
		_ = try bob.processIncomingDecrypted(round2BoundFrame)

		// Rule 4's other half: now that NEITHER of bob's live PQ leaves
		// presents id0 any longer — genuinely, in alice's own session, not
		// just in bob's — the pin must retire.
		XCTAssertFalse(
			alice.auth.theirs.pinned.contains(id0),
			"group-rules.md rule 4 — the pin retires once no live PQ leaf presents the evicted id"
		)
	}

	// MARK: - Pin maintenance survives a faulted write-back

	/// `pqRekeyApply`'s own leaf-move write-back (`recvGroup`/`leafKeys`)
	/// lands on `self` before this call ever reaches its own `stateUpdate`
	/// — a fault right after that write-back (armed at
	/// `pqRekeyApply.afterWriteBackBeforeBind`) leaves `self.auth.mine.
	/// pinned` stale: the just-moved leaf's NEW id is now presented but not
	/// yet covered by the (unrecomputed) `pinned` set. `makeSessionArchive`,
	/// called directly on that torn state (bypassing `stateUpdate`), must
	/// still recompute a normal-form `pinned` that covers it — proven by
	/// the resulting archive restoring successfully. Mutation: reverting
	/// `makeSessionArchive`'s `auth: pqPinnedAuth()` back to `auth: auth`
	/// makes this fail (the archived, stale `pinned` no longer covers the
	/// just-moved id, so `restore`'s own pin safety check rejects it).
	#if DEBUG
		func testArchiveAfterFaultedRekeyApplyWriteBackStillRestores() throws {
			OracleCheck.allow([.recvClassical, .sendClassical, .recvPQ, .sendPQ])
			defer { OracleCheck.allow([]) }
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			let id0 = bob.identity.clientID

			// Phases 1-3, verbatim from `testRule4Pin`: age bob's bookkeeping
			// to the window's edge, a real classical catch-up to `s7`, then a
			// real rotation to `s8` that evicts `id0` from both parties'
			// classical history while bob's PQ leaves are left hand-aged —
			// still presenting `id0`.
			for step in 1...7 {
				let stepID = Data("wb-bob-step\(step)".utf8)
				try alice.auth.theirs.commit(stepID)
				try bob.auth.mine.commit(stepID)
			}
			let s7 = try XCTUnwrap(bob.auth.mine.current)
			let (recvSigningKey, recvSignatureKey) =
				try TwoMLSIdentity.mintSignatureKeypair()
			let (sendSigningKey, sendSignatureKey) =
				try TwoMLSIdentity.mintSignatureKeypair()
			bob.leafKeys.recvClassical.pending[s7] = LeafKey(
				signingKey: recvSigningKey, signatureKey: recvSignatureKey)
			bob.leafKeys.sendClassical.pending[s7] = LeafKey(
				signingKey: sendSigningKey, signatureKey: sendSignatureKey)
			_ = try bob.prepareToEncrypt()
			let bobFrame = try bob.encrypt(Data("wb-bob-catchup".utf8)).frame
			let aliceSaw = try alice.processIncomingDecrypted(bobFrame)
			try alice.queueProposal(digest: aliceSaw.queuedProposal.digest)
			_ = try alice.prepareToEncrypt()
			let aliceFoldFrame = try alice.encrypt(Data("wb-alice-catchup-fold".utf8))
				.frame
			_ = try bob.processIncomingDecrypted(aliceFoldFrame)

			let s8 = Data("wb-bob-step8".utf8)
			_ = try bob.prepareToEncrypt(rotating: s8)
			let rotationOfferFrame = try bob.encrypt(Data("wb-bob-rotate-offer".utf8))
				.frame
			let aliceSawRotation = try alice.processIncomingDecrypted(
				rotationOfferFrame)
			try alice.queueProposal(digest: aliceSawRotation.queuedProposal.digest)
			_ = try alice.prepareToEncrypt()
			let rotationFoldFrame = try alice.encrypt(
				Data("wb-alice-rotation-fold".utf8)
			).frame
			_ = try bob.processIncomingDecrypted(rotationFoldFrame)
			let currentID = try XCTUnwrap(alice.auth.theirs.current)
			XCTAssertTrue(bob.auth.mine.pinned.contains(id0))

			// Round 1 (mirrors `testRule4Pin`): bob's recv-PQ mirror still
			// presents `id0` — hand-build his catch-up Upd′, deliver it
			// through alice's REAL `pqRekeyRespond` (she is already pinned,
			// so this succeeds), then arm the fault right where bob's OWN
			// resulting leaf move would otherwise write back.
			let round = try handBuildPQLeafMoveUpd(proposer: &bob, newID: currentID)
			let round1Commit = try alice.pqRekeyRespond(round.frame)
			bob.pqInflight = .rekeyInitiated(updMessage: round.bytes)
			bob.pendingSideBand = round.frame

			TwoMLSSessionTestHooks.armFault("pqRekeyApply.afterWriteBackBeforeBind")
			defer { TwoMLSSessionTestHooks.disarmAllFaults() }
			XCTAssertThrowsError(try bob.pqRekeyApply(round1Commit.frame))

			// The write-back landed (bob's own recv-PQ leaf now presents
			// `currentID`) even though the call itself threw before ever
			// reaching its own `stateUpdate`.
			XCTAssertEqual(
				try basicIdentifier(
					TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq))
						.credential),
				currentID)
			// `bob.auth.mine.pinned` is stale here — still whatever the LAST
			// real `stateUpdate` left it at, not yet covering `currentID`.
			// Calling `makeSessionArchive` directly must recompute it anyway.
			let archive = try bob.makeSessionArchive(kind: .checkpoint)
			let body = try archive.decode(SessionArchive.self)
			XCTAssertTrue(body.auth.mine.pinned.contains(currentID))
			XCTAssertTrue(body.auth.mine.pinned.contains(id0))

			XCTAssertNoThrow(
				try TwoMLSSession.restore(
					core: nil, checkpoint: archive,
					classicalProvider: SessionTestSupport.classicalProvider,
					pqProvider: SessionTestSupport.pqProvider))
		}
	#endif

	/// `id0` is pinned from the moment bob's own last successful state
	/// update ran — well BEFORE this frame ever evicts it from history —
	/// because the normal form pins every currently-presented id, in-
	/// history or not (book group-rules.md rule 4's own wording only
	/// names the evicted case, but pinning an in-history id is behavior-
	/// neutral for every caller: `PartySequence.commit` checks `current
	/// == id` before ever consulting `pinned`, and `validSuccessor`'s
	/// authorization shortcut already excludes a `history` successor, so
	/// neither can tell the difference). A fault armed right between the
	/// classical
	/// eviction landing on `self` and this call's own `stateUpdate`
	/// (`processMessageFrame.afterStapleBeforeDecrypt`), on the very frame
	/// that evicts `id0`, catches this directly: `pinned` already covers
	/// `id0` at that exact moment, not only after some later recompute
	/// reacts to the eviction. Mutation: pinning only an id ALREADY absent
	/// from `history` (`presented.subtracting(history)`, instead of only
	/// subtracting candidates) would leave `id0` unpinned here — it was
	/// still in `history` as of bob's last successful state update — and
	/// only pick it up after a LATER recompute, which the retry below
	/// would still need in order for the catch-up to succeed; asserting
	/// success is already true at the fault point rules that out.
	#if DEBUG
		func testPinnedBeforeEvictionHealsOnRetryAndAcceptsTheCatchUp() throws {
			OracleCheck.allow([.recvClassical, .sendClassical, .recvPQ, .sendPQ])
			defer { OracleCheck.allow([]) }
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			let id0 = bob.identity.clientID

			// Phases 1-3 setup, verbatim from `testRule4Pin`, up to (but not
			// including) alice folding bob's rotation.
			for step in 1...7 {
				let stepID = Data("pbe-bob-step\(step)".utf8)
				try alice.auth.theirs.commit(stepID)
				try bob.auth.mine.commit(stepID)
			}
			let s7 = try XCTUnwrap(bob.auth.mine.current)
			let (recvSigningKey, recvSignatureKey) =
				try TwoMLSIdentity.mintSignatureKeypair()
			let (sendSigningKey, sendSignatureKey) =
				try TwoMLSIdentity.mintSignatureKeypair()
			bob.leafKeys.recvClassical.pending[s7] = LeafKey(
				signingKey: recvSigningKey, signatureKey: recvSignatureKey)
			bob.leafKeys.sendClassical.pending[s7] = LeafKey(
				signingKey: sendSigningKey, signatureKey: sendSignatureKey)
			_ = try bob.prepareToEncrypt()
			let bobFrame = try bob.encrypt(Data("pbe-bob-catchup".utf8)).frame
			let aliceSaw = try alice.processIncomingDecrypted(bobFrame)
			try alice.queueProposal(digest: aliceSaw.queuedProposal.digest)
			_ = try alice.prepareToEncrypt()
			let aliceFoldFrame = try alice.encrypt(Data("pbe-alice-catchup-fold".utf8))
				.frame
			_ = try bob.processIncomingDecrypted(aliceFoldFrame)

			let s8 = Data("pbe-bob-step8".utf8)
			_ = try bob.prepareToEncrypt(rotating: s8)
			let rotationOfferFrame = try bob.encrypt(Data("pbe-bob-rotate-offer".utf8))
				.frame
			let aliceSawRotation = try alice.processIncomingDecrypted(
				rotationOfferFrame)
			try alice.queueProposal(digest: aliceSawRotation.queuedProposal.digest)
			_ = try alice.prepareToEncrypt()
			// THE EVICTING FRAME: folding this into alice's recv-classical
			// canonicalizes bob onto `s8`, evicting `id0` from history.
			let rotationFoldFrame = try alice.encrypt(
				Data("pbe-alice-rotation-fold".utf8)
			)
			.frame

			TwoMLSSessionTestHooks.armFault(
				"processMessageFrame.afterStapleBeforeDecrypt")
			defer { TwoMLSSessionTestHooks.disarmAllFaults() }
			XCTAssertThrowsError(try bob.processIncoming(rotationFoldFrame))

			// The classical eviction has already landed on `self` (inside
			// `handleStaple`, before this call's own `stateUpdate` was ever
			// reached) — yet `pinned` ALREADY covers `id0`, from bob's last
			// successful state update, well before this eviction.
			XCTAssertFalse(bob.auth.mine.history.contains(id0))
			XCTAssertTrue(
				bob.auth.mine.pinned.contains(id0),
				"pinned before eviction — the normal form pins every "
					+ "presented id, not only ones already absent from history"
			)

			// Retry: an idempotent re-ride of the already-applied fold,
			// which reaches the real `stateUpdate` this time — `pinned`
			// stays stable across it.
			_ = try bob.processIncomingDecrypted(rotationFoldFrame)
			XCTAssertTrue(bob.auth.mine.pinned.contains(id0))

			// bob's own PQ leaves still lag (unmoved by any of the above) —
			// the genuine catch-up now succeeds end to end. Alice's own
			// `pqRekeyRespond` is unaffected by bob's gap (her own pin was
			// recomputed at her own earlier `prepareToEncrypt`) — the
			// property this test targets is bob's own `pqRekeyApply`, whose
			// adjudication checks THIS id-move against `bob.auth.mine`
			// (his own view of himself), which only just healed above.
			let currentID = try XCTUnwrap(bob.auth.mine.current)
			let round = try handBuildPQLeafMoveUpd(proposer: &bob, newID: currentID)
			let commitFrame = try alice.pqRekeyRespond(round.frame)
			bob.pqInflight = .rekeyInitiated(updMessage: round.bytes)
			bob.pendingSideBand = round.frame
			XCTAssertNoThrow(try bob.pqRekeyApply(commitFrame.frame))
		}
	#endif

	// MARK: - Races cost one extra round, never a stall

	/// `protocol-flows.md:56`: a rotation landing while an A.5 `Upd′` is
	/// in flight does not re-mint that round. Exercises the actual race:
	/// Bob folds Alice's rotation, AND Alice applies that fold, WHILE her
	/// A.5 `Upd′` is still `.rekeyInitiated` — not sequenced after the
	/// round has already completed. The round survives unchanged and
	/// completes normally afterward; her leaf still lags, so her own next
	/// PQ turn (her OWN catch-up — unaffected by C2) must open it.
	func testRotationDuringInFlightA5DoesNotReMintAndCompletesNormally() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		try driveOneA4Round(initiator: &bob, responder: &alice)
		XCTAssertTrue(alice.myPQTurn)

		// Alice opens an A.5 (native path — same-id today).
		let begin = try alice.pqRekeyBegin()
		// PR2: opened via `bob` — the frame's addressee.
		let originalUpdBytes = try Frames.decodePQRekeyUpd(bob.openOrRaw(begin.frame))
		guard case .rekeyInitiated = alice.pqInflight else {
			XCTFail("expected alice to hold .rekeyInitiated")
			return
		}

		// She rotates. Her own offer alone doesn't touch the in-flight
		// round.
		let alice2ID = Data("alice-race-inflight".utf8)
		_ = try alice.prepareToEncrypt(rotating: alice2ID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		guard case .rekeyInitiated = alice.pqInflight else {
			XCTFail("expected the in-flight round to survive the rotation offer")
			return
		}

		// The actual race: bob folds it, AND alice applies that fold,
		// WHILE her A.5 Upd′ is STILL `.rekeyInitiated` — the round
		// hasn't been responded to yet, let alone completed.
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		discardIncidentalSelfDrive(&bob)
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(alice2ID))

		// The round is not re-minted — still the exact same Upd′.
		guard case .rekeyInitiated(let updMessage) = alice.pqInflight else {
			XCTFail("expected the in-flight round to survive the fold landing")
			return
		}
		XCTAssertEqual(updMessage, originalUpdBytes)

		// It completes normally (same-id — real `pqRekeyBegin` can't
		// carry the new id; see `testRotatedOpenerAnnouncesItsCurrentID`).
		let commitFrame = try bob.pqRekeyRespond(begin.frame).frame
		XCTAssertNoThrow(try alice.pqRekeyApply(commitFrame))
		XCTAssertNil(alice.pqInflight)
		XCTAssertNotNil(alice.owedBind)

		// No stall: alice's owed bind discharges cleanly.
		let dischargePrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		discardIncidentalSelfDrive(&alice)
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertNil(alice.owedBind)
		XCTAssertFalse(alice.myPQTurn)
		XCTAssertTrue(bob.myPQTurn)

		// Her recv-PQ leaf (the round's own target) still lags — same-id
		// only — so her credential has not landed anywhere yet.
		let aliceRecvPQ = try TwoMLSSession.ownLeaf(of: try XCTUnwrap(alice.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(aliceRecvPQ.credential), alice.identity.clientID)

		// Bob completes one plain, uneventful A.4 — passes the turn back
		// to alice.
		try driveOneA4Round(initiator: &bob, responder: &alice)
		XCTAssertTrue(alice.myPQTurn)

		// Her own next PQ turn must open her recv-PQ catch-up.
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("next-turn".utf8))
		let opensRekey: Bool
		if case .rekeyInitiated = alice.pqInflight {
			opensRekey = true
		} else {
			opensRekey = false
		}
		XCTExpectFailure(
			"protocol-flows.md:56 — her own next turn must open the recv-PQ catch-up"
		) {
			XCTAssertTrue(opensRekey)
		}
	}

	/// A responder whose rotation staple hasn't applied answers with a
	/// no-move `Commit′`. `protocol-flows.md:56`: "a responder whose own
	/// rotation staple has not yet applied answers with a Commit′ that
	/// moves nothing." Bob has ALREADY folded (committed) Alice's
	/// rotation — his own view of her is canonical — but that fold's
	/// staple hasn't reached Alice yet, so HER OWN AS still shows her old
	/// id as canonical when Bob's A.5 asks her to respond.
	func testResponderRotationStapleNotYetAppliedAnswersWithNoMoveCommit() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertTrue(bob.myPQTurn)

		// Alice proposes a rotation; bob approves and commits (folds) it
		// for real — his OWN view of her canonicalizes — but the
		// resulting fold-frame is held back, not yet delivered to alice.
		let alice2ID = Data("alice-race-staple-not-applied".utf8)
		_ = try alice.prepareToEncrypt(rotating: alice2ID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold-not-yet-delivered".utf8)).frame
		discardIncidentalSelfDrive(&bob)
		XCTAssertEqual(bob.theirPrincipalState, .sync(alice2ID))

		// Bob (still turn holder) opens an A.5 on Alice's send group —
		// the group her own leaf lives in — BEFORE she has ever seen his
		// fold. Her OWN AS still shows her old id, so her responder
		// Commit′ can only be a no-move (same-id) refresh, not a stall.
		// Captured BEFORE the respond: `rotatedCredential` reports the
		// PROPOSER's move (bob's, here — a same-id carrier), not whether
		// the RESPONDER's own leaf moved, so it can't stand in for "a
		// Commit′ that moves nothing" on alice's side. Check her own leaf
		// directly instead.
		let aliceSendPQLeafBefore = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.sendGroup?.pq))
		let aliceSendPQKeyBefore = aliceSendPQLeafBefore.signatureKey

		let begin = try bob.pqRekeyBegin()
		let response = try alice.pqRekeyRespond(begin.frame)
		let aliceSendPQLeafAfter = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.sendGroup?.pq))
		XCTAssertEqual(
			try basicIdentifier(aliceSendPQLeafAfter.credential),
			alice.identity.clientID,
			"protocol-flows.md:56 — \"a Commit′ that moves nothing\": her own leaf must still present her founding id here"
		)
		XCTAssertEqual(aliceSendPQLeafAfter.signatureKey, aliceSendPQKeyBefore)
		XCTAssertNoThrow(try bob.pqRekeyApply(response.frame))
		XCTAssertNil(bob.pqInflight)
		XCTAssertNotNil(bob.owedBind)

		// The fold finally reaches alice — "her own rotation staple"
		// applying — and she answers with an ordinary frame, giving bob
		// the fresh evidence (bound to his post-fold epoch) his upcoming
		// discharge needs (evidence-gating: nothing else licenses a
		// SECOND commit from bob past a peer who hasn't caught up on his
		// first).
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(alice2ID))
		_ = try alice.prepareToEncrypt()
		let aliceAckFrame = try alice.encrypt(Data("alice-ack".utf8)).frame
		_ = try bob.processIncomingDecrypted(aliceAckFrame)

		// Bob discharges — his ack rides the classical staple.
		let dischargePrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8)).frame
		discardIncidentalSelfDrive(&bob)
		_ = try alice.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(alice.myPQTurn)

		// It is her recv-PQ leaf (Group_B.pq — the group her OWN trigger
		// reads) that fires her next turn, not her send-PQ leaf
		// (Group_A.pq, just re-keyed same-id above): both happen to
		// still lag here, but it's the receive-group leaf the book's
		// trigger actually consults.
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("next-turn".utf8))
		let opensRekey: Bool
		if case .rekeyInitiated = alice.pqInflight {
			opensRekey = true
		} else {
			opensRekey = false
		}
		XCTExpectFailure(
			"protocol-flows.md:56 — the next turn must open the catch-up once the responder's rotation lands"
		) {
			XCTAssertTrue(opensRekey)
		}
	}

	// MARK: - A.3-minted leaf born under the then-canonical id

	/// `session-lifecycle.md:202-203` / `group-rules.md:144-145`: "A PQ
	/// leaf minted at A.3 is born under its owner's THEN-canonical id."
	/// Reachable natively: the acceptor (Bob) can rotate classically
	/// before the A.3 bootstrap ever runs — both classical halves are up
	/// right after establishment, and A.3 is fully independent of them.
	/// `pqBootstrapRespond` founds on a freshly minted leaf under
	/// `auth.mine.current` at A.3 time, so a pre-A.3 rotation is already
	/// reflected in the founded leaf.
	func testA3MintedLeafBornUnderThenCanonicalID() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let bobNewID = Data("bob-then-canonical".utf8)

		// Bob rotates BEFORE any A.3 round — purely classical.
		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try alice.processIncomingDecrypted(offerFrame)
		_ = try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(bob.myPrincipalState, .sync(bobNewID))

		// A.3 now runs.
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(bob.isFullyEstablished)

		let foundedLeafID = try basicIdentifier(
			try TwoMLSSession.ownLeaf(of: try XCTUnwrap(bob.sendGroup?.pq)).credential)
		XCTAssertEqual(foundedLeafID, bobNewID)
	}

	// MARK: - C2: the reciprocal A.5 defers until the peer's own A.5 has landed

	/// Deployed-compatibility (NOT book-specified — the book records it in the shipped-anomaly
	/// section, `session-lifecycle.md:291-302`, "Unchecked join," resolution): a conforming
	/// peer defers opening the reciprocal A.5 until the rotated party's OWN A.5 has landed (its
	/// leaf in our send-PQ group presents its current id) — a rotate-before-bind deployed
	/// peer's OWN responder Commit′ would otherwise orphan its recv-PQ key permanently. Our own
	/// catch-up (our leaf lagging) is unaffected — only the reciprocal trigger defers.
	/// Deployed-compatible profile only (§4 C2). Every session is deployed-compatible until
	/// profiles exist (§5), so this runs unconditionally. When profiles land, build the session
	/// under that profile and add a correct-profile twin that asserts the reciprocal A.5 opens
	/// on the first turn. Before Alice's own A.5 lands, Bob's PQ turn opens a plain A.4
	/// (deferral — true today, plain, since the trigger is unconditionally A.4 anyway). After
	/// it genuinely lands (hand-built — `pqRekeyBegin` can't carry an id; see
	/// `testRotatedOpenerAnnouncesItsCurrentID`), Bob's next turn must open the reciprocal A.5
	/// (marker — both the trigger and the deferral condition it would need are unimplemented).
	func testReciprocalDefersUntilOwnA5Lands() throws {
		// Alice's own A.5, once hand-built to genuinely land, mints a
		// store-only key (a PQ leaf move is not a rotation).
		OracleCheck.allow([.recvPQ])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertTrue(bob.myPQTurn)

		let alice2ID = Data("alice-c2-defer".utf8)
		_ = try alice.prepareToEncrypt(rotating: alice2ID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		discardIncidentalSelfDrive(&bob)
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(alice2ID))
		XCTAssertTrue(bob.myPQTurn)

		// Alice sends an ordinary frame back — fresh evidence licensing
		// bob's upcoming A.4 discharge below (his fold above already
		// spent the earlier evidence from her rotation offer).
		_ = try alice.prepareToEncrypt()
		let aliceAckFrame = try alice.encrypt(Data("alice-ack".utf8)).frame
		_ = try bob.processIncomingDecrypted(aliceAckFrame)

		// Before alice's own A.5 has landed anywhere, bob's PQ turn defers
		// to a plain A.4 — true today (plain), matching C2.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("bob-defers".utf8))
		guard case .initiating = bob.pqInflight else {
			XCTFail("expected bob to defer to a plain A.4 before alice's own A.5 lands")
			return
		}

		// Drive that A.4 to completion — flips the turn to alice.
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		_ = try bob.pqRatchetBind(ctFrame)
		let dischargePrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bob-a4-bound".utf8)).frame
		_ = try alice.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(alice.myPQTurn)

		// Alice's own A.5 now genuinely lands (hand-built content driven
		// through the real accept/apply path, which already conforms).
		let round = try handBuildPQLeafMoveUpd(proposer: &alice, newID: alice2ID)
		let commit = try bob.pqRekeyRespond(round.frame)
		XCTAssertEqual(commit.rotatedCredential, alice2ID)
		alice.pqInflight = .rekeyInitiated(updMessage: round.bytes)
		alice.pendingSideBand = round.frame
		XCTAssertNoThrow(try alice.pqRekeyApply(commit.frame))
		let dischargePrepared2 = try alice.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared2.didCommit)
		let boundFrame2 = try alice.encrypt(Data("alice-a5-bound".utf8)).frame
		discardIncidentalSelfDrive(&alice)
		_ = try bob.processIncomingDecrypted(boundFrame2)
		XCTAssertTrue(bob.myPQTurn)

		// Alice's leaf in BOB's group now presents her current id — her
		// own A.5 has landed.
		let aliceLeafAtBob = try peerLeaf(in: try XCTUnwrap(bob.sendGroup?.pq))
		XCTAssertEqual(try basicIdentifier(aliceLeafAtBob.credential), alice2ID)

		// Her leaf in her OWN group (bob's receive group) still lags — now
		// bob's turn must open the reciprocal A.5.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("bob-reciprocal-probe".utf8))
		let opensReciprocal: Bool
		if case .rekeyInitiated = bob.pqInflight {
			opensReciprocal = true
		} else {
			opensReciprocal = false
		}
		XCTExpectFailure(
			"protocol-flows.md:56 / session-lifecycle.md:291-302 (C2) — the reciprocal A.5 must open once the peer's own A.5 has landed"
		) {
			XCTAssertTrue(opensReciprocal)
		}
	}

	// MARK: - The join-key rule

	/// Spec — Group Rules rule 4 plus the A.3 step text (`group-rules.md:154-158` /
	/// `protocol-flows.md:142`): until a leaf moves, its owner signs in that group with the key
	/// the leaf presents. A group joined from a KeyPackage (the A.3 KP′) is signed with that
	/// KeyPackage's key, even if the owner rotated after minting it — moving one group's leaf
	/// never retires a key another group's leaf still presents (that third clause becomes
	/// testable once this engine stores more than one live key per party — today `identity`
	/// holds a single PQ signing key for the session's life, so there is no SECOND stored key
	/// yet whose survival could be checked). A party that rotates classically between KP′ mint
	/// (at `initiate()`) and the A.3 join/bind still signs in its recv-PQ group with KP′'s key:
	/// this is really a D1 guard (`TwoMLSSession+Messaging.swift`'s rotation path never mints or
	/// touches a PQ key), asserted here at the point rule 4 calls out explicitly. Plain: this
	/// already holds today. Reachable natively (no `@testable` state splicing needed for the
	/// setup).
	func testJoinKeyRuleSurvivesRotationBetweenKPMintAndA3Join() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let alice2ID = Data("alice-join-key-rule".utf8)

		// Alice rotates classically — strictly between her KP′'s mint
		// (baked into `alice` from `initiate()`, before this test ever
		// starts) and the A.3 join/bind, which hasn't run yet.
		_ = try alice.prepareToEncrypt(rotating: alice2ID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(alice2ID))

		// KP′'s own presented key, captured BEFORE the join spends
		// `bootstrapKPSecret` (`pqBootstrapJoin` clears it).
		let kpSignatureKey = try XCTUnwrap(alice.bootstrapKPSecret).keyPackage.leafNode
			.signatureKey

		// A.3 now runs — alice joins Group_B.pq off the ORIGINAL KP′.
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(alice.isFullyEstablished)

		// Discharge the join's owed bind — licensed by bob's still-fresh
		// fold-frame evidence — so bob's own `.bootstrapResponded` clears
		// (otherwise a later real PQ call on bob would refuse as
		// `.sessionNotReady`, unrelated to what this test checks).
		let dischargePrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)

		// The leaf's presented key: still KP′'s, untouched by the
		// classical rotation.
		let aliceRecvPQLeaf = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.recvGroup?.pq))
		XCTAssertEqual(aliceRecvPQLeaf.signatureKey, kpSignatureKey)

		// Hand the turn back to alice with one plain, uneventful A.4 (the
		// A.3 discharge above passed it to bob).
		try driveOneA4Round(initiator: &bob, responder: &alice)
		XCTAssertTrue(alice.myPQTurn)

		// An operation signed in that SAME group verifies under that key,
		// via the REAL native path: alice's own `pqRekeyBegin()` signs her
		// Upd′ with `recvPQSigningKey()` — which must resolve to KP′'s key
		// for this to work — and bob's real `pqRekeyRespond`
		// cryptographically verifies it.
		let begin = try alice.pqRekeyBegin()
		XCTAssertNoThrow(try bob.pqRekeyRespond(begin.frame))
	}
}
