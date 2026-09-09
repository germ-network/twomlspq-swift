import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Slice 6: classical principal credential/signature-key rotation, layered on
/// the slice-5 fold path and the real Authentication Service
/// (`CredentialAuthentication.swift`). A rotation round is author → approve →
/// fold → apply: the rotator's `prepareToEncrypt(rotating:)` mints a fresh
/// signature keypair and stages a rotating `Upd(self)` (via the swift-mls
/// rotation ring + `NewSigningIdentity`) into its RECV group (the peer's send
/// group); the peer surfaces it, approves it (`queueProposal`, now AS-gated
/// via `AuthCore.theirs.validSuccessorOfCurrent`), and its own next
/// `prepareToEncrypt`/`committingRound` folds it — canonicalizing the
/// rotator's RECV-leaf first; the rotator's SEND-leaf lags until its own next
/// `committingRound` performs the own-leaf catch-up (§3c), threading the same
/// ring through a `newIdentity`-carrying commit on its own group.
@available(iOS 26, macOS 26, *)
final class RotationTests: XCTestCase {
	/// The occupied leaf OTHER than the caller's own — `ownLeaf(of:)` (the
	/// production custody helper) deliberately always reads `myLeafIndex`,
	/// so a test that wants to read what the PEER's leaf currently presents
	/// (as this group's own perspective sees it) needs this instead.
	private func peerLeafCredential(of group: MLS.RFC9420.Group) throws
		-> MLS.RFC9420.Credential
	{
		guard
			let entry = group.tree.nonBlankLeaves().first(where: {
				$0.index != group.myLeafIndex
			}
			)
		else {
			throw TwoMLSError.credentialUnknown
		}
		return try MLS.RFC9420.LeafNode(mlsEncoded: entry.record.encoded).credential
	}

	/// Hand-craft a rotating `Upd(self)` on `proposer`'s own leaf (in
	/// `proposer.recvGroup`, mirroring `FoldTests.authorBobCredentialRotation`)
	/// naming `newID` as its new `.basic` identity — genuinely ring-signed,
	/// so only an Authentication Service guard (never a signature failure)
	/// is what has to catch a malicious/colliding `newID`.
	private func authorRotatingUpd(
		proposer: inout TwoMLSSession, newID: Data
	) throws -> Data {
		var mirror = try XCTUnwrap(proposer.recvGroup)
		let currentSigningKey = try proposer.recvClassicalSigningKey()
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.classical.proposeUpdate(
			SessionTestSupport.classicalProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.classicalProvider,
				current: currentSigningKey, new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: newID),
				signatureKey: freshSignatureKey))
		proposer.recvGroup = mirror
		return try message.mlsEncoded()
	}

	/// Verify a parked §A.4 EK leg's framing/signature against `bob`'s
	/// mirror on a THROWAWAY copy of `bob.recvGroup` — unlike
	/// `bob.pqRatchetRespond`, this never consumes any of bob's real
	/// inflight state, so it can be called twice (once per custody site
	/// under test) without one call's state transition blocking the other.
	/// Mirrors `processA4Leg`'s core check (`+Ratchet.swift`): `unprotect`
	/// only succeeds if the leg was genuinely signed under whatever key
	/// `bob`'s tree currently shows for the sender's leaf.
	private func verifyEKLegOpensCleanly(_ frame: Data, against bob: TwoMLSSession) throws {
		let (tag, messageBytes) = try Frames.decodePQLeg(frame)
		XCTAssertEqual(tag, Frames.pqEKTag)
		guard
			case .privateMessage(let pm) = try MLS.RFC9420.Message(
				mlsEncoded: messageBytes)
		else {
			XCTFail("expected a privateMessage EK leg")
			return
		}
		var recvCopy = try XCTUnwrap(bob.recvGroup)
		let out = try recvCopy.classical.unprotect(
			SessionTestSupport.classicalProvider, message: pm)
		guard case .application = out.content else {
			XCTFail("expected application content")
			return
		}
	}

	// MARK: - Full round trip (the acceptance test)

	/// Alice rotates end to end: offer → Bob approves + folds (canonicalizing
	/// Alice's RECV-leaf, the first canonicalization) → Alice applies Bob's
	/// staple (`ownCredentialCanonicalized`) → Alice's own-leaf catch-up
	/// (`committingRound`, triggered by a PLAIN `prepareToEncrypt()` with
	/// nothing else queued or owed) moves her SEND-leaf too, which Bob then
	/// applies (`newSender`) — both `PrincipalState`s converge to
	/// `.sync(aliceNewID)`, both of Alice's classical leaves present the new
	/// credential, and app traffic round-trips both directions under the new
	/// key afterward.
	func testFullClassicalRotationRoundTripsBothLeavesAndPrincipalStates() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceOldID = alice.identity.clientID
		let aliceNewID = Data("alice-rotated".utf8)

		// 1: Alice authors the rotation.
		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		XCTAssertEqual(alice.myPrincipalState, .pending(old: aliceOldID, new: aliceNewID))

		// 2: Bob receives the offer and approves it — the AS accepts a
		// genuinely NEW id as a valid successor of Bob's tracked `theirs`.
		let frame1 = try alice.encrypt(Data("rotate-offer".utf8))
		let decrypted1 = try bob.processIncoming(frame1)
		XCTAssertEqual(decrypted1.queuedProposal.proposing, aliceNewID)
		XCTAssertNoThrow(try bob.queueProposal(digest: decrypted1.queuedProposal.digest))

		// 3: Bob folds it into his next commit (on Group_B, his sendGroup) —
		// AS consult point 2: `theirs.commit(aliceNewID)` canonicalizes it in
		// Bob's own ledger before the group advances.
		let groupBEpochBefore = try XCTUnwrap(bob.sendGroup?.classical.context.epoch)
		let prepared2 = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared2.didCommit)
		XCTAssertEqual(prepared2.committedRemoteClientID, aliceNewID)
		XCTAssertEqual(bob.sendGroup?.classical.context.epoch, groupBEpochBefore + 1)
		XCTAssertEqual(bob.theirPrincipalState, .sync(aliceNewID))

		// 4: Alice applies Bob's staple — her RECV-leaf (Group_B mirror)
		// canonicalizes FIRST; her SEND-leaf (Group_A) still lags.
		let frame2 = try bob.encrypt(Data("bob-fold".utf8))
		let decrypted2 = try alice.processIncoming(frame2)
		XCTAssertTrue(decrypted2.didApplyRemoteCommit)
		XCTAssertTrue(decrypted2.ownCredentialCanonicalized)
		XCTAssertNil(decrypted2.newSender)
		XCTAssertEqual(alice.myPrincipalState, .sync(aliceNewID))
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: alice.recvGroup!.classical).credential),
			aliceNewID)
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: alice.sendGroup!.classical).credential),
			aliceOldID,
			"the send-classical leaf documentedly lags until the own-leaf catch-up")

		// 5: Alice's own-leaf catch-up — triggered by a PLAIN
		// `prepareToEncrypt()`, nothing queued or owed — moves her
		// send-classical leaf. Bob applies it and sees `newSender`.
		let prepared3 = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared3.didCommit)
		let frame3 = try alice.encrypt(Data("alice-catchup".utf8))
		let decrypted3 = try bob.processIncoming(frame3)
		XCTAssertTrue(decrypted3.didApplyRemoteCommit)
		XCTAssertEqual(decrypted3.newSender, aliceNewID)
		XCTAssertFalse(decrypted3.ownCredentialCanonicalized)
		XCTAssertEqual(bob.theirPrincipalState, .sync(aliceNewID))
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: alice.sendGroup!.classical).credential),
			aliceNewID, "the send-classical leaf has now caught up")

		// 6: app traffic round-trips both directions under the new key.
		_ = try alice.prepareToEncrypt()
		let aliceMsg = try alice.encrypt(Data("post-rotation-alice".utf8))
		let fromAlice = try bob.processIncoming(aliceMsg)
		XCTAssertEqual(fromAlice.applicationMessage, Data("post-rotation-alice".utf8))

		_ = try bob.prepareToEncrypt()
		let bobMsg = try bob.encrypt(Data("post-rotation-bob".utf8))
		let fromBob = try alice.processIncoming(bobMsg)
		XCTAssertEqual(fromBob.applicationMessage, Data("post-rotation-bob".utf8))
	}

	/// Load-bearing custody regression: after Alice's full rotation converges
	/// (both her classical leaves on the new key), the §A.4 PQ ratchet — three
	/// classical `protect` sites in `+Ratchet.swift`, easily missed — still
	/// signs/verifies correctly. Bob (the PQ turn-holder post-bootstrap)
	/// stages the EK on his own (unrotated) key; Alice's `pqRatchetRespond`
	/// replies with the CT, `protect`-ing it on `sendGroup.classical` under
	/// her NEW key (`sendClassicalSigningKey()`) — Bob's `pqRatchetBind` can
	/// only open it if his tree-derived verification agrees, which it does
	/// only because his `recvGroup` mirror already shows Alice's new key from
	/// the classical rotation above. `protect` never self-verifies, so a
	/// missed custody site would surface ONLY here, at the peer.
	func testA4RatchetLegAfterClassicalRotationVerifiesUnderNewKey() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceNewID = Data("alice-pq-rotated".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8))
		let decryptedOffer = try bob.processIncoming(offerFrame)
		try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8))
		_ = try alice.processIncoming(foldFrame)
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8))
		_ = try bob.processIncoming(catchUpFrame)

		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: alice.sendGroup!.classical).credential),
			aliceNewID)
		XCTAssertEqual(
			try basicIdentifier(peerLeafCredential(of: bob.recvGroup!.classical)),
			aliceNewID)

		// Refresh Alice's discharge license (§5): her catch-up commit above
		// advanced `sendGroup.classical` past the epoch Bob's last inbound
		// frame evidenced, and the upcoming PQ bind needs current evidence
		// to discharge on Alice's very next `prepareToEncrypt`.
		_ = try bob.prepareToEncrypt()
		let refreshFrame = try bob.encrypt(Data("refresh".utf8))
		_ = try alice.processIncoming(refreshFrame)

		// §A.3 bootstrap — PQ founding stays on the founding identity
		// throughout slice 6, unaffected by the classical rotation above.
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)
		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8))
		_ = try bob.processIncoming(boundFrame)
		XCTAssertTrue(bob.myPQTurn)

		// §A.4: Bob (turn-holder) stages the EK; Alice responds with the CT,
		// signed under her NEW classical key.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame)
		XCTAssertNoThrow(try bob.pqRatchetBind(ctFrame))

		// Discharge Bob's owed bind — flips the PQ turn to Alice (the
		// rotator), who becomes the turn-holder for the two MF4 custody
		// pins below.
		XCTAssertNotNil(bob.owedBind)
		let dischargePrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame2 = try bob.encrypt(Data("bound-2".utf8))
		_ = try alice.processIncoming(boundFrame2)
		XCTAssertTrue(alice.myPQTurn)

		// MF4 (a): Alice — the rotator, now turn-holder — self-stages a
		// fresh EK. `stageRatchet` (`+Ratchet.swift:49`) must sign it under
		// her NEW rotated key: `protect` never self-verifies, so a
		// wrong-key mistake there would surface only when Bob opens it.
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("alice-turn".utf8))
		let originalEKFrame = try XCTUnwrap(alice.pqPendingOutbound())
		guard case .initiating = alice.pqInflight else {
			XCTFail("expected alice to hold `.initiating` after self-staging")
			return
		}
		try verifyEKLegOpensCleanly(originalEKFrame, against: bob)

		// MF4 (b): Bob offers Alice a routine (non-rotating) Upd; Alice's
		// own next `prepareToEncrypt` folds it, committing PAST the epoch
		// her parked EK was staged at — `rewrapSideBand`
		// (`+Ratchet.swift:182`) must re-mint that stale leg, again under
		// her NEW key.
		_ = try bob.prepareToEncrypt()
		let bobOfferFrame = try bob.encrypt(Data("bob-offer".utf8))
		let decryptedOffer2 = try alice.processIncoming(bobOfferFrame)
		try alice.queueProposal(digest: decryptedOffer2.queuedProposal.digest)

		let parkedEpoch = try XCTUnwrap(alice.sendGroup?.classical.context.epoch)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		XCTAssertEqual(alice.sendGroup?.classical.context.epoch, parkedEpoch + 1)
		let aliceFoldFrame = try alice.encrypt(Data("alice-fold".utf8))

		let rewrappedEKFrame = try XCTUnwrap(alice.pqPendingOutbound())
		XCTAssertNotEqual(
			rewrappedEKFrame, originalEKFrame,
			"rewrapSideBand must have re-minted the stale leg at the new epoch")

		// Bob must actually apply Alice's fold before his recv mirror can
		// open a leg framed at the new epoch.
		_ = try bob.processIncoming(aliceFoldFrame)
		try verifyEKLegOpensCleanly(rewrappedEKFrame, against: bob)
	}

	// MARK: - CODE FIX 1: a converged rotation must not be droppable

	/// Session-bricking regression: once Alice's rotation has FULLY
	/// canonicalized (both of her classical leaves present the new
	/// credential), a second `prepareToEncrypt(rotating:)` must not replace
	/// the converged `rotationCandidate` — the wedge relaxation's epoch
	/// check alone (`recvGroup.classical`'s epoch has moved past the
	/// staged-at epoch) is ALSO true after a successful convergence, so
	/// without the `auth.mine.history` guard this would silently drop the
	/// very key both leaves now present. Every later `encrypt`/
	/// `prepareToEncrypt` would then throw `.credentialUnknown` forever
	/// (the custody resolver can no longer find a principal matching what
	/// the tree presents) — unrecoverable. The fix instead throws
	/// `.rotationInFlight`, and the session stays fully usable afterward.
	func testSecondRotationAfterFullConvergenceIsRotationInFlightAndSessionNotBricked() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceNewID = Data("alice-converged-v2".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8))
		let decryptedOffer = try bob.processIncoming(offerFrame)
		try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8))
		_ = try alice.processIncoming(foldFrame)

		// Alice's own-leaf catch-up: BOTH her classical leaves now present
		// `aliceNewID` — the rotation has fully converged.
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8))
		_ = try bob.processIncoming(catchUpFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(aliceNewID))
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: alice.sendGroup!.classical).credential),
			aliceNewID)

		XCTAssertThrowsError(
			try alice.prepareToEncrypt(rotating: Data("alice-v3".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .rotationInFlight)
		}

		// The session must NOT be bricked: a plain `prepareToEncrypt`/
		// `encrypt` still works, still signing under `aliceNewID`'s key.
		_ = try alice.prepareToEncrypt()
		let aliceMsg = try alice.encrypt(Data("post-rejected-rotation".utf8))
		let fromAlice = try bob.processIncoming(aliceMsg)
		XCTAssertEqual(fromAlice.applicationMessage, Data("post-rejected-rotation".utf8))
	}

	// MARK: - CODE FIX 2: rotating to my own current id

	/// `rotating` naming my own recv-leaf's CURRENT id (here, the founding
	/// id — no rotation has happened yet) can never converge:
	/// `PartySequence.commit(current)` early-returns as a no-op, so the
	/// offer would sit `.pending` forever with no fold able to
	/// canonicalize it. `prepareToEncrypt(rotating:)` rejects it up front.
	func testRotatingToOwnCurrentIDIsRejected() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertThrowsError(
			try alice.prepareToEncrypt(rotating: alice.identity.clientID)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .credentialUnknown)
		}
	}

	/// The AS-path half of CODE FIX 2: a peer's same-id "rotation" offer
	/// (identical clientID, a fresh signature key only —
	/// `offeredID == auth.theirs.current`) must not leak into
	/// `authorizedNext` — `PartySequence.commit`'s own `current == id`
	/// no-op never clears an authorization stuck there, so a leaked entry
	/// would linger forever. `validateOfferedUpdate` skips the `authorize`
	/// call for this case; `validSuccessorOfCurrent` already accepts it
	/// trivially (`pred == succ`).
	func testSameIDRotationOfferDoesNotLeakIntoAuthorizedNext() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let rotatingMessage = try authorRotatingUpd(
			proposer: &bob, newID: bob.identity.clientID)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8))
		let (staple, _, app) = try Frames.decodeMessageFrame(bobFrame)
		let craftedProposal = Frames.encodeProposalSection(
			proposing: bob.identity.clientID, message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncoming(craftedFrame)
		XCTAssertNoThrow(try alice.queueProposal(digest: decrypted.queuedProposal.digest))
		XCTAssertTrue(alice.auth.theirs.authorizedNext.isEmpty)
	}

	// MARK: - Mutation-verify: F2 one-generation cap

	/// A second `prepareToEncrypt(rotating:)` naming a DIFFERENT id while a
	/// candidate is still outstanding is `.rotationInFlight` — F2's
	/// single-in-flight cap. Naming the SAME candidate again is idempotent.
	func testSecondRotationWithDifferentIDWhileOutstandingIsRotationInFlight() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		_ = try alice.prepareToEncrypt(rotating: Data("alice-v2".utf8))
		XCTAssertThrowsError(try alice.prepareToEncrypt(rotating: Data("alice-v3".utf8))) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .rotationInFlight)
		}
		XCTAssertNoThrow(try alice.prepareToEncrypt(rotating: Data("alice-v2".utf8)))
	}

	// MARK: - Mutation-verify: AS rejects a non-successor / rollback credential

	/// Bob rotates fully to `bobV2` — BOTH his leaves converge (his RECV-leaf
	/// via Alice's fold, his SEND-leaf via his own next catch-up) — then
	/// attempts to "rotate" BACK to his own now-retired original id, a
	/// rollback. `queueProposal`'s AS consult
	/// (`PartySequence.validSuccessor`'s own rollback guard: an
	/// authorized-but-already-retired id falls through to the ordering check
	/// and loses) rejects it as `.invalidSuccession`, before it ever reaches
	/// a commit.
	///
	/// The rollback offer is hand-authored directly on `bob.recvGroup`
	/// (mirroring `FoldTests.authorBobCredentialRotation`) rather than via a
	/// second `prepareToEncrypt(rotating:)` call: F2's single-slot keyring
	/// (§7) cannot represent a THIRD live credential, so first letting bob's
	/// own rotation fully converge (both leaves on `bobV2`, `rotationCandidate`
	/// still `bobV2`) before hand-crafting the rollback keeps this test to
	/// the TWO credentials the minimal cut supports.
	func testRollbackToRetiredCredentialIsRejectedAtQueueProposal() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let bobOriginalID = bob.identity.clientID
		let bobV2ID = Data("bob-v2".utf8)

		_ = try bob.prepareToEncrypt(rotating: bobV2ID)
		let frame1 = try bob.encrypt(Data("bob-rotate".utf8))
		let decrypted1 = try alice.processIncoming(frame1)
		try alice.queueProposal(digest: decrypted1.queuedProposal.digest)
		let prepared = try alice.prepareToEncrypt()
		XCTAssertEqual(prepared.committedRemoteClientID, bobV2ID)
		XCTAssertEqual(alice.theirPrincipalState, .sync(bobV2ID))

		let foldFrame = try alice.encrypt(Data("alice-fold".utf8))
		_ = try bob.processIncoming(foldFrame)

		// Bob's own-leaf catch-up: a PLAIN `prepareToEncrypt()` converges his
		// SEND-leaf to `bobV2` too, before the rollback is ever authored.
		let catchUpPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(catchUpPrepared.didCommit)
		let catchUpFrame = try bob.encrypt(Data("bob-catchup".utf8))
		_ = try alice.processIncoming(catchUpFrame)
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: bob.sendGroup!.classical).credential),
			bobV2ID)

		// Hand-author the rollback: `newIdentity: .basic(bobOriginalID)`,
		// genuinely ring-signed off `bob.recvClassicalSigningKey()` (still
		// `bobV2`'s key — `rotationCandidate` is untouched by this direct
		// construction).
		var mirror = try XCTUnwrap(bob.recvGroup)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (rollbackMessage, _) = try mirror.classical.proposeUpdate(
			SessionTestSupport.classicalProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.classicalProvider,
				current: try bob.recvClassicalSigningKey(), new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: bobOriginalID),
				signatureKey: freshSignatureKey))
		bob.recvGroup = mirror
		let rollbackBytes = try rollbackMessage.mlsEncoded()

		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8))
		let (staple, _, app) = try Frames.decodeMessageFrame(carrierFrame)
		let rollbackProposal = Frames.encodeProposalSection(
			proposing: bobOriginalID, message: rollbackBytes)
		let rollbackFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: rollbackProposal, app: app)

		let decrypted2 = try alice.processIncoming(rollbackFrame)
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted2.queuedProposal.digest)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}
	}

	// MARK: - MF2: the self-id guard (`+ClassicalCommit.swift:98-100`)

	/// A peer's rotating offer naming MY OWN FOUNDING id as its new
	/// credential is `.invalidSuccession` — `theirs.validSuccessor` alone
	/// cannot see `mine`'s sequence (an id I already hold would otherwise
	/// look like a fresh, never-retired successor of the peer's), so
	/// `validateOfferedUpdate`'s `!auth.mine.knownIDs.contains(offeredID)`
	/// guard closes that gap explicitly, before `theirs` is ever consulted.
	func testQueueProposalRejectsOfferNamingApproversFoundingID() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let rotatingMessage = try authorRotatingUpd(
			proposer: &bob, newID: alice.identity.clientID)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8))
		let (staple, _, app) = try Frames.decodeMessageFrame(bobFrame)
		let craftedProposal = Frames.encodeProposalSection(
			proposing: alice.identity.clientID, message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncoming(craftedFrame)
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}
	}

	/// Same guard, the other known-id source: a peer's rotating offer
	/// naming MY OWN in-flight CANDIDATE id (an id sitting in
	/// `auth.mine.authorizedNext`, not yet canonicalized) is also
	/// `.invalidSuccession` — `knownIDs` spans `history` AND
	/// `authorizedNext` AND `pinned`.
	func testQueueProposalRejectsOfferNamingApproversInFlightCandidateID() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceCandidateID = Data("alice-candidate".utf8)
		_ = try alice.prepareToEncrypt(rotating: aliceCandidateID)
		XCTAssertTrue(alice.auth.mine.authorizedNext.contains(aliceCandidateID))

		let rotatingMessage = try authorRotatingUpd(
			proposer: &bob, newID: aliceCandidateID)
		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8))
		let (staple, _, app) = try Frames.decodeMessageFrame(bobFrame)
		let craftedProposal = Frames.encodeProposalSection(
			proposing: aliceCandidateID, message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncoming(craftedFrame)
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}
	}

	// MARK: - M5: value semantics for `theirs` on a rejected offer

	/// A rejected peer offer (`queueProposal` throwing, here via the MF2
	/// self-id guard) must leave `auth.theirs` — its `authorizedNext` in
	/// particular — completely unchanged, not just `mine`.
	/// `validateOfferedUpdate` computes `authCopy.theirs.authorize(...)` on
	/// a LOCAL copy and writes it back to `self.auth` only once every check
	/// (including the self-id guard, which runs first) has passed — so a
	/// throw here must never leak a pending authorization into the real
	/// `auth.theirs`.
	func testRejectedOfferLeavesTheirsUnchanged() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let rotatingMessage = try authorRotatingUpd(
			proposer: &bob, newID: alice.identity.clientID)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8))
		let (staple, _, app) = try Frames.decodeMessageFrame(bobFrame)
		let craftedProposal = Frames.encodeProposalSection(
			proposing: alice.identity.clientID, message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncoming(craftedFrame)
		let theirsBefore = alice.auth.theirs
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}
		XCTAssertEqual(alice.auth.theirs, theirsBefore)
	}

	// MARK: - Mutation-verify: the old key is rejected after rotation

	/// After Alice's classical rotation fully converges, a forged app message
	/// hand-`protect`-ed with her RETIRED `identity.signingKey` (bypassing
	/// `encrypt`, which resolves the correct current key via the custody
	/// resolver) fails Bob's `unprotect` — his tree shows Alice's leaf
	/// presenting the NEW key, so the old signature does not verify.
	func testOldKeyIsRejectedAfterRotation() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceOldSigningKey = alice.identity.signingKey
		let aliceNewID = Data("alice-old-key-test".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8))
		let decryptedOffer = try bob.processIncoming(offerFrame)
		try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8))
		_ = try alice.processIncoming(foldFrame)
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8))
		_ = try bob.processIncoming(catchUpFrame)

		// Both sides now agree Alice's send-classical leaf presents the NEW
		// key — build a forged app message signed with the OLD one instead,
		// entirely off a local throwaway copy (alice's real state untouched).
		_ = try alice.prepareToEncrypt()
		let pending = try XCTUnwrap(alice.pendingProposal)
		guard var send = alice.sendGroup else {
			XCTFail("expected alice to be established")
			return
		}
		let forgedPM = try send.classical.protect(
			SessionTestSupport.classicalProvider, applicationData: Data("forged".utf8),
			authenticatedData: pending.hash, signingKey: aliceOldSigningKey)
		let forgedAppBytes = try MLS.RFC9420.Message.privateMessage(forgedPM).mlsEncoded()
		let proposalSection = Frames.encodeProposalSection(
			proposing: pending.proposing, message: pending.message)
		let forgedFrame = Frames.encodeMessageFrame(
			staple: alice.currentStaple, proposal: proposalSection, app: forgedAppBytes)

		let bobEpochBefore = bob.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try bob.processIncoming(forgedFrame))
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, bobEpochBefore)
	}

	// MARK: - Mutation-verify: value semantics on a throw

	/// A tampered rotating-fold staple throws and burns NEITHER the group NOR
	/// `auth` — Alice's `myPrincipalState` stays `.pending` exactly as it was,
	/// and the genuine (untampered) frame still applies correctly afterward.
	func testTamperedRotatingFoldLeavesGroupAndAuthUnchanged() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceOldID = alice.identity.clientID
		let aliceNewID = Data("alice-tamper-v2".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8))
		let decryptedOffer = try bob.processIncoming(offerFrame)
		try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8))

		let (staple, proposal, app) = try Frames.decodeMessageFrame(foldFrame)
		var tamperedStaple = staple
		tamperedStaple[tamperedStaple.index(before: tamperedStaple.endIndex)] ^= 0xFF
		let tamperedFrame = Frames.encodeMessageFrame(
			staple: tamperedStaple, proposal: proposal, app: app)

		let epochBefore = alice.recvGroup?.classical.context.epoch
		let principalBefore = alice.myPrincipalState
		XCTAssertEqual(principalBefore, .pending(old: aliceOldID, new: aliceNewID))
		XCTAssertThrowsError(try alice.processIncoming(tamperedFrame))
		XCTAssertEqual(alice.recvGroup?.classical.context.epoch, epochBefore)
		XCTAssertEqual(alice.myPrincipalState, principalBefore)

		// The genuine frame still applies correctly afterward — no state was
		// corrupted by the failed attempt.
		let decrypted = try alice.processIncoming(foldFrame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertTrue(decrypted.ownCredentialCanonicalized)
		XCTAssertEqual(alice.myPrincipalState, .sync(aliceNewID))
	}

	// MARK: - Mutation-verify: the effects reshape still rejects a roster change

	/// A commit that folds Alice's genuinely-rotating Upd BY REFERENCE
	/// alongside an extra `Add` is still `.invalidFoldEffects` — slice 6
	/// widens the union/count validator to accept `.credentialReplaced` as an
	/// equivalent leaf-move to `.updated`, but never touches the
	/// Add/Remove/`membershipRemoved` whitelist. Mirrors
	/// `FoldTests.testFoldEffectsWithAnAddThrowsInvalidFoldEffects`, swapping
	/// a routine fold for a rotating one.
	func testRotatingFoldWithRosterAddStillThrowsInvalidFoldEffects() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceNewID = Data("alice-roster-v2".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8))
		let decryptedOffer = try bob.processIncoming(offerFrame)
		try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		let rotatingMessage = try XCTUnwrap(bob.queuedProposal?.message)

		guard let sendGroupB = bob.sendGroup else {
			XCTFail("expected bob to be established")
			return
		}
		let mallory = try SessionTestSupport.identity("mallory-rotation")

		let badCommitBytes = try withDeployedWireWidth { () throws -> Data in
			guard
				case .publicMessage(let updatePub) = try MLS.RFC9420.Message(
					mlsEncoded: rotatingMessage)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			let verified = try sendGroupB.classical.verifying(
				SessionTestSupport.classicalProvider, proposal: updatePub)
			var proposalStore = MLS.RFC9420.ProposalStore()
			let ref = try proposalStore.insert(
				verified, SessionTestSupport.classicalProvider)

			let transition = try sendGroupB.classical.committing(
				SessionTestSupport.classicalProvider,
				proposals: [
					.reference(ref),
					.proposal(.add(mallory.keyPackage.classical)),
				],
				proposalStore: proposalStore, signingKey: bob.identity.signingKey,
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage)
			return try transition.takeOutput().message.mlsEncoded()
		}

		let badStaple = Frames.encodeMlsMessageStaple(badCommitBytes)
		_ = try alice.prepareToEncrypt()
		let carrierFrame = try alice.encrypt(Data("carrier".utf8))
		let (_, proposal, app) = try Frames.decodeMessageFrame(carrierFrame)
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposal, app: app)

		let recvEpochBefore = alice.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try alice.processIncoming(badFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidFoldEffects)
		}
		XCTAssertEqual(alice.recvGroup?.classical.context.epoch, recvEpochBefore)
	}

	// MARK: - MF3: recv-side `adjudicate` (`applyFoldCommit`/`applyBind`)

	/// A commit hand-built directly on the PEER's (Bob's) send group,
	/// threading a `newIdentity` naming a NEVER-OFFERED id through the
	/// committer's own-leaf-catch-up mechanism (`committing(newIdentity:)`)
	/// — bypassing the offer/approve dance entirely, with an empty
	/// proposals list — is shape-valid (exactly one moved leaf, the
	/// committer's own path-refresh) but fails the Authentication
	/// Service's successor check. `applyFoldCommit`'s
	/// `auth.adjudicate(effects)` (`+ClassicalCommit.swift:476`) is the
	/// ONLY thing that catches this; the shape whitelist alone would wave
	/// it through since a `.credentialReplaced` on the committer counts as
	/// an ordinary leaf move.
	func testApplyFoldCommitRejectsNeverOfferedNewIdentityViaAdjudicate() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		guard let sendGroupB = bob.sendGroup else {
			XCTFail("expected bob to be established")
			return
		}
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let neverOfferedID = Data("mallory-never-offered".utf8)

		let badCommitBytes = try withDeployedWireWidth { () throws -> Data in
			let transition = try sendGroupB.classical.committing(
				SessionTestSupport.classicalProvider,
				proposals: [],
				sign: MLS.RFC9420.signingClosure(
					SessionTestSupport.classicalProvider,
					current: bob.identity.signingKey, new: freshSigningKey),
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage,
				newIdentity: MLS.RFC9420.NewSigningIdentity(
					credential: .basic(identity: neverOfferedID),
					signatureKey: freshSignatureKey))
			return try transition.takeOutput().message.mlsEncoded()
		}

		let badStaple = Frames.encodeMlsMessageStaple(badCommitBytes)
		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8))
		let (_, proposal, app) = try Frames.decodeMessageFrame(carrierFrame)
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposal, app: app)

		let recvEpochBefore = alice.recvGroup?.classical.context.epoch
		let theirsBefore = alice.auth.theirs
		XCTAssertThrowsError(try alice.processIncoming(badFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}
		XCTAssertEqual(alice.recvGroup?.classical.context.epoch, recvEpochBefore)
		XCTAssertEqual(alice.auth.theirs, theirsBefore)
	}

	/// The `0x05` bind-riding counterpart: a genuine PQ bind commit (the
	/// real, untouched `owed.pqCommitMessage`) stapled alongside a
	/// hand-built classical bind commit whose `newIdentity` names a
	/// NEVER-OFFERED id — correct PSKs, correct attestation, so it clears
	/// `verifyFullCommitAttestation` and the shape whitelist
	/// (`validateBindClassicalEffects`) cleanly. Only `applyBind`'s
	/// `auth.adjudicate(classicalEffects)` (`+ClassicalCommit.swift:681`)
	/// catches the never-offered identity. Mirrors
	/// `BootstrapTests.testWrongClassicalAttestationIsRejectedAndRolledBack`'s
	/// construction, swapping the bad attestation for a bad `newIdentity`.
	func testApplyBindRejectsNeverOfferedNewIdentityViaAdjudicate() throws {
		let established = try SessionTestSupport.established()
		var alice = established.alice
		var bob = established.bob
		let aliceIdentity = established.aliceIdentity

		_ = try bob.prepareToEncrypt()
		let helloFrame = try bob.encrypt(Data("bob-hello".utf8))
		_ = try alice.processIncoming(helloFrame)

		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		let owed = try XCTUnwrap(alice.owedBind)
		var send = try XCTUnwrap(alice.sendGroup)
		var recv = try XCTUnwrap(alice.recvGroup)

		let bobRecvClassicalEpochBefore = try XCTUnwrap(
			bob.recvGroup?.classical.context.epoch)
		let bobRecvPQEpochBefore = try XCTUnwrap(bob.recvGroup?.pq?.context.epoch)
		let bobTheirsBefore = bob.auth.theirs

		var pqForExport = try XCTUnwrap(send.pq)
		let apqPSK = try MLS.Combiner.ExportedPsk.export(
			from: &pqForExport, SessionTestSupport.pqProvider,
			componentID: MLS.Combiner.Codepoints.deployed.apqComponentID)
		send.pq = pqForExport

		var store = MLS.Combiner.PSKStore()
		store.register(apqPSK)

		// The CORRECT attestation (unlike the sibling attestation test) —
		// only the never-offered `newIdentity` below is malicious.
		let attestation = MLS.Combiner.ApqInfoUpdate(
			tEpoch: owed.tEpoch, pqEpoch: owed.pqEpoch)
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(
				apqPSK.proposal(
					nonce: SessionTestSupport.classicalProvider.randomBytes(
						SessionTestSupport.classicalProvider.hashSize))),
			.proposal(
				try attestation.proposal(
					componentID: MLS.Combiner.Codepoints.deployed.apqComponentID
				)
			),
		]

		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let neverOfferedID = Data("mallory-bind-never-offered".utf8)

		let (proposalMessage, _) = try recv.classical.proposeUpdate(
			SessionTestSupport.classicalProvider, signingKey: aliceIdentity.signingKey,
			framing: .publicMessage)
		let proposalBytes = try proposalMessage.mlsEncoded()
		let proposalHash = try SessionTestSupport.classicalProvider.hash(proposalBytes)

		let (commitBytes, advancedClassical): (Data, MLS.RFC9420.Group) =
			try withDeployedWireWidth {
				let transition = try send.classical.committing(
					SessionTestSupport.classicalProvider, proposals: proposals,
					sign: MLS.RFC9420.signingClosure(
						SessionTestSupport.classicalProvider,
						current: aliceIdentity.signingKey,
						new: freshSigningKey),
					randomness: try .generate(
						SessionTestSupport.classicalProvider),
					includePath: true, framing: .publicMessage,
					psk: store.resolver(),
					newIdentity: MLS.RFC9420.NewSigningIdentity(
						credential: .basic(identity: neverOfferedID),
						signatureKey: freshSignatureKey))
				let adopted = transition.group
				let sent = transition.takeOutput()
				let bytes = try sent.message.mlsEncoded()
				let advanced = try sent.takePending().apply(onto: adopted)
				return (bytes, advanced.group)
			}
		send.classical = advancedClassical

		let appPM = try send.classical.protect(
			SessionTestSupport.classicalProvider, applicationData: Data("bound".utf8),
			authenticatedData: proposalHash, signingKey: freshSigningKey)
		let appBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()

		let badStaple = Frames.encodeAPQPrivateMessage(
			t: commitBytes, pq: owed.pqCommitMessage)
		let proposalSection = Frames.encodeProposalSection(
			proposing: aliceIdentity.clientID, message: proposalBytes)
		let frame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposalSection, app: appBytes)

		XCTAssertThrowsError(try bob.processIncoming(frame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}

		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, bobRecvClassicalEpochBefore)
		XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, bobRecvPQEpochBefore)
		XCTAssertEqual(bob.auth.theirs, bobTheirsBefore)
	}
}
