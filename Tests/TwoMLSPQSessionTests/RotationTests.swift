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
		// PR2: `frame` is header-sealed on exit; `bob` (the recipient) is the
		// one whose receive window opens it.
		let (tag, messageBytes) = try Frames.decodePQLeg(bob.openOrRaw(frame))
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
		let frame1 = try alice.encrypt(Data("rotate-offer".utf8)).frame
		let decrypted1 = try bob.processIncomingDecrypted(frame1)
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
		let frame2 = try bob.encrypt(Data("bob-fold".utf8)).frame
		let decrypted2 = try alice.processIncomingDecrypted(frame2)
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
		let frame3 = try alice.encrypt(Data("alice-catchup".utf8)).frame
		let decrypted3 = try bob.processIncomingDecrypted(frame3)
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
		let aliceMsg = try alice.encrypt(Data("post-rotation-alice".utf8)).frame
		let fromAlice = try bob.processIncomingDecrypted(aliceMsg)
		XCTAssertEqual(fromAlice.applicationMessage, Data("post-rotation-alice".utf8))

		_ = try bob.prepareToEncrypt()
		let bobMsg = try bob.encrypt(Data("post-rotation-bob".utf8)).frame
		let fromBob = try alice.processIncomingDecrypted(bobMsg)
		XCTAssertEqual(fromBob.applicationMessage, Data("post-rotation-bob".utf8))
	}

	// MARK: - D4/NIT6: classical receive tolerates a same-credential key-only rotation

	/// D4: on the CLASSICAL path, a peer that rotates only its LEAF SIGNING
	/// KEY while keeping the SAME `clientID` is already accepted today — no
	/// code change (`.credentialReplaced` fires on a signature-key-only
	/// change too, `CredentialPresentation` being `Equatable` over both
	/// credential AND key; `TwoPartyRules.validateTwoPartyUpdateCommit`
	/// counts it as an ordinary moved leaf; `PartySequence.validSuccessor`'s
	/// `pred == succ` clause trivially licenses a same-id "successor"). This
	/// is a TEST that pins that tolerance.
	///
	/// The rotating peer must be HAND-ROLLED with raw swift-mls calls (the
	/// `newIdentity:`-carrying `committing(...)` pattern at
	/// `bindPQCommitWithoutInjectedS`-adjacent fixtures / `RotationTests`
	/// above): our own `TwoMLSSession` API cannot drive this scenario at
	/// all — `prepareToEncrypt(rotating: sameID)` rejects a same-id target
	/// outright (`Messaging.swift`, `guard rotating != myCurrentID`), and
	/// even a raw same-id rotating `Upd` staged through the module couldn't
	/// be FOLDED then SIGNED FROM afterward: nothing in this module ever
	/// stages a bare same-id key swap into the stored `leafKeys` (only an
	/// explicit rotation candidate or the rule-4 catch-up target ever
	/// populate `pending`), so the stored key set would hold no entry to
	/// sign from either.
	func testClassicalReceiveToleratesPeerSigningKeyRotationUnderSameCredential() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		// Bob's own copy of Group_B (his `sendGroup`, classical-only
		// pre-bootstrap) — the same logical group Alice mirrors as her
		// `recvGroup`.
		var send = try XCTUnwrap(bob.sendGroup)
		let sameID = bob.identity.clientID
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()

		// A self-committing leaf rotation: SAME `clientID`, a brand-new
		// signing key — exactly the `newIdentity:`-carrying `committing(...)`
		// shape used elsewhere in this file/`BootstrapTests`, just with the
		// credential held fixed.
		let transition = try send.classical.committing(
			SessionTestSupport.classicalProvider, proposals: [],
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.classicalProvider,
				current: try bob.sendClassicalSigningKey(), new: freshSigningKey),
			randomness: try .generate(SessionTestSupport.classicalProvider),
			includePath: true, framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: sameID),
				signatureKey: freshSignatureKey))
		let adopted = transition.group
		let sent = transition.takeOutput()
		let commitBytes = try sent.message.mlsEncoded()
		let advanced = try sent.takePending().apply(onto: adopted)
		send.classical = advanced.group

		// A routine `Upd(self)`, staged for the NEXT round and already
		// re-signed under the just-rotated key (§11 MF3's every-round shape).
		let (nextProposal, _) = try send.classical.proposeUpdate(
			SessionTestSupport.classicalProvider, signingKey: freshSigningKey,
			framing: .publicMessage)
		let proposalBytes = try nextProposal.mlsEncoded()
		let proposalHash = try SessionTestSupport.classicalProvider.hash(proposalBytes)

		// The app payload, PROTECTED ON THE POST-ROTATION EPOCH under the new
		// key — `unprotect` verifies a PrivateMessage's signature against the
		// sender leaf's CURRENTLY presented key, so a clean decrypt below is
		// itself the "subsequent verify uses the new key" proof.
		let appPM = try send.classical.protect(
			SessionTestSupport.classicalProvider,
			applicationData: Data("bob-rotated".utf8),
			authenticatedData: proposalHash, signingKey: freshSigningKey)
		let appBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()

		let staple = Frames.encodeMlsMessageStaple(commitBytes)
		let proposalSection = Frames.encodeProposalSection(
			proposing: sameID, message: proposalBytes)
		// Unsealed, like `testCorruptedBindStapleIsRejected`'s hand-rolled
		// frame: `openOrRaw` tries a header-open first and falls back to
		// treating an unsealable blob as already-raw, so a hand-rolled
		// caller with no header key of its own needs no seal step.
		let frame = Frames.encodeMessageFrame(
			staple: staple, proposal: proposalSection, app: appBytes)

		let decrypted = try alice.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-rotated".utf8))
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertFalse(decrypted.ownCredentialCanonicalized)

		// D3: `canonicalize` (+ClassicalCommit.swift) sets `newSender` only
		// on an id change — a same-id key-only refresh is accepted and
		// canonicalizes nothing.
		XCTAssertNil(decrypted.newSender)
		XCTAssertEqual(alice.theirPrincipalState, .sync(sameID))
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
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
		_ = try bob.processIncomingDecrypted(catchUpFrame)

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
		let refreshFrame = try bob.encrypt(Data("refresh".utf8)).frame
		_ = try alice.processIncomingDecrypted(refreshFrame)

		// §A.3 bootstrap — PQ founding stays on the founding identity
		// throughout slice 6, unaffected by the classical rotation above.
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(bob.myPQTurn)

		// §A.4: Bob (turn-holder) stages the EK; Alice responds with the CT,
		// signed under her NEW classical key.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		XCTAssertNoThrow(try bob.pqRatchetBind(ctFrame))

		// Discharge Bob's owed bind — flips the PQ turn to Alice (the
		// rotator), who becomes the turn-holder for the two MF4 custody
		// pins below.
		XCTAssertNotNil(bob.owedBind)
		let dischargePrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame2 = try bob.encrypt(Data("bound-2".utf8)).frame
		_ = try alice.processIncomingDecrypted(boundFrame2)
		XCTAssertTrue(alice.myPQTurn)

		// Alice's recv-PQ leaf — joined at §A.3 off her identity's original
		// KeyPackage — still presents her pre-rotation id, so her own next
		// turn opens the catch-up instead of a plain A.4. Drive it, then
		// hand the turn back with one plain, uneventful A.4, so the MF4
		// assertions below see alice holding the turn with nothing lagging.
		let catchUpTag = try SessionTestSupport.drivePQRound(
			initiator: &alice, responder: &bob)
		XCTAssertEqual(catchUpTag, Frames.pqRekeyUpdTag)
		let handBackTag = try SessionTestSupport.drivePQRound(
			initiator: &bob, responder: &alice)
		XCTAssertEqual(handBackTag, Frames.pqEKTag)
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
		let bobOfferFrame = try bob.encrypt(Data("bob-offer".utf8)).frame
		let decryptedOffer2 = try alice.processIncomingDecrypted(bobOfferFrame)
		_ = try alice.queueProposal(digest: decryptedOffer2.queuedProposal.digest)

		let parkedEpoch = try XCTUnwrap(alice.sendGroup?.classical.context.epoch)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		XCTAssertEqual(alice.sendGroup?.classical.context.epoch, parkedEpoch + 1)
		let aliceFoldFrame = try alice.encrypt(Data("alice-fold".utf8)).frame

		let rewrappedEKFrame = try XCTUnwrap(alice.pqPendingOutbound())
		// PR2: `pqPendingOutbound()` re-seals under a fresh nonce on every
		// call, so the SEALED bytes always differ even for an unchanged
		// plaintext — compare the OPENED plaintexts instead (the outer
		// header epoch — alice's recv group, Group_B — hasn't moved here,
		// so `bob`'s window already opens both). `tryOpen` + `XCTUnwrap`
		// rather than `openOrRaw`: a frame that fails to open must fail the
		// test, not silently compare equal (or not) as still-sealed bytes.
		let openedRewrapped = try XCTUnwrap(bob.tryOpen(rewrappedEKFrame))
		let openedOriginal = try XCTUnwrap(bob.tryOpen(originalEKFrame))
		XCTAssertNotEqual(
			openedRewrapped, openedOriginal,
			"rewrapSideBand must have re-minted the stale leg at the new epoch")

		// Bob must actually apply Alice's fold before his recv mirror can
		// open a leg framed at the new epoch.
		_ = try bob.processIncomingDecrypted(aliceFoldFrame)
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
	/// (the stored `leafKeys` slot the dropped candidate would have named
	/// is gone, so the live choke point can no longer find a match for
	/// what the tree presents) — unrecoverable. The fix instead throws
	/// `.rotationInFlight`, and the session stays fully usable afterward.
	func testSecondRotationAfterFullConvergenceIsRotationInFlightAndSessionNotBricked() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceNewID = Data("alice-converged-v2".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)

		// Alice's own-leaf catch-up: BOTH her classical leaves now present
		// `aliceNewID` — the rotation has fully converged.
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
		_ = try bob.processIncomingDecrypted(catchUpFrame)
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
		let aliceMsg = try alice.encrypt(Data("post-rejected-rotation".utf8)).frame
		let fromAlice = try bob.processIncomingDecrypted(aliceMsg)
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
		let bobFrame = try bob.encrypt(Data("bob-app".utf8)).frame
		// PR2: opened via `alice` (the recipient).
		let (staple, _, app) = try Frames.decodeMessageFrame(alice.openOrRaw(bobFrame))
		let craftedProposal = Frames.encodeProposalSection(
			proposing: bob.identity.clientID, message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncomingDecrypted(craftedFrame)
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
		let frame1 = try bob.encrypt(Data("bob-rotate".utf8)).frame
		let decrypted1 = try alice.processIncomingDecrypted(frame1)
		_ = try alice.queueProposal(digest: decrypted1.queuedProposal.digest)
		let prepared = try alice.prepareToEncrypt()
		XCTAssertEqual(prepared.committedRemoteClientID, bobV2ID)
		XCTAssertEqual(alice.theirPrincipalState, .sync(bobV2ID))

		let foldFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)

		// Bob's own-leaf catch-up: a PLAIN `prepareToEncrypt()` converges his
		// SEND-leaf to `bobV2` too, before the rollback is ever authored.
		let catchUpPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(catchUpPrepared.didCommit)
		let catchUpFrame = try bob.encrypt(Data("bob-catchup".utf8)).frame
		_ = try alice.processIncomingDecrypted(catchUpFrame)
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
		let carrierFrame = try bob.encrypt(Data("carrier".utf8)).frame
		// PR2: opened via `alice` (the recipient).
		let (staple, _, app) = try Frames.decodeMessageFrame(alice.openOrRaw(carrierFrame))
		let rollbackProposal = Frames.encodeProposalSection(
			proposing: bobOriginalID, message: rollbackBytes)
		let rollbackFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: rollbackProposal, app: app)

		let decrypted2 = try alice.processIncomingDecrypted(rollbackFrame)
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
		let bobFrame = try bob.encrypt(Data("bob-app".utf8)).frame
		// PR2: opened via `alice` (the recipient).
		let (staple, _, app) = try Frames.decodeMessageFrame(alice.openOrRaw(bobFrame))
		let craftedProposal = Frames.encodeProposalSection(
			proposing: alice.identity.clientID, message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncomingDecrypted(craftedFrame)
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
		let bobFrame = try bob.encrypt(Data("bob-app".utf8)).frame
		// PR2: opened via `alice` (the recipient).
		let (staple, _, app) = try Frames.decodeMessageFrame(alice.openOrRaw(bobFrame))
		let craftedProposal = Frames.encodeProposalSection(
			proposing: aliceCandidateID, message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncomingDecrypted(craftedFrame)
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
		let bobFrame = try bob.encrypt(Data("bob-app".utf8)).frame
		// PR2: opened via `alice` (the recipient).
		let (staple, _, app) = try Frames.decodeMessageFrame(alice.openOrRaw(bobFrame))
		let craftedProposal = Frames.encodeProposalSection(
			proposing: alice.identity.clientID, message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncomingDecrypted(craftedFrame)
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
		let aliceOldSigningKey = try alice.sendClassicalSigningKey()
		let aliceNewID = Data("alice-old-key-test".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
		_ = try bob.processIncomingDecrypted(catchUpFrame)

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
		XCTAssertThrowsError(try bob.processIncomingDecrypted(forgedFrame))
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
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame

		// PR2: opened via `alice` (the recipient); the reconstructed
		// `tamperedFrame` below passes straight through `processIncoming`'s
		// `openOrRaw` (an unsealable blob is returned as-is).
		let (staple, proposal, app) = try Frames.decodeMessageFrame(
			alice.openOrRaw(foldFrame))
		var tamperedStaple = staple
		tamperedStaple[tamperedStaple.index(before: tamperedStaple.endIndex)] ^= 0xFF
		let tamperedFrame = Frames.encodeMessageFrame(
			staple: tamperedStaple, proposal: proposal, app: app)

		let epochBefore = alice.recvGroup?.classical.context.epoch
		let principalBefore = alice.myPrincipalState
		XCTAssertEqual(principalBefore, .pending(old: aliceOldID, new: aliceNewID))
		XCTAssertThrowsError(try alice.processIncomingDecrypted(tamperedFrame))
		XCTAssertEqual(alice.recvGroup?.classical.context.epoch, epochBefore)
		XCTAssertEqual(alice.myPrincipalState, principalBefore)

		// The genuine frame still applies correctly afterward — no state was
		// corrupted by the failed attempt.
		let decrypted = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertTrue(decrypted.ownCredentialCanonicalized)
		XCTAssertEqual(alice.myPrincipalState, .sync(aliceNewID))
	}

	// MARK: - Mutation-verify: the effects reshape still rejects a roster change

	/// A commit that folds Alice's genuinely-rotating Upd BY REFERENCE
	/// alongside an extra `Add` is still `.invalidFoldEffects` — slice 6
	/// widens the union/count validator to accept `.credentialReplaced` as an
	/// equivalent leaf-move to `.updated`, but never touches the
	/// Add/Remove/`membershipRemoved` allow-list. Mirrors
	/// `FoldTests.testFoldEffectsWithAnAddThrowsUnexpectedProposal`, swapping
	/// a routine fold for a rotating one.
	func testRotatingFoldWithRosterAddStillThrowsUnexpectedProposal() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceNewID = Data("alice-roster-v2".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		let rotatingMessage = try XCTUnwrap(bob.queuedProposal?.message)

		guard let sendGroupB = bob.sendGroup else {
			XCTFail("expected bob to be established")
			return
		}
		let mallory = try SessionTestSupport.identity("mallory-rotation")

		let badCommitBytes = try withDeployedWireConventions { () throws -> Data in
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
				proposalStore: proposalStore,
				signingKey: try bob.sendClassicalSigningKey(),
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage)
			return try transition.takeOutput().message.mlsEncoded()
		}

		let badStaple = Frames.encodeMlsMessageStaple(badCommitBytes)
		_ = try alice.prepareToEncrypt()
		let carrierFrame = try alice.encrypt(Data("carrier".utf8)).frame
		// PR2: opened via `bob` (the recipient) — the app section is a
		// throwaway filler `alice.processIncoming` never reaches (the fold
		// staple is rejected first).
		let (_, proposal, app) = try Frames.decodeMessageFrame(bob.openOrRaw(carrierFrame))
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposal, app: app)

		// The exact-id inline allow-list (`TwoPartyRules.validateInlineProposals`)
		// now catches the smuggled `Add` before `validating` ever runs, so
		// this now throws `.unexpectedProposal` rather than reaching the
		// post-apply `.invalidFoldEffects` shape check. Same rejection,
		// earlier gate.
		let recvEpochBefore = alice.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try alice.processIncomingDecrypted(badFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .unexpectedProposal)
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
	/// ONLY thing that catches this; the shape allow-list alone would wave
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

		let badCommitBytes = try withDeployedWireConventions { () throws -> Data in
			let transition = try sendGroupB.classical.committing(
				SessionTestSupport.classicalProvider,
				proposals: [],
				sign: MLS.RFC9420.signingClosure(
					SessionTestSupport.classicalProvider,
					current: try bob.sendClassicalSigningKey(),
					new: freshSigningKey),
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage,
				newIdentity: MLS.RFC9420.NewSigningIdentity(
					credential: .basic(identity: neverOfferedID),
					signatureKey: freshSignatureKey))
			return try transition.takeOutput().message.mlsEncoded()
		}

		let badStaple = Frames.encodeMlsMessageStaple(badCommitBytes)
		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8)).frame
		// PR2: opened via `alice` (the recipient) — the app section is a
		// throwaway filler `alice.processIncoming` never reaches (the fold
		// staple is rejected first).
		let (_, proposal, app) = try Frames.decodeMessageFrame(
			alice.openOrRaw(carrierFrame))
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposal, app: app)

		let recvEpochBefore = alice.recvGroup?.classical.context.epoch
		let theirsBefore = alice.auth.theirs
		XCTAssertThrowsError(try alice.processIncomingDecrypted(badFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}
		XCTAssertEqual(alice.recvGroup?.classical.context.epoch, recvEpochBefore)
		XCTAssertEqual(alice.auth.theirs, theirsBefore)
	}

	/// The `0x05` bind-riding counterpart: a genuine PQ bind commit (the
	/// real, untouched `owed.pqCommitMessage`) stapled alongside a
	/// hand-built classical bind commit whose `newIdentity` names a
	/// NEVER-OFFERED id — correct PSKs, correct attestation, so it clears
	/// `verifyFullCommitAttestation` and the shape allow-list
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
		let helloFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(helloFrame)

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)

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
		// only the never-offered `newIdentity` below is malicious. The `.custom`
		// wrapped form, matching what `applyBind`'s `withDeployedWireConventions`
		// ambient now expects to decode — a bare `.appDataUpdate` would misparse
		// under that ambient instead of reaching the adjudicate seam this test
		// targets. The body encode itself must run under the same ambient (the
		// deployed `.uint32` `ComponentID` width), since — unlike the typed
		// `.appDataUpdate` arm, which defers encoding until `committing` below —
		// `.custom`'s `body` is already-encoded `Data` at construction time.
		let attestation = MLS.Combiner.ApqInfoUpdate(
			tEpoch: owed.tEpoch, pqEpoch: owed.pqEpoch)
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(
				apqPSK.proposal(
					nonce: SessionTestSupport.classicalProvider.randomBytes(
						SessionTestSupport.classicalProvider.hashSize))),
			.proposal(
				.custom(
					type: .init(.appDataUpdate),
					body: try withDeployedWireConventions {
						try attestation.appDataUpdate(
							componentID: MLS.Combiner.Codepoints
								.deployed.apqComponentID
						).mlsEncoded()
					})
			),
		]

		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let neverOfferedID = Data("mallory-bind-never-offered".utf8)

		let (proposalMessage, _) = try recv.classical.proposeUpdate(
			SessionTestSupport.classicalProvider,
			signingKey: try alice.recvClassicalSigningKey(),
			framing: .publicMessage)
		let proposalBytes = try proposalMessage.mlsEncoded()
		let proposalHash = try SessionTestSupport.classicalProvider.hash(proposalBytes)

		let (commitBytes, advancedClassical): (Data, MLS.RFC9420.Group) =
			try withDeployedWireConventions {
				let transition = try send.classical.committing(
					SessionTestSupport.classicalProvider, proposals: proposals,
					sign: MLS.RFC9420.signingClosure(
						SessionTestSupport.classicalProvider,
						current: try alice.sendClassicalSigningKey(),
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

		XCTAssertThrowsError(try bob.processIncomingDecrypted(frame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}

		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, bobRecvClassicalEpochBefore)
		XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, bobRecvPQEpochBefore)
		XCTAssertEqual(bob.auth.theirs, bobTheirsBefore)
	}

	// MARK: - Evidence-gating: an unlicensed own-leaf catch-up must not commit

	/// B1 — the §A.3-bootstrap wedge: with a lagging send-leaf
	/// (`rotationCandidate` live), an owed bind parked, and Bob's licensing Upd
	/// NOT yet applied (`peerAppliedSendEpoch == nil`), an unlicensed
	/// `prepareToEncrypt` must NOT commit. Pre-fix the catch-up fired
	/// unlicensed: the `0x00` staple advanced Alice's send group past the owed
	/// bind's reserved epoch, and every later licensed discharge threw
	/// `.epochDesync` forever. Post-fix the catch-up is deferred until the
	/// license re-arrives, then lands TOGETHER with the bind on one `0x05`
	/// round. `pqBootstrapJoin` requires `pendingProposal == nil`, so the
	/// rotation offer's `encrypt` runs before the bootstrap join. Cites
	/// `protocol-flows.md` §Evidence-gating.
	func testUnlicensedBootstrapOwnLeafCatchUpDoesNotCommit() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceNewID = Data("alice-evidence-b1".utf8)

		// Rotation round: Alice's recv-leaf canonicalizes, her send-leaf lags.
		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(aliceNewID))
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: alice.recvGroup!.classical).credential),
			aliceNewID)
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: alice.sendGroup!.classical).credential),
			alice.identity.clientID, "the send-classical leaf documentedly lags")

		// §A.3 bootstrap: Bob founds Group_B.pq, Alice joins and owes the bind.
		// `pendingProposal` is nil (the offer's `encrypt` cleared it), so the
		// join is not blocked by its own guard.
		XCTAssertNil(alice.pendingProposal)
		let sendEpochBefore = try XCTUnwrap(alice.sendGroup?.classical.context.epoch)
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertNotNil(alice.owedBind)
		XCTAssertEqual(alice.sendGroup?.classical.context.epoch, sendEpochBefore)

		// Simulate Bob's licensing Upd never having arrived.
		alice.peerAppliedSendEpoch = nil

		let prepared = try alice.prepareToEncrypt()
		XCTAssertFalse(prepared.didCommit, "an unlicensed catch-up must not commit")
		XCTAssertNotNil(alice.owedBind)
		XCTAssertEqual(alice.sendGroup?.classical.context.epoch, sendEpochBefore)
		let stalledStapleKind = Frames.stapleKind(alice.currentStaple.first!)
		XCTAssertNotEqual(stalledStapleKind, .mlsMessage)
		XCTAssertNotEqual(stalledStapleKind, .apqPrivateMessage)

		// Re-license: Bob's next inbound frame stamps our send epoch.
		_ = try bob.prepareToEncrypt()
		let licenseFrame = try bob.encrypt(Data("license".utf8)).frame
		_ = try alice.processIncomingDecrypted(licenseFrame)
		XCTAssertNotNil(alice.peerAppliedSendEpoch)

		// The deferred catch-up and the bind land on ONE licensed round.
		let prepared2 = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared2.didCommit)
		XCTAssertNil(alice.owedBind)
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		// PR2: opened via `bob` (the recipient).
		let (staple, _, _) = try Frames.decodeMessageFrame(bob.openOrRaw(boundFrame))
		XCTAssertEqual(Frames.stapleKind(staple.first!), .apqPrivateMessage)

		let decrypted = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertEqual(decrypted.newSender, aliceNewID)
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: alice.sendGroup!.classical).credential),
			aliceNewID, "the send-classical leaf has now caught up")
	}

	/// B3 — no PQ at all: an unlicensed own-leaf catch-up must not produce a
	/// staple nothing bridges. Same lagging send-leaf, no bootstrap, Bob's
	/// license withheld: `didCommit == false` and the send epoch is unchanged.
	/// Re-license and the deferred catch-up commits; Bob applies it
	/// (`newSender == aliceNewID`). Cites `protocol-flows.md` §Evidence-gating.
	func testUnlicensedOwnLeafCatchUpDoesNotCommit() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceNewID = Data("alice-evidence-b3".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(aliceNewID))

		let sendEpochBefore = try XCTUnwrap(alice.sendGroup?.classical.context.epoch)
		alice.peerAppliedSendEpoch = nil

		let prepared = try alice.prepareToEncrypt()
		XCTAssertFalse(prepared.didCommit, "an unlicensed catch-up must not commit")
		XCTAssertEqual(alice.sendGroup?.classical.context.epoch, sendEpochBefore)
		let stalledStapleKind = Frames.stapleKind(alice.currentStaple.first!)
		XCTAssertNotEqual(stalledStapleKind, .mlsMessage)
		XCTAssertNotEqual(stalledStapleKind, .apqPrivateMessage)

		// Re-license and the deferred catch-up commits.
		_ = try bob.prepareToEncrypt()
		let licenseFrame = try bob.encrypt(Data("license".utf8)).frame
		_ = try alice.processIncomingDecrypted(licenseFrame)
		XCTAssertNotNil(alice.peerAppliedSendEpoch)

		let prepared2 = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared2.didCommit)
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
		// PR2: opened via `bob` (the recipient).
		let (staple, _, _) = try Frames.decodeMessageFrame(bob.openOrRaw(catchUpFrame))
		XCTAssertEqual(Frames.stapleKind(staple.first!), .mlsMessage)
		let decrypted = try bob.processIncomingDecrypted(catchUpFrame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertEqual(decrypted.newSender, aliceNewID)
	}
}

// MARK: - Generalized catch-up retention

@available(iOS 26, macOS 26, *)
extension RotationTests {
	/// An §A.5 `pqRekeyApply` keeps `recvPQ.pending[mine.current]`
	/// when the recv-PQ leaf STILL lags after the apply. The in-flight
	/// race: bob's own begin is minted key-only FIRST, against his
	/// then-current id; only AFTER that does `c` become canonical, with a
	/// held catch-up key supplied out of band (as a migrated session's
	/// mint would). The apply promotes the round's own (same-id) key, and
	/// must retain the now-lagging `pending[c]` it never touched.
	func testRekeyApplyRetainsPQCatchUpKey() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let upd = try bob.pqRekeyBegin().frame

		let c = Data("bob-rust-rotated".utf8)
		let (sk, pk) = try TwoMLSIdentity.mintSignatureKeypair()
		bob.auth.mine.history.append(c)
		bob.leafKeys.recvPQ.pending[c] = LeafKey(signingKey: sk, signatureKey: pk)
		alice.auth.theirs.history.append(c)

		let commit = try alice.pqRekeyRespond(upd).frame
		_ = try bob.pqRekeyApply(commit)
		XCTAssertNotEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq)).credential),
			c, "the apply promoted the round's own (same-id) key, not c")
		XCTAssertEqual(
			bob.leafKeys.recvPQ.pending[c]?.signatureKey, pk,
			"the retained catch-up key")
		XCTAssertEqual(bob.leafKeys.recvPQ.pending.count, 1)
	}

	/// The id-MOVING variant of the race above: bob's own begin targets
	/// `c1` while his leaf lags, then a classical rotation to `c2` lands
	/// WHILE that round is still `.rekeyInitiated` — the self-drive makes
	/// this natively reachable (an explicit-only `pqRekeyBegin` could
	/// never race a self-driven round against itself). The apply promotes
	/// `pending[c1]` (the round's own target) regardless of the later
	/// move; nothing ever staged `pending[c2]`, so `pending` clears
	/// entirely. His own leaf still lags `c2` afterward, so the NEXT begin
	/// mints fresh for it, and the parked target restores.
	func testRekeyApplyDuringIDMovingInFlightRoundThenNextBeginTargetsTheLaterID() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let c1 = Data("bob-race-c1".utf8)
		bob.auth.mine.history.append(c1)
		alice.auth.theirs.history.append(c1)

		let upd = try bob.pqRekeyBegin().frame
		guard case .rekeyInitiated = bob.pqInflight else {
			XCTFail("expected bob to hold .rekeyInitiated after pqRekeyBegin")
			return
		}
		XCTAssertNotNil(bob.leafKeys.recvPQ.pending[c1])

		// The race: a further classical rotation, to c2, lands while the
		// round above is still in flight (bookkeeping-only advance — the
		// actual classical fold mechanics aren't what this test targets).
		// The parked target (c1) now differs from `mine.current` (c2) —
		// restore check 6/7 must still admit it. `mine.current` moving also
		// makes bob's (untouched) recv-CLASSICAL leaf lag, so it needs its
		// own catch-up entry too (restore's check 7, classical arm) — a
		// held key, exactly as a migrated session's mint would supply.
		let c2 = Data("bob-race-c2".utf8)
		bob.auth.mine.history.append(c2)
		alice.auth.theirs.history.append(c2)
		let (recvClassicalSigningKey, recvClassicalSignatureKey) =
			try TwoMLSIdentity.mintSignatureKeypair()
		bob.leafKeys.recvClassical.pending[c2] = LeafKey(
			signingKey: recvClassicalSigningKey, signatureKey: recvClassicalSignatureKey
		)

		let midRaceArchive = try bob.makeSessionArchive(kind: .checkpoint)
		XCTAssertNoThrow(
			try TwoMLSSession.restore(
				core: nil, checkpoint: midRaceArchive,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider))

		let commit = try alice.pqRekeyRespond(upd).frame
		_ = try bob.pqRekeyApply(commit)

		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: XCTUnwrap(bob.recvGroup?.pq)).credential),
			c1, "the apply promoted the round's own target, c1, not the later c2")
		XCTAssertNil(bob.leafKeys.recvPQ.pending[c2], "nothing ever staged a key for c2")
		XCTAssertTrue(
			bob.leafKeys.recvPQ.pending.isEmpty,
			"c1 was promoted, and no entry pins a target the leaf has already moved past"
		)

		// His own leaf still lags c2 — the next begin mints a FRESH round
		// for it, not a re-serve of the stale c1 round. `pqRekeyBegin`
		// refuses while a bind is owed (the apply above owes one); clear it
		// here, isolating this begin from the unrelated classical discharge
		// mechanics a full round would otherwise need to drive first — pure
		// test scaffolding, not real host behavior.
		bob.owedBind = nil
		_ = try bob.pqRekeyBegin()
		guard case .rekeyInitiated(let nextUpdBytes) = bob.pqInflight else {
			XCTFail("expected bob to hold .rekeyInitiated after the fresh begin")
			return
		}
		XCTAssertNotEqual(nextUpdBytes, upd)
		XCTAssertNotNil(bob.leafKeys.recvPQ.pending[c2])
	}

	/// Rotation staging never touches send-classical at all — its own
	/// next committing round mints fresh for whatever id it then presents,
	/// so there is nothing to stage there in advance and nothing for a new
	/// candidate's own recv-classical staging to disturb. Bob's
	/// send-classical leaf already lags `mine.current` (`c`, from an
	/// earlier Rust-won rotation, hand-set here); authoring ANOTHER native
	/// rotation (to `d`) leaves that entry exactly as it was, and stages
	/// nothing send-side for `d` either.
	func testRotationWhileSendLeafLagsLeavesSendClassicalPendingUntouched() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let c = Data("bob-send-lags".utf8)
		let (csk, cpk) = try TwoMLSIdentity.mintSignatureKeypair()
		bob.auth.mine.history.append(c)
		bob.leafKeys.sendClassical.pending[c] = LeafKey(signingKey: csk, signatureKey: cpk)

		let d = Data("bob-new-candidate".utf8)
		let prepared = try bob.prepareToEncrypt(rotating: d)
		XCTAssertFalse(prepared.didCommit, "a fresh candidate offer, not a fold")
		XCTAssertEqual(
			bob.leafKeys.sendClassical.pending[c]?.signatureKey, cpk,
			"a hand-set send-classical entry is left untouched by recv-side staging"
		)
		XCTAssertNil(
			bob.leafKeys.sendClassical.pending[d],
			"the new candidate's key is staged in recv-classical only")
		XCTAssertEqual(bob.leafKeys.sendClassical.pending.count, 1)
		XCTAssertEqual(bob.rotationCandidate?.clientID, d)
	}
}
