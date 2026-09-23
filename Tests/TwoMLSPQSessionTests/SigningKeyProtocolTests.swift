import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// Holds the engine to `docs/protocol/signing-keys-and-credential-catch-up.md`
/// (D1, D3, §1, §3, §4 C1, D6). Where the engine already conforms, the
/// assertion is a plain regression guard; where it does not yet, the
/// assertion is wrapped in `XCTExpectFailure` so the run stays green today
/// and turns red once that gap closes.
@available(iOS 26, macOS 26, *)
final class SigningKeyProtocolTests: XCTestCase {

	// MARK: - Own-leaf signature keys

	/// A party's four own-leaf signature keys — one per group it is a member
	/// of (send-classical, recv-classical, send-PQ, recv-PQ).
	private struct OwnLeafSignatureKeys {
		let sendClassical: MLS.SignaturePublicKey
		let recvClassical: MLS.SignaturePublicKey
		let sendPQ: MLS.SignaturePublicKey
		let recvPQ: MLS.SignaturePublicKey

		var all: [MLS.SignaturePublicKey] {
			[sendClassical, recvClassical, sendPQ, recvPQ]
		}
	}

	private func ownLeafSignatureKeys(of session: TwoMLSSession) throws -> OwnLeafSignatureKeys
	{
		OwnLeafSignatureKeys(
			sendClassical: try TwoMLSSession.ownLeaf(
				of: try XCTUnwrap(session.sendGroup?.classical)
			).signatureKey,
			recvClassical: try TwoMLSSession.ownLeaf(
				of: try XCTUnwrap(session.recvGroup?.classical)
			).signatureKey,
			sendPQ: try TwoMLSSession.ownLeaf(
				of: try XCTUnwrap(session.sendGroup?.pq)
			).signatureKey,
			recvPQ: try TwoMLSSession.ownLeaf(
				of: try XCTUnwrap(session.recvGroup?.pq)
			).signatureKey)
	}

	// MARK: - Fixtures

	/// `SessionTestSupport.establishedDedicatedAndApproved()` taken through a
	/// full §A.3 bootstrap round, landing both parties `isFullyEstablished`.
	private func fullyEstablishedDedicatedPair() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession
	) {
		let established = try SessionTestSupport.establishedDedicatedAndApproved()
		var alice = established.alice
		var bob = established.bob
		let begin = try alice.pqBootstrapBegin()
		let respond = try bob.pqBootstrapRespond(begin.frame)
		_ = try alice.pqBootstrapJoin(respond.frame)
		XCTAssertTrue(bob.isFullyEstablished)
		XCTAssertTrue(alice.isFullyEstablished)
		return (alice, bob)
	}

	// MARK: - Hand-built PQ leaf moves (§3)

	/// Hand-builds `proposer`'s own Upd′ into its recv-PQ mirror: `newID` as
	/// the leaf's credential (pass `proposer.identity.clientID` for a
	/// same-id move) and a freshly minted PQ signature key — the PQ-arm
	/// analogue of `RotationTests.authorRotatingUpd`'s classical
	/// construction, genuinely ring-signed so only a successor/presentation
	/// guard (never a signature failure) is what has to catch it.
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
		let bytes = try message.mlsEncoded()
		return (Frames.encodePQRekeyUpd(bytes), bytes)
	}

	/// `handBuildPQLeafMoveUpd`, but re-framed with `authenticatedData` — the
	/// §4 C1 announced id. The leaf's own self-signature (`LeafNodeTBS`) never
	/// covers `authenticatedData` (RFC 9420 §7.2), so the genuinely
	/// ring-signed leaf `proposeUpdate` already produced carries over
	/// unchanged; only the enclosing envelope needs a fresh signature over the
	/// new authenticated data — built from public swift-mls framing
	/// (`FramedContent` + `protectPublic`), since 0.1.3's `proposeUpdate` has
	/// no `authenticatedData:` parameter of its own.
	private func handBuildPQLeafMoveUpdWithAD(
		proposer: inout TwoMLSSession, newID: Data, authenticatedData: Data
	) throws -> (frame: Data, bytes: Data) {
		var mirror = try XCTUnwrap(proposer.recvGroup)
		let currentSigningKey = try proposer.recvPQSigningKey()
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (rawMessage, _) = try mirror.pq!.proposeUpdate(
			SessionTestSupport.pqProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.pqProvider,
				current: currentSigningKey, new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: newID), signatureKey: freshSignatureKey
			))
		guard case .publicMessage(let rawPub) = rawMessage else {
			XCTFail("expected a publicMessage-framed Upd′")
			throw TwoMLSError.malformedSideBandMessage
		}
		let reframed = MLS.RFC9420.FramedContent(
			groupID: rawPub.content.groupID, epoch: rawPub.content.epoch,
			sender: rawPub.content.sender, authenticatedData: authenticatedData,
			content: rawPub.content.content)
		let sealed = try MLS.RFC9420.protectPublic(
			SessionTestSupport.pqProvider, content: reframed,
			groupContext: mirror.pq!.context, confirmationTag: nil,
			signingKey: currentSigningKey, membershipKey: mirror.pq!.epoch.membershipKey
		)
		proposer.recvGroup = mirror
		let bytes = try MLS.RFC9420.Message.publicMessage(sealed).mlsEncoded()
		return (Frames.encodePQRekeyUpd(bytes), bytes)
	}

	/// Hand-builds the Commit′ that folds `updBytes` (already known to be a
	/// `publicMessage` Upd′) into `committer`'s send-PQ, mirroring
	/// `pqRekeyRespond`'s construction minus its id-based gate
	/// (`validatePQLeafMove`) and the C1 announced-id cross-check. Omits
	/// the `0xFF02` cross-party PSK `pqRekeyRespond` conditionally injects —
	/// fine here, since the book allows but never requires it (§1).
	private func handBuildPQRekeyCommit(
		committer: TwoMLSSession, updBytes: Data
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
		let transition = try sendPQ.committing(
			SessionTestSupport.pqProvider, proposals: [.reference(ref)],
			proposalStore: proposalStore, signingKey: try committer.sendPQSigningKey(),
			randomness: try .generate(SessionTestSupport.pqProvider), includePath: true,
			framing: .publicMessage)
		return Frames.encodePQRekeyCommit(try transition.takeOutput().message.mlsEncoded())
	}

	/// `handBuildPQRekeyCommit`, but the COMMITTER's own leaf ALSO carries a
	/// `newIdentity` — the live path against a deployed-engine peer, whose
	/// committer moves its own leaf as part of discharging the round (the
	/// classical ring's `newIdentity:`-on-`committing` pattern, mirroring
	/// `RotationTests`'s own-leaf-catch-up construction, here on the PQ
	/// group). `.framedContent` stays on the committer's CURRENT key (the
	/// enclosing commit still verifies against the pre-commit sender leaf);
	/// `.leafNode`/`.groupInfo` route to the fresh key `committerNewID`
	/// installs.
	private func handBuildPQRekeyCommitWithCommitterMove(
		committer: TwoMLSSession, updBytes: Data, committerNewID: Data
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
		return Frames.encodePQRekeyCommit(try transition.takeOutput().message.mlsEncoded())
	}

	/// Hand-builds a rotating `Upd(self)` from `proposer`'s CURRENT leaf
	/// (genuinely ring-signed, mirroring `RotationTests.authorRotatingUpd`)
	/// naming `newID`, and delivers it to `receiver` inside a full message
	/// frame carrying a throwaway app payload — the classical-side analogue
	/// of `handBuildPQLeafMoveUpd`. Needed because D6 is computed on
	/// RECEIPT, before any `queueProposal` approval — `receiver.auth.theirs`
	/// must already reflect whatever canonical state the test wants BEFORE
	/// this call.
	private func deliverHandBuiltClassicalOffer(
		proposer: inout TwoMLSSession, receiver: inout TwoMLSSession, newID: Data
	) throws -> DecryptResult {
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
				credential: .basic(identity: newID), signatureKey: freshSignatureKey
			))
		proposer.recvGroup = mirror
		let proposalBytes = try message.mlsEncoded()

		var send = try XCTUnwrap(proposer.sendGroup)
		let appPM = try send.classical.protect(
			SessionTestSupport.classicalProvider,
			applicationData: Data("hand-built-offer".utf8), authenticatedData: Data(),
			signingKey: try proposer.sendClassicalSigningKey())
		let appBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()

		let frame = Frames.encodeMessageFrame(
			staple: proposer.currentStaple,
			proposal: Frames.encodeProposalSection(
				proposing: newID, message: proposalBytes),
			app: appBytes)
		return try receiver.processIncomingDecrypted(frame)
	}

	// MARK: - D1: own-leaf keys pairwise distinct

	/// D1: a party's own four leaf keys, and all eight across a pair, must
	/// be pairwise distinct.
	func testD1OwnLeafSignatureKeysArePairwiseDistinct() throws {
		let (initiator, plainAcceptor) = try RatchetTests.fullyEstablishedTurnOnBob()
		try XCTExpectFailure(
			"D1: the initiator's own four leaf keys must be pairwise distinct"
		) {
			try assertFourOwnLeafKeysPairwiseDistinct(initiator)
		}
		try XCTExpectFailure(
			"D1: the plain acceptor's own four leaf keys must be pairwise distinct"
		) {
			try assertFourOwnLeafKeysPairwiseDistinct(plainAcceptor)
		}
		try XCTExpectFailure(
			"D1: all eight own-leaf keys across the plain pair must be pairwise distinct"
		) {
			try assertEightOwnLeafKeysPairwiseDistinct(initiator, plainAcceptor)
		}

		let (initiatorForDedicated, dedicatedAcceptor) = try fullyEstablishedDedicatedPair()
		try XCTExpectFailure(
			"D1: the initiator's own four leaf keys must be pairwise distinct"
		) {
			try assertFourOwnLeafKeysPairwiseDistinct(initiatorForDedicated)
		}
		// The born-dedicated acceptor already keeps its own-identity pair
		// (D's classical+PQ keys) separate from its retained
		// invitation-identity pair, so its own four leaf keys are already
		// pairwise distinct today.
		try assertFourOwnLeafKeysPairwiseDistinct(dedicatedAcceptor)
		try XCTExpectFailure(
			"D1: all eight own-leaf keys across the dedicated pair must be pairwise distinct"
		) {
			try assertEightOwnLeafKeysPairwiseDistinct(
				initiatorForDedicated, dedicatedAcceptor)
		}
	}

	private func assertFourOwnLeafKeysPairwiseDistinct(
		_ session: TwoMLSSession, file: StaticString = #filePath, line: UInt = #line
	) throws {
		let keys = try ownLeafSignatureKeys(of: session)
		XCTAssertEqual(Set(keys.all).count, keys.all.count, file: file, line: line)
	}

	private func assertEightOwnLeafKeysPairwiseDistinct(
		_ alice: TwoMLSSession, _ bob: TwoMLSSession,
		file: StaticString = #filePath, line: UInt = #line
	) throws {
		let aliceKeys = try ownLeafSignatureKeys(of: alice)
		let bobKeys = try ownLeafSignatureKeys(of: bob)
		XCTAssertEqual(Set(aliceKeys.all + bobKeys.all).count, 8, file: file, line: line)
	}

	// MARK: - D3: every own-leaf move mints a fresh key

	/// D3: every own-leaf move must mint a fresh signature key, in that
	/// group only.
	func testD3EveryOwnLeafMoveMintsAFreshKeyInThatGroupOnly() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		_ = try alice.prepareToEncrypt()
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decrypted.queuedProposal.digest)

		let bobKeysBefore = try ownLeafSignatureKeys(of: bob)
		let aliceKeysBefore = try ownLeafSignatureKeys(of: alice)

		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)

		let bobKeysAfter = try ownLeafSignatureKeys(of: bob)
		let aliceKeysAfter = try ownLeafSignatureKeys(of: alice)

		// A PQ key is never equal to a classical key, so these hold today
		// regardless of D3's gap.
		XCTAssertNotEqual(bobKeysAfter.sendClassical, bobKeysAfter.sendPQ)
		XCTAssertNotEqual(bobKeysAfter.sendClassical, bobKeysAfter.recvPQ)
		XCTExpectFailure(
			"D3: a committing round must mint a fresh send-classical signature key"
		) {
			XCTAssertNotEqual(bobKeysBefore.sendClassical, bobKeysAfter.sendClassical)
			XCTAssertNotEqual(bobKeysAfter.sendClassical, bobKeysAfter.recvClassical)
		}
		XCTAssertEqual(bobKeysBefore.recvClassical, bobKeysAfter.recvClassical)
		XCTAssertEqual(bobKeysBefore.sendPQ, bobKeysAfter.sendPQ)
		XCTAssertEqual(bobKeysBefore.recvPQ, bobKeysAfter.recvPQ)

		XCTAssertNotEqual(aliceKeysAfter.recvClassical, aliceKeysAfter.sendPQ)
		XCTAssertNotEqual(aliceKeysAfter.recvClassical, aliceKeysAfter.recvPQ)
		XCTExpectFailure(
			"D3: a folded routine Upd(self) must mint a fresh recv-classical signature key"
		) {
			XCTAssertNotEqual(
				aliceKeysBefore.recvClassical, aliceKeysAfter.recvClassical)
			XCTAssertNotEqual(
				aliceKeysAfter.recvClassical, aliceKeysAfter.sendClassical)
		}
		XCTAssertEqual(aliceKeysBefore.sendClassical, aliceKeysAfter.sendClassical)
		XCTAssertEqual(aliceKeysBefore.sendPQ, aliceKeysAfter.sendPQ)
		XCTAssertEqual(aliceKeysBefore.recvPQ, aliceKeysAfter.recvPQ)
	}

	// MARK: - D1: classical rotation leaves PQ keys unchanged

	/// D1: a classical principal rotation must leave both parties' PQ
	/// own-leaf keys unchanged, even while a real PQ commit (bob's
	/// self-staged A.4, driven to completion below) runs concurrently.
	/// Deliberately stops short of alice's own next PQ turn: once fixed,
	/// that round legitimately opens as her A.5 catch-up and changes her
	/// key (see the catch-up test below), which this guard must not
	/// anticipate.
	func testD1ClassicalRotationLeavesBothPQOwnLeafKeysUnchanged() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let aliceNewID = Data("alice-signing-key-rotated".utf8)

		let aliceKeysBefore = try ownLeafSignatureKeys(of: alice)
		let bobKeysBefore = try ownLeafSignatureKeys(of: bob)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)

		// Bob's own turn-holder auto-drive self-stages an A.4 EK on this
		// fold — drive it to completion, so a real PQ commit lands
		// alongside the rotation below.
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		guard case .initiating = bob.pqInflight else {
			XCTFail("expected bob to hold .initiating after the A.4 self-drive")
			return
		}

		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
		_ = try bob.processIncomingDecrypted(catchUpFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(aliceNewID))

		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		_ = try bob.pqRatchetBind(ctFrame)
		let dischargePrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(dischargePrepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8)).frame
		_ = try alice.processIncomingDecrypted(boundFrame)

		let aliceKeysAfter = try ownLeafSignatureKeys(of: alice)
		let bobKeysAfter = try ownLeafSignatureKeys(of: bob)

		XCTAssertEqual(aliceKeysBefore.sendPQ, aliceKeysAfter.sendPQ)
		XCTAssertEqual(aliceKeysBefore.recvPQ, aliceKeysAfter.recvPQ)
		XCTAssertEqual(bobKeysBefore.sendPQ, bobKeysAfter.sendPQ)
		XCTAssertEqual(bobKeysBefore.recvPQ, bobKeysAfter.recvPQ)
	}

	// MARK: - D3: one proposed Update offer per peer epoch

	/// D3 (proposed): frames within one epoch of the peer's group must
	/// repeat the identical Update offer.
	func testD3OnePrepareToEncryptOfferPerPeerEpoch() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let firstPrepared = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("first".utf8))
		let secondPrepared = try alice.prepareToEncrypt()
		XCTExpectFailure(
			"D3: proposed — one Update offer per peer epoch, repeated across frames"
		) {
			XCTAssertEqual(
				firstPrepared.proposalMessage, secondPrepared.proposalMessage)
		}

		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)

		// Once the peer's commit has moved the epoch, the next offer
		// legitimately differs — true today and under D3 alike.
		let thirdPrepared = try alice.prepareToEncrypt()
		XCTAssertNotEqual(secondPrepared.proposalMessage, thirdPrepared.proposalMessage)
	}

	// MARK: - §3: same-id, key-only PQ Upd′

	/// §3: a same-id PQ leaf move — key-only — must be accepted.
	func testSection3SameIDKeyOnlyPQUpdIsAccepted() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertTrue(bob.myPQTurn)

		let round = try handBuildPQLeafMoveUpd(
			proposer: &bob, newID: bob.identity.clientID)

		XCTAssertNoThrow(try alice.pqRekeyRespond(round.frame))
	}

	// MARK: - §3: PQ leaf catch-up to an already-canonical id

	/// §3: catch-up is canonical-only — a hand-built Upd′ moving the
	/// proposer's PQ leaf to an id already canonical at the peer must be
	/// accepted, and the resulting round must complete.
	func testSection3PQLeafCatchUpToAnAlreadyCanonicalID() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertTrue(bob.myPQTurn)
		let bobNewID = Data("bob-canonical-catchup".utf8)

		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try alice.processIncomingDecrypted(offerFrame)
		_ = try alice.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		XCTAssertEqual(foldPrepared.committedRemoteClientID, bobNewID)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.theirPrincipalState, .sync(bobNewID))

		let round = try handBuildPQLeafMoveUpd(proposer: &bob, newID: bobNewID)
		// A value-type COPY of alice, taken AFTER canonicalization above
		// (bobNewID is already canonical in it) but BEFORE her real
		// `pqRekeyRespond` call below — so that call's own epoch advance on
		// the REAL alice can't invalidate this already-built commit.
		let commitFrame = try handBuildPQRekeyCommit(
			committer: alice, updBytes: round.bytes)

		XCTAssertNoThrow(try alice.pqRekeyRespond(round.frame))

		bob.pqInflight = .rekeyInitiated(updMessage: round.bytes)
		bob.pendingSideBand = round.frame
		XCTAssertNoThrow(try bob.pqRekeyApply(commitFrame))
		XCTAssertNil(bob.pqInflight)
	}

	// MARK: - §3: rejected PQ leaf moves

	/// §3: a move to a NEW id is refused unless that id is already
	/// canonical; a same-id move is exempt (see the same-id test above). An
	/// authorized-but-not-yet-canonical candidate and an id neither party
	/// has ever offered are each refused, at both `pqRekeyRespond`
	/// (`.rekeyProposalRejected`) and `pqRekeyApply` (`.invalidSuccession`),
	/// leaving state untouched. (A genuine rollback needs a PQ leaf already on
	/// a newer canonical id, constructible now via a full catch-up round but
	/// not exercised here — `validSuccessor`'s own rollback ordering is
	/// covered at the AS level by `CredentialAuthenticationTests`.)
	func testSection3RejectsNonCanonicalPQLeafMoves() throws {
		// (a) authorized (approved via `queueProposal`) but not yet folded
		// — not canonical.
		do {
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			let candidateID = Data("bob-authorized-not-canonical".utf8)
			_ = try bob.prepareToEncrypt(rotating: candidateID)
			let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
			let decryptedOffer = try alice.processIncomingDecrypted(offerFrame)
			_ = try alice.queueProposal(digest: decryptedOffer.queuedProposal.digest)
			try assertPQLeafMoveRejectedAtRespondAndApply(
				proposer: &bob, committer: &alice, newID: candidateID)
		}

		// (b) an id neither party has ever offered.
		do {
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			try assertPQLeafMoveRejectedAtRespondAndApply(
				proposer: &bob, committer: &alice,
				newID: Data("nobody-ever-offered-this".utf8))
		}
	}

	/// Hand-builds `proposer`'s own Upd′ naming `newID` and asserts §3's
	/// move is refused at BOTH gates: `committer.pqRekeyRespond`
	/// (`.rekeyProposalRejected`, the id-based belt before any commit is
	/// spent) and, independently, `proposer.pqRekeyApply` of a separately
	/// hand-built Commit′ that bypasses that belt (`.invalidSuccession`, the
	/// apply-side backstop adjudicating `proposer`'s OWN leaf — from
	/// `proposer`'s perspective applying, the folded leaf is `mine` — against
	/// `auth.mine`) — each leaving its side's state untouched, and
	/// `proposer.pqInflight` staying `.rekeyInitiated`.
	private func assertPQLeafMoveRejectedAtRespondAndApply(
		proposer: inout TwoMLSSession, committer: inout TwoMLSSession, newID: Data,
		file: StaticString = #filePath, line: UInt = #line
	) throws {
		let round = try handBuildPQLeafMoveUpd(proposer: &proposer, newID: newID)

		let sendClassicalEpochBefore = committer.sendGroup?.classical.context.epoch
		let sendPQEpochBefore = committer.sendGroup?.pq?.context.epoch
		let stateSeqBefore = committer.stateSeq
		XCTAssertThrowsError(
			try committer.pqRekeyRespond(round.frame), file: file, line: line
		) { error in
			XCTAssertEqual(
				error as? TwoMLSError, .rekeyProposalRejected, file: file,
				line: line)
		}
		XCTAssertNil(committer.pqInflight, file: file, line: line)
		XCTAssertEqual(
			committer.sendGroup?.classical.context.epoch, sendClassicalEpochBefore,
			file: file, line: line)
		XCTAssertEqual(
			committer.sendGroup?.pq?.context.epoch, sendPQEpochBefore, file: file,
			line: line)
		XCTAssertEqual(committer.stateSeq, stateSeqBefore, file: file, line: line)

		let commitFrame = try handBuildPQRekeyCommit(
			committer: committer, updBytes: round.bytes)
		proposer.pqInflight = .rekeyInitiated(updMessage: round.bytes)
		let recvPQEpochBefore = proposer.recvGroup?.pq?.context.epoch
		XCTAssertThrowsError(
			try proposer.pqRekeyApply(commitFrame), file: file, line: line
		) { error in
			XCTAssertEqual(
				error as? TwoMLSError, .invalidSuccession, file: file, line: line)
		}
		guard case .rekeyInitiated = proposer.pqInflight else {
			XCTFail(
				"expected proposer to still hold .rekeyInitiated", file: file,
				line: line)
			return
		}
		XCTAssertEqual(
			proposer.recvGroup?.pq?.context.epoch, recvPQEpochBefore, file: file,
			line: line)
	}

	// MARK: - §3: heal a stuck A.5

	/// A deployed-engine-style stuck A.5: the rotated party (bob, already
	/// canonical at the peer) holds `.rekeyInitiated` with a hand-built
	/// id-and-key-changing Upd′, re-sent every frame while unresolved (§1),
	/// at the responder's current epoch throughout. A deployed-engine
	/// initiator also carries the handed-off id in the authenticated data
	/// (§4 C1); swift-mls's `proposeUpdate` always frames it empty, so this
	/// hand-built frame carries none either.
	func testSection3HealsAStuckDeployedEngineStyleRekey() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertTrue(bob.myPQTurn)
		let bobNewID = Data("bob-stuck-heal".utf8)

		// Built BEFORE alice's AS has canonicalized `bobNewID` — bob's stuck
		// re-sends genuinely fail at first (§1: the frame is re-sent
		// unchanged every round while unresolved).
		let round = try handBuildPQLeafMoveUpd(proposer: &bob, newID: bobNewID)
		bob.pqInflight = .rekeyInitiated(updMessage: round.bytes)
		bob.pendingSideBand = round.frame

		for _ in 0..<3 {
			let sendPQEpochBefore = alice.sendGroup?.pq?.context.epoch
			let stateSeqBefore = alice.stateSeq
			XCTAssertThrowsError(try alice.pqRekeyRespond(round.frame)) { error in
				XCTAssertEqual(error as? TwoMLSError, .rekeyProposalRejected)
			}
			XCTAssertNil(alice.pqInflight)
			XCTAssertEqual(alice.sendGroup?.pq?.context.epoch, sendPQEpochBefore)
			XCTAssertEqual(alice.stateSeq, stateSeqBefore)
		}

		// A classical round, running independently of the stuck A.5, catches
		// alice's AS up to `bobNewID` — the book's §A.5 trigger rule (D5):
		// nothing here specially targets the stuck round.
		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try alice.processIncomingDecrypted(offerFrame)
		_ = try alice.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.theirPrincipalState, .sync(bobNewID))

		// The SAME, still-unchanged stuck Upd′ frame — re-sent once more,
		// exactly as the book's re-send convention has it — now heals.
		bob.pqInflight = .rekeyInitiated(updMessage: round.bytes)
		bob.pendingSideBand = round.frame
		let response = try alice.pqRekeyRespond(round.frame)
		XCTAssertEqual(response.rotatedCredential, bobNewID)

		XCTAssertNoThrow(try bob.pqRekeyApply(response.frame))
		XCTAssertNil(bob.pqInflight)
	}

	// MARK: - `SideBandResult.rotatedCredential`

	/// `rotatedCredential` is nil on a same-id, key-only accepted Upd′, and
	/// equal to the new id on an id-changing one.
	func testRotatedCredentialReportsIDChangeOnlyOnAnAcceptedRekey() throws {
		var (aliceSameID, bobSameID) = try RatchetTests.fullyEstablishedTurnOnBob()
		let sameIDRound = try handBuildPQLeafMoveUpd(
			proposer: &bobSameID, newID: bobSameID.identity.clientID)
		let sameIDResponse = try aliceSameID.pqRekeyRespond(sameIDRound.frame)
		XCTAssertNil(sameIDResponse.rotatedCredential)

		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let bobNewID = Data("bob-rotated-credential".utf8)
		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try alice.processIncomingDecrypted(offerFrame)
		_ = try alice.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)

		let round = try handBuildPQLeafMoveUpd(proposer: &bob, newID: bobNewID)
		let response = try alice.pqRekeyRespond(round.frame)
		XCTAssertEqual(response.rotatedCredential, bobNewID)
	}

	/// `rotatedCredential` is nil on every OTHER side-band call.
	func testRotatedCredentialIsNilForOtherSideBandCalls() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let begin = try alice.pqBootstrapBegin()
		XCTAssertNil(begin.rotatedCredential)
		let respond = try bob.pqBootstrapRespond(begin.frame)
		XCTAssertNil(respond.rotatedCredential)
		_ = try alice.pqBootstrapJoin(respond.frame)

		var (_, turnBob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let rekeyBegin = try turnBob.pqRekeyBegin()
		XCTAssertNil(rekeyBegin.rotatedCredential)

		// A fresh pair, so bob's self-staged EK (below) isn't racing the
		// `.rekeyInitiated` this same session just parked above.
		var (ratchetAlice, ratchetBob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try ratchetBob.prepareToEncrypt()
		_ = try ratchetBob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(ratchetBob.pqPendingOutbound())
		let ratchetRespond = try ratchetAlice.pqRatchetRespond(ekFrame)
		XCTAssertNil(ratchetRespond.rotatedCredential)
	}

	// MARK: - §4 C1: announced id cross-check

	/// §4 C1: an announced id (Upd′'s authenticated data) equal to the
	/// proposed leaf's Basic id is accepted, exactly like the absent-AD case.
	func testSection4AnnouncedIDMatchingLeafIsAccepted() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertTrue(bob.myPQTurn)
		let bobNewID = Data("bob-announced-match".utf8)

		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try alice.processIncomingDecrypted(offerFrame)
		_ = try alice.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)

		let round = try handBuildPQLeafMoveUpdWithAD(
			proposer: &bob, newID: bobNewID, authenticatedData: bobNewID)

		let response = try alice.pqRekeyRespond(round.frame)
		XCTAssertEqual(response.rotatedCredential, bobNewID)
	}

	/// §4 C1: an announced id that disagrees with the proposed leaf's Basic
	/// id is rejected — `.rekeyProposalRejected`, state unchanged — even
	/// though the id itself is already canonical: the leaf credential is
	/// authoritative, but a present, WRONG hint is never silently accepted.
	func testSection4AnnouncedIDMismatchIsRejected() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertTrue(bob.myPQTurn)
		let bobNewID = Data("bob-announced-mismatch".utf8)

		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try alice.processIncomingDecrypted(offerFrame)
		_ = try alice.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)

		let round = try handBuildPQLeafMoveUpdWithAD(
			proposer: &bob, newID: bobNewID,
			authenticatedData: Data("not-the-leaf-id".utf8))

		let sendPQEpochBefore = alice.sendGroup?.pq?.context.epoch
		let stateSeqBefore = alice.stateSeq
		XCTAssertThrowsError(try alice.pqRekeyRespond(round.frame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .rekeyProposalRejected)
		}
		XCTAssertNil(alice.pqInflight)
		XCTAssertEqual(alice.sendGroup?.pq?.context.epoch, sendPQEpochBefore)
		XCTAssertEqual(alice.stateSeq, stateSeqBefore)
	}

	// MARK: - Committer-leaf move at apply (the live deployed-engine path)

	/// The COMMITTER's own leaf moving in the Commit′ — the live path
	/// against a deployed-engine peer, whose committer moves its own leaf as
	/// part of discharging the round (contrast
	/// `assertPQLeafMoveRejectedAtRespondAndApply`'s PROPOSER-leaf case,
	/// which is `mine` from the applying party's perspective). From bob's
	/// (the applier's) perspective the committer, alice, is the peer —
	/// `theirs` — so a non-canonical move is `.invalidSuccession`,
	/// `pqInflight` stays `.rekeyInitiated`, and an honest re-sent Commit′
	/// still applies; a move to an already-canonical id is accepted.
	func testSection3CommitterLeafMoveAtApply() throws {
		// (a) non-canonical: refused, state untouched, an honest re-sent
		// Commit′ still applies.
		do {
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			let begin = try bob.pqRekeyBegin()
			guard case .rekeyInitiated(let updMessage) = bob.pqInflight else {
				XCTFail("expected bob to hold .rekeyInitiated after pqRekeyBegin")
				return
			}

			let nonCanonicalID = Data("alice-committer-non-canonical".utf8)
			let badCommitFrame = try handBuildPQRekeyCommitWithCommitterMove(
				committer: alice, updBytes: updMessage,
				committerNewID: nonCanonicalID)

			let recvPQEpochBefore = bob.recvGroup?.pq?.context.epoch
			XCTAssertThrowsError(try bob.pqRekeyApply(badCommitFrame)) { error in
				XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
			}
			guard case .rekeyInitiated = bob.pqInflight else {
				XCTFail("expected bob to still hold .rekeyInitiated")
				return
			}
			XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, recvPQEpochBefore)

			// The honest Commit′ — via the real `pqRekeyRespond`, on alice's
			// UNTOUCHED sendGroup.pq (the hand-built commit above was built
			// from a local copy and never applied to it) — still applies.
			let honestCommitFrame = try alice.pqRekeyRespond(begin.frame).frame
			XCTAssertNoThrow(try bob.pqRekeyApply(honestCommitFrame))
			XCTAssertNil(bob.pqInflight)
		}

		// (b) canonical: the committer's own leaf may ALSO catch up to an
		// already-canonical id.
		do {
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			let aliceNewID = Data("alice-committer-canonical".utf8)

			// Park bob's own Upd′ FIRST: bob holds the PQ turn, so a
			// classical fold while `pqInflight == nil` would auto-self-drive
			// a NEW PQ round (`encrypt`'s `maybeStageNextRound`) and clobber
			// it before we ever get to hand-build anything.
			_ = try bob.pqRekeyBegin()
			guard case .rekeyInitiated(let updMessage) = bob.pqInflight else {
				XCTFail("expected bob to hold .rekeyInitiated after pqRekeyBegin")
				return
			}

			// Canonicalize `aliceNewID` at bob's AS, via an ordinary
			// classical rotation — exactly like the proposer catch-up tests
			// do for the peer's id.
			_ = try alice.prepareToEncrypt(rotating: aliceNewID)
			let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
			let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
			_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
			let foldPrepared = try bob.prepareToEncrypt()
			XCTAssertTrue(foldPrepared.didCommit)
			let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
			_ = try alice.processIncomingDecrypted(foldFrame)
			XCTAssertEqual(bob.theirPrincipalState, .sync(aliceNewID))

			let commitFrame = try handBuildPQRekeyCommitWithCommitterMove(
				committer: alice, updBytes: updMessage, committerNewID: aliceNewID)

			XCTAssertNoThrow(try bob.pqRekeyApply(commitFrame))
			XCTAssertNil(bob.pqInflight)
		}
	}

	// MARK: - D6: the catch-up flag

	/// D6: a born-dedicated acceptor's recv-classical catch-up offer (sender
	/// == proposing == the dedicated principal D) arrives at the initiator
	/// with `isCatchUp == true` — the invitation-id → D convergence is
	/// already seeded as canonical in the initiator's `auth.theirs` at
	/// Group_B's join (`establishedDedicatedAndApproved`), so this recv-leaf
	/// catch-up (`prepareToEncrypt`'s implicit arm, group-rules rule 4) is a
	/// textbook D6 flag.
	func testD6BornDedicatedCatchUpOfferIsFlagged() throws {
		let established = try SessionTestSupport.establishedDedicatedAndApproved()
		var alice = established.alice
		var bob = established.bob

		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("catchup".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.queuedProposal.proposing, established.dedicatedClientID)
		XCTAssertTrue(decrypted.queuedProposal.isCatchUp)
	}

	/// D6: a routine same-id refresh offer is never flagged.
	func testD6RoutineSameIDOfferIsNotFlagged() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try alice.prepareToEncrypt()
		let frame = try alice.encrypt(Data("hi".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertFalse(decrypted.queuedProposal.isCatchUp)
	}

	/// D6: a rotation to a candidate that is only AUTHORIZED (approved via
	/// `queueProposal`) but not yet canonical (not yet folded) is never
	/// flagged — the flag checks `auth.theirs.current`, never
	/// `authorizedNext`.
	func testD6RotationToOnlyAuthorizedCandidateIsNotFlagged() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let candidateID = Data("bob-only-authorized".utf8)

		_ = try bob.prepareToEncrypt(rotating: candidateID)
		let firstOffer = try bob.encrypt(Data("offer".utf8)).frame
		let firstDecrypted = try alice.processIncomingDecrypted(firstOffer)
		XCTAssertFalse(firstDecrypted.queuedProposal.isCatchUp)
		_ = try alice.queueProposal(digest: firstDecrypted.queuedProposal.digest)

		// Re-offered, now that `candidateID` is authorized (but still not
		// canonical) at alice — still not flagged.
		_ = try bob.prepareToEncrypt(rotating: candidateID)
		let secondOffer = try bob.encrypt(Data("offer-again".utf8)).frame
		let secondDecrypted = try alice.processIncomingDecrypted(secondOffer)
		XCTAssertFalse(secondDecrypted.queuedProposal.isCatchUp)
	}

	/// D6: a ROLLBACK offer — a leaf currently on the canonical HEAD (`cID`)
	/// offering to move back to an OLDER, still-remembered canonical id
	/// (`bID`) — is never flagged: the narrowed rule requires landing on the
	/// CURRENT head, not merely a historically-known id. `bob`'s founding
	/// identity IS `cID` here (so the leaf genuinely, currently presents it),
	/// and `bID` is spliced into `alice.auth.theirs.history` directly
	/// (`@testable`) ahead of it — a lagging PQ round bypassing this cap
	/// entirely is out of scope for this unit-level check.
	func testD6RollbackOfferIsNotFlagged() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged(bob: "bob-c")
		let cID = bob.identity.clientID
		let bID = Data("bob-b".utf8)
		alice.auth.theirs.history = [bID, cID]
		XCTAssertEqual(alice.theirPrincipalState, .sync(cID))

		let decrypted = try deliverHandBuiltClassicalOffer(
			proposer: &bob, receiver: &alice, newID: bID)
		XCTAssertFalse(decrypted.queuedProposal.isCatchUp)
	}

	/// D6: an offer landing on ANY non-head canonical id — not just the
	/// immediately-preceding one — is never flagged either.
	func testD6NonHeadCanonicalIDIsNotFlagged() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged(bob: "bob-c")
		let cID = bob.identity.clientID
		let aID = Data("bob-a".utf8)
		let bID = Data("bob-b".utf8)
		alice.auth.theirs.history = [aID, bID, cID]

		let decrypted = try deliverHandBuiltClassicalOffer(
			proposer: &bob, receiver: &alice, newID: aID)
		XCTAssertFalse(decrypted.queuedProposal.isCatchUp)
	}

	/// D6: a host approving a flagged catch-up offer through `queueProposal`
	/// folds it cleanly, exactly like a new-client offer — the born-dedicated
	/// acceptor's recv-classical leaf converges to D.
	func testD6ApprovingFlaggedCatchUpOfferConverges() throws {
		let established = try SessionTestSupport.establishedDedicatedAndApproved()
		var alice = established.alice
		var bob = established.bob

		_ = try bob.prepareToEncrypt()
		let offerFrame = try bob.encrypt(Data("catchup".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(offerFrame)
		XCTAssertTrue(decrypted.queuedProposal.isCatchUp)

		_ = try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		let folded = try alice.prepareToEncrypt()
		XCTAssertTrue(folded.didCommit)
		XCTAssertEqual(folded.committedRemoteClientID, established.dedicatedClientID)
		let foldFrame = try alice.encrypt(Data("folded".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)

		XCTAssertEqual(alice.theirPrincipalState, .sync(established.dedicatedClientID))
		let bobRecvLeafID = try basicIdentifier(
			TwoMLSSession.ownLeaf(of: try XCTUnwrap(bob.recvGroup?.classical))
				.credential)
		XCTAssertEqual(bobRecvLeafID, established.dedicatedClientID)
	}
}
