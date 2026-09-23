import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// Holds the engine to `docs/protocol/signing-keys-and-credential-catch-up.md`
/// (D1, D3, §1, §3). Where the engine already conforms, the assertion is a
/// plain regression guard; where it does not yet, the assertion is wrapped
/// in `XCTExpectFailure` so the run stays green today and turns red once
/// that gap closes.
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

	/// Hand-builds the Commit′ that folds `updBytes` (already known to be a
	/// `publicMessage` Upd′) into `committer`'s send-PQ, mirroring
	/// `pqRekeyRespond`'s construction minus its presentation guard. Omits
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

		try XCTExpectFailure("§3: a same-id, key-only PQ leaf move must be accepted") {
			XCTAssertNoThrow(try alice.pqRekeyRespond(round.frame))
		}
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
		// Built from alice's PRE-respond state, so a successful respond
		// below (once fixed) — which moves her sendGroup.pq epoch — can't
		// invalidate it.
		let commitFrame = try handBuildPQRekeyCommit(
			committer: alice, updBytes: round.bytes)

		try XCTExpectFailure("§3: catch-up to an already-canonical id must be accepted") {
			XCTAssertNoThrow(try alice.pqRekeyRespond(round.frame))
		}

		bob.pqInflight = .rekeyInitiated(updMessage: round.bytes)
		bob.pendingSideBand = round.frame
		try XCTExpectFailure("§3: pqRekeyApply succeeds and departs .rekeyInitiated") {
			XCTAssertNoThrow(try bob.pqRekeyApply(commitFrame))
			XCTAssertNil(bob.pqInflight)
		}
	}

	// MARK: - §3: rejected PQ leaf moves

	/// §3: a move to a NEW id is refused unless that id is already
	/// canonical; a same-id move is exempt (see the same-id test above). An
	/// authorized-but-not-yet-canonical candidate and an id neither party
	/// has ever offered are each refused, at both `pqRekeyRespond` and
	/// `pqRekeyApply`, leaving state untouched. (A genuine rollback needs a
	/// PQ leaf already on a newer id, which today's API cannot produce —
	/// the PQ leaf never legitimately moves — so it is not exercised here.)
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
	/// (`.rekeyProposalRejected`) and, independently, `proposer.pqRekeyApply`
	/// of a separately hand-built Commit′ (`.invalidRekeyEffects`) — each
	/// leaving its side's state untouched.
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
				error as? TwoMLSError, .invalidRekeyEffects, file: file, line: line)
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

		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try alice.processIncomingDecrypted(offerFrame)
		_ = try alice.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(alice.theirPrincipalState, .sync(bobNewID))

		let round = try handBuildPQLeafMoveUpd(proposer: &bob, newID: bobNewID)
		bob.pqInflight = .rekeyInitiated(updMessage: round.bytes)
		bob.pendingSideBand = round.frame

		var response: SideBandResult?
		for _ in 0..<3 {
			let sendPQEpochBefore = alice.sendGroup?.pq?.context.epoch
			let stateSeqBefore = alice.stateSeq
			do {
				response = try alice.pqRekeyRespond(round.frame)
			} catch {
				XCTAssertEqual(error as? TwoMLSError, .rekeyProposalRejected)
				XCTAssertNil(alice.pqInflight)
				XCTAssertEqual(
					alice.sendGroup?.pq?.context.epoch, sendPQEpochBefore)
				XCTAssertEqual(alice.stateSeq, stateSeqBefore)
			}
		}

		XCTExpectFailure(
			"§3: a stuck A.5 re-send must eventually be accepted once the id is canonical"
		) {
			XCTAssertNotNil(response)
		}

		// The responder's own Commit′ — Test 6 covers the apply-effects
		// gate against a hand-built one on its own.
		if let response {
			XCTAssertNoThrow(try bob.pqRekeyApply(response.frame))
			XCTAssertNil(bob.pqInflight)
		}
	}
}
