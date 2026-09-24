import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
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
		// This hand-built Upd′ bypasses `pqRekeyBegin`, which never mints a
		// rotating key itself today — stage the fresh key so
		// `pqRekeyApply`'s promotion can find it when this move lands.
		try proposer.leafKeys.recvPQ.stage(
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey),
			for: newID)
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
		// Same reasoning as `handBuildPQLeafMoveUpd` — stage the fresh key
		// so `pqRekeyApply`'s promotion can find it.
		try proposer.leafKeys.recvPQ.stage(
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey),
			for: newID)
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
		// Stage the fresh key even though this offer is never folded back
		// onto `proposer` within this test.
		try proposer.leafKeys.recvClassical.stage(
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey),
			for: newID)
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
		try assertFourOwnLeafKeysPairwiseDistinct(initiator)
		try assertFourOwnLeafKeysPairwiseDistinct(plainAcceptor)
		try assertEightOwnLeafKeysPairwiseDistinct(initiator, plainAcceptor)

		let (initiatorForDedicated, dedicatedAcceptor) = try fullyEstablishedDedicatedPair()
		try assertFourOwnLeafKeysPairwiseDistinct(initiatorForDedicated)
		// The born-dedicated acceptor already keeps its own-identity pair
		// (D's classical+PQ keys) separate from its retained
		// invitation-identity pair, so its own four leaf keys are already
		// pairwise distinct today.
		try assertFourOwnLeafKeysPairwiseDistinct(dedicatedAcceptor)
		try assertEightOwnLeafKeysPairwiseDistinct(
			initiatorForDedicated, dedicatedAcceptor)
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
		// D1: send-classical is always a fresh founding leaf, distinct from
		// recv-classical (the return KP/invitation half) by construction —
		// no longer gated on D3's still-open rotation gap.
		XCTAssertNotEqual(bobKeysAfter.sendClassical, bobKeysAfter.recvClassical)
		// D3: a committing round mints a fresh send-classical signature key.
		XCTAssertNotEqual(bobKeysBefore.sendClassical, bobKeysAfter.sendClassical)
		XCTAssertEqual(bobKeysBefore.recvClassical, bobKeysAfter.recvClassical)
		XCTAssertEqual(bobKeysBefore.sendPQ, bobKeysAfter.sendPQ)
		XCTAssertEqual(bobKeysBefore.recvPQ, bobKeysAfter.recvPQ)

		XCTAssertNotEqual(aliceKeysAfter.recvClassical, aliceKeysAfter.sendPQ)
		XCTAssertNotEqual(aliceKeysAfter.recvClassical, aliceKeysAfter.recvPQ)
		// D1: recv-classical (the return KP) is always distinct from
		// send-classical (a fresh founding leaf) by construction.
		XCTAssertNotEqual(aliceKeysAfter.recvClassical, aliceKeysAfter.sendClassical)
		// D3: a folded routine Upd(self) mints a fresh recv-classical
		// signature key.
		XCTAssertNotEqual(aliceKeysBefore.recvClassical, aliceKeysAfter.recvClassical)
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

	// MARK: - D3: one Update offer per peer epoch

	/// D3: frames within one epoch of the peer's group repeat the
	/// identical Update offer.
	func testD3OnePrepareToEncryptOfferPerPeerEpoch() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let firstPrepared = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("first".utf8))
		let secondPrepared = try alice.prepareToEncrypt()
		XCTAssertEqual(firstPrepared.proposalMessage, secondPrepared.proposalMessage)

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

	/// 100 frames within one epoch, no peer commit: every offer repeats the
	/// first one's exact bytes, `stagedUpdates` stays at one entry, and the
	/// sealed Core archive stays essentially flat (only a `stateSeq` counter
	/// widening by a couple of bytes, not per-frame growth). Kills: minting
	/// a fresh offer (or appending a new `stagedUpdates` entry) on every
	/// `prepareToEncrypt` call instead of reusing the one already staged
	/// this epoch — that mutation grows the archive by roughly the offer's
	/// own size on every one of the 99 extra frames, not by a few bytes
	/// total.
	func testFramesWithinOneEpochRepeatTheIdenticalOffer() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		let testKey = SecretBytes(randomByteCount: 32)
		let testAAD = Data("signing-key-protocol-tests".utf8)

		let first = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("0".utf8))
		let firstCoreSize = try alice.makeSessionArchive(kind: .core)
			.seal(with: testKey, aad: testAAD).count

		for frame in 1..<100 {
			let prepared = try alice.prepareToEncrypt()
			XCTAssertEqual(prepared.proposalMessage, first.proposalMessage)
			_ = try alice.encrypt(Data("\(frame)".utf8))
		}

		XCTAssertEqual(alice.stagedUpdates.count, 1)
		let lastCoreSize = try alice.makeSessionArchive(kind: .core)
			.seal(with: testKey, aad: testAAD).count
		XCTAssertLessThan(lastCoreSize - firstCoreSize, 16)
	}

	/// A rotation candidate gets its own offer, distinct from — and
	/// coexisting with — the routine offer; a plain frame after it still
	/// repeats the ROUTINE offer, not the candidate's. Kills: latest-wins
	/// reuse (one slot for the whole epoch instead of per target);
	/// re-minting a repeated rotation offer.
	func testRotationGetsItsOwnOfferAndPlainFramesKeepTheRoutineOffer() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceRotated = Data("alice-rotated-in-epoch".utf8)

		let routineFirst = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("r0".utf8))
		let rotationFirst = try alice.prepareToEncrypt(rotating: aliceRotated)
		_ = try alice.encrypt(Data("c0".utf8))
		XCTAssertNotEqual(routineFirst.proposalMessage, rotationFirst.proposalMessage)

		let routineAgain = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("r1".utf8))
		XCTAssertEqual(routineAgain.proposalMessage, routineFirst.proposalMessage)

		let rotationAgain = try alice.prepareToEncrypt(rotating: aliceRotated)
		let rotationFrame = try alice.encrypt(Data("c1".utf8)).frame
		XCTAssertEqual(rotationAgain.proposalMessage, rotationFirst.proposalMessage)

		// D3: the routine offer is a key move too, so it stages its own
		// `pending` entry alongside the candidate's.
		let aliceOwnID = try XCTUnwrap(alice.auth.mine.current)
		XCTAssertEqual(alice.stagedUpdates.count, 2)
		XCTAssertEqual(
			Set(alice.leafKeys.recvClassical.pending.keys), [aliceOwnID, aliceRotated])

		// The peer folds the candidate's (already-sent) offer; it
		// promotes, and the candidate's `pending` entry is pruned.
		_ = try bob.processIncomingDecrypted(rotationFrame)
		_ = try bob.queueProposal(digest: rotationAgain.proposalHash)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertNil(alice.leafKeys.recvClassical.pending[aliceRotated])
	}

	/// D3: a routine offer mints a fresh key in recv-classical only — never
	/// a same-key refresh, and never leaked into another group. Kills: a
	/// routine offer signed without `newIdentity`.
	func testRoutineOfferPresentsAFreshKeyInRecvClassicalOnly() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let ownID = try XCTUnwrap(alice.auth.mine.current)
		let beforeKey = try TwoMLSSession.ownLeaf(
			of: XCTUnwrap(alice.recvGroup).classical
		).signatureKey

		_ = try alice.prepareToEncrypt()
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame

		let pendingKey = try XCTUnwrap(alice.leafKeys.recvClassical.pending[ownID])
		XCTAssertNotEqual(pendingKey.signatureKey.data, beforeKey.data)
		XCTAssertNotEqual(
			alice.leafKeys.recvClassical.current?.signatureKey.data,
			pendingKey.signatureKey.data)
		XCTAssertNotEqual(
			alice.leafKeys.sendClassical.current?.signatureKey.data,
			pendingKey.signatureKey.data)
		XCTAssertNil(alice.leafKeys.sendClassical.pending[ownID])
		XCTAssertNotEqual(
			alice.leafKeys.sendPQ.current?.signatureKey.data,
			pendingKey.signatureKey.data)
		XCTAssertNotEqual(
			alice.leafKeys.recvPQ.current?.signatureKey.data,
			pendingKey.signatureKey.data)

		let decrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decrypted.queuedProposal.digest)
		let foldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)

		XCTAssertEqual(
			alice.leafKeys.recvClassical.current?.signatureKey.data,
			pendingKey.signatureKey.data)
		XCTAssertNil(alice.leafKeys.recvClassical.pending[ownID])
		let presented = try TwoMLSSession.ownLeaf(
			of: XCTUnwrap(alice.recvGroup).classical
		).signatureKey
		XCTAssertEqual(presented.data, pendingKey.signatureKey.data)
	}

	/// Every committing round — a fold, a bind discharge, or a
	/// catch-up — presents a FRESH send-classical key and leaves `pending`
	/// empty afterward, never shared with another group. Kills: signing the
	/// path with `current`; leaving `pending` populated.
	func testEveryCommitPresentsAFreshSendClassicalKeyAndHoldsNoPending() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		// A bare fold: alice approves bob's routine offer.
		_ = try bob.prepareToEncrypt()
		let bobOfferFrame = try bob.encrypt(Data("bob-offer".utf8)).frame
		let bobOfferDecrypted = try alice.processIncomingDecrypted(bobOfferFrame)
		_ = try alice.queueProposal(digest: bobOfferDecrypted.queuedProposal.digest)
		let keyBeforeFold = try XCTUnwrap(alice.leafKeys.sendClassical.current)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let keyAfterFold = try XCTUnwrap(alice.leafKeys.sendClassical.current)
		XCTAssertNotEqual(
			keyAfterFold.signatureKey, keyBeforeFold.signatureKey,
			"a bare fold must mint a fresh send-classical key too")
		XCTAssertTrue(alice.leafKeys.sendClassical.pending.isEmpty)

		// A catch-up: alice rotates, bob folds it into recv-classical, and
		// alice's own next committing round catches her send-classical leaf
		// up to the new id.
		let newID = Data("alice-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		let rotateFrame = try alice.encrypt(Data("rotate".utf8)).frame
		let rotateDecrypted = try bob.processIncomingDecrypted(rotateFrame)
		_ = try bob.queueProposal(digest: rotateDecrypted.queuedProposal.digest)
		let bobFoldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(bobFoldPrepared.didCommit)
		let bobFoldFrame = try bob.encrypt(Data("bob-fold".utf8)).frame
		let aliceCanonicalized = try alice.processIncomingDecrypted(bobFoldFrame)
		XCTAssertTrue(aliceCanonicalized.ownCredentialCanonicalized)

		let catchUpPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(catchUpPrepared.didCommit)
		let keyAfterCatchUp = try XCTUnwrap(alice.leafKeys.sendClassical.current)
		XCTAssertNotEqual(keyAfterCatchUp.signatureKey, keyAfterFold.signatureKey)
		XCTAssertTrue(alice.leafKeys.sendClassical.pending.isEmpty)
		XCTAssertNotEqual(
			keyAfterCatchUp.signatureKey,
			alice.leafKeys.recvClassical.current?.signatureKey,
			"the send-classical catch-up key must not equal recv-classical's")
		XCTAssertNotEqual(
			keyAfterCatchUp.signatureKey, alice.leafKeys.sendPQ.current?.signatureKey)
		XCTAssertNotEqual(
			keyAfterCatchUp.signatureKey, alice.leafKeys.recvPQ.current?.signatureKey)
	}

	/// After a rotation converges on recv-classical, the send-classical
	/// leaf's own later catch-up mints its OWN fresh key — it never reuses
	/// the candidate's key recv-classical now presents. Kills: re-adding
	/// the send-classical candidate staging this commit removed.
	func testSendClassicalCatchUpNeverReusesTheCandidateKey() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let newID = Data("alice-v2".utf8)

		_ = try alice.prepareToEncrypt(rotating: newID)
		let frame1 = try alice.encrypt(Data("rotate-offer".utf8)).frame
		let decrypted1 = try bob.processIncomingDecrypted(frame1)
		_ = try bob.queueProposal(digest: decrypted1.queuedProposal.digest)
		let prepared2 = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared2.didCommit)
		let frame2 = try bob.encrypt(Data("bob-fold".utf8)).frame
		let decrypted2 = try alice.processIncomingDecrypted(frame2)
		XCTAssertTrue(decrypted2.ownCredentialCanonicalized)
		let recvClassicalKey = try XCTUnwrap(alice.leafKeys.recvClassical.current)
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: alice.sendGroup!.classical).credential),
			alice.identity.clientID, "send-classical documentedly still lags here")

		// Alice's own-leaf catch-up — the send-classical leaf's turn.
		let prepared3 = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared3.didCommit)
		let sendClassicalKey = try XCTUnwrap(alice.leafKeys.sendClassical.current)
		XCTAssertNotEqual(sendClassicalKey.signatureKey, recvClassicalKey.signatureKey)
		XCTAssertTrue(alice.leafKeys.sendClassical.pending.isEmpty)
	}

	/// Restore rejects a non-empty send-classical `pending`, and both
	/// mint paths drop a supplied one rather than carrying it through.
	/// Kills: dropping the strict-empty check; the mint forwarding entries.
	func testRestoreRejectsSendClassicalPending() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		alice.leafKeys.sendClassical.pending[Data("smuggled".utf8)] = LeafKey(
			signingKey: signingKey, signatureKey: signatureKey)
		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: archive,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// D3: a key-only move (a routine offer/fold, either direction) raises
	/// no host event — a rotation still does. Kills: flags firing on every
	/// `.credentialReplaced`, not just an id change.
	func testKeyOnlyMovesRaiseNoHostEvent() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		// alice → bob: alice's routine offer, bob folds it.
		_ = try alice.prepareToEncrypt()
		let aliceOfferFrame = try alice.encrypt(Data("a-offer".utf8)).frame
		let bobSawOffer = try bob.processIncomingDecrypted(aliceOfferFrame)
		_ = try bob.queueProposal(digest: bobSawOffer.queuedProposal.digest)
		let bobFoldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(bobFoldPrepared.didCommit)
		let bobFoldFrame = try bob.encrypt(Data("b-fold".utf8)).frame
		let aliceSawFold = try alice.processIncomingDecrypted(bobFoldFrame)
		XCTAssertNil(aliceSawFold.newSender)
		XCTAssertFalse(aliceSawFold.ownCredentialCanonicalized)

		// bob → alice: bob's routine offer, alice folds it.
		_ = try bob.prepareToEncrypt()
		let bobOfferFrame = try bob.encrypt(Data("b-offer".utf8)).frame
		let aliceSawOffer = try alice.processIncomingDecrypted(bobOfferFrame)
		_ = try alice.queueProposal(digest: aliceSawOffer.queuedProposal.digest)
		let aliceFoldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(aliceFoldPrepared.didCommit)
		let aliceFoldFrame = try alice.encrypt(Data("a-fold".utf8)).frame
		let bobSawFold = try bob.processIncomingDecrypted(aliceFoldFrame)
		XCTAssertNil(bobSawFold.newSender)
		XCTAssertFalse(bobSawFold.ownCredentialCanonicalized)

		// A genuine rotation (an id change) still fires
		// `ownCredentialCanonicalized` for the leaf that moved.
		let aliceNewID = Data("alice-rotated-host-event".utf8)
		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let rotationOfferFrame = try alice.encrypt(Data("rotate-offer".utf8)).frame
		let bobSawRotationOffer = try bob.processIncomingDecrypted(rotationOfferFrame)
		_ = try bob.queueProposal(digest: bobSawRotationOffer.queuedProposal.digest)
		let bobFoldRotationPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(bobFoldRotationPrepared.didCommit)
		let bobFoldRotationFrame = try bob.encrypt(Data("rotate-fold".utf8)).frame
		let aliceSawRotationFold = try alice.processIncomingDecrypted(bobFoldRotationFrame)
		XCTAssertNil(aliceSawRotationFold.newSender)
		XCTAssertTrue(aliceSawRotationFold.ownCredentialCanonicalized)
	}

	/// A host-relied invariant: folding a peer's same-id key-only commit
	/// (a routine offer, approved and folded) still reports
	/// `didApplyRemoteCommit == true` — a real commit landed, moving the
	/// epoch — alongside `newSender == nil`, since the id itself never
	/// changed. Hosts that gate other state on `didApplyRemoteCommit`
	/// must see it fire here exactly as it does for an id-changing fold.
	/// Kills: `applied`/`didApplyRemoteCommit` depending on whether the
	/// credential id changed, rather than on whether a commit was folded.
	func testSameIDKeyMoveFoldStillAppliesTheRemoteCommit() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		_ = try alice.prepareToEncrypt()
		let offerFrame = try alice.encrypt(Data("routine-offer".utf8)).frame
		let bobSawOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: bobSawOffer.queuedProposal.digest)

		let bobFoldPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(bobFoldPrepared.didCommit)
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		let aliceSawFold = try alice.processIncomingDecrypted(foldFrame)

		XCTAssertTrue(
			aliceSawFold.didApplyRemoteCommit,
			"a same-id key-only commit is still a real applied commit")
		XCTAssertNil(aliceSawFold.newSender, "the id never changed")
	}

	/// A `prepareToEncrypt` whose `pendingProposal` is never consumed by
	/// `encrypt` (the offer never left the local session), followed by a
	/// peer commit that moves the recv epoch, followed by another
	/// `prepareToEncrypt`. The second prepare must re-propose at the NEW
	/// epoch, not repeat the dead-epoch bytes — `reuseOffer` must key off
	/// `stagedUpdates` alone, since the epoch-advance sites drain
	/// `stagedUpdates` (and prune the stale key) but never touch
	/// `pendingProposal` directly. Kills: `reuseOffer` consulting
	/// `pendingProposal` before/instead of `stagedUpdates`.
	func testUnconsumedOfferIsNotReusedAcrossAnEpochMove() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let ownID = try XCTUnwrap(alice.auth.mine.current)

		// Bob's A.4 legs first (alice's responder leg refuses while she
		// holds a pending proposal), then alice prepares but never encrypts.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		_ = try bob.pqRatchetBind(ctFrame)

		let stale = try alice.prepareToEncrypt()
		XCTAssertNotNil(alice.pendingProposal)
		let staleKey = try XCTUnwrap(alice.leafKeys.recvClassical.pending[ownID])

		// Bob discharges the bind alone; alice's offer never reached him.
		let bobPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(bobPrepared.didCommit)
		let bindFrame = try bob.encrypt(Data("bind-only".utf8)).frame
		let epochBefore = try XCTUnwrap(alice.recvGroup?.classical.context.epoch)
		_ = try alice.processIncomingDecrypted(bindFrame)
		XCTAssertNotEqual(alice.recvGroup?.classical.context.epoch, epochBefore)
		XCTAssertTrue(alice.stagedUpdates.isEmpty)
		XCTAssertNil(alice.leafKeys.recvClassical.pending[ownID], "stale key pruned")

		let fresh = try alice.prepareToEncrypt()
		XCTAssertNotEqual(
			fresh.proposalMessage, stale.proposalMessage,
			"a dead-epoch offer must not be repeated after the epoch moved")
		let freshKey = alice.leafKeys.recvClassical.pending[ownID]
		XCTAssertNotNil(freshKey, "the new offer must stage its own key")
		XCTAssertNotEqual(freshKey?.signatureKey.data, staleKey.signatureKey.data)

		// And the peer must be able to fold what alice now sends.
		let frame = try alice.encrypt(Data("offer".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertNoThrow(try bob.queueProposal(digest: decrypted.queuedProposal.digest))
		XCTAssertTrue(try bob.prepareToEncrypt().didCommit)
	}

	/// The peer's epoch can move without ever folding our own routine
	/// offer — here, a bind discharge alone. The stale offer's `pending`
	/// entry and `stagedUpdates` record both go, and the next offer mints
	/// a genuinely different key. Kills: reuse across epochs; retention
	/// keeping a stale routine key.
	func testEpochMoveWithoutOurFoldMintsANewOfferAndPrunesTheStaleKey() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let ownID = try XCTUnwrap(alice.auth.mine.current)

		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("stale-offer".utf8))
		let staleKey = try XCTUnwrap(alice.leafKeys.recvClassical.pending[ownID])
		XCTAssertEqual(alice.stagedUpdates.count, 1)

		// Bob owes a PQ bind and discharges it alone — alice's offer above
		// was never delivered/queued to him, so nothing of hers folds.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		_ = try bob.pqRatchetBind(ctFrame)
		XCTAssertNotNil(bob.owedBind)

		let bobPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(bobPrepared.didCommit)
		XCTAssertNil(bobPrepared.committedRemoteClientID, "nothing of alice's folded")
		let bindFrame = try bob.encrypt(Data("bind-only".utf8)).frame

		let recvEpochBefore = try XCTUnwrap(alice.recvGroup?.classical.context.epoch)
		_ = try alice.processIncomingDecrypted(bindFrame)
		XCTAssertNotEqual(alice.recvGroup?.classical.context.epoch, recvEpochBefore)

		XCTAssertTrue(alice.stagedUpdates.isEmpty)
		XCTAssertNil(alice.leafKeys.recvClassical.pending[ownID])

		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("fresh-offer".utf8))
		let freshKey = try XCTUnwrap(alice.leafKeys.recvClassical.pending[ownID])
		XCTAssertNotEqual(freshKey.signatureKey.data, staleKey.signatureKey.data)
	}

	/// A new offer for a target reuses the HELD key while an own-offer
	/// window is outstanding — never replaces it, since a window offer may
	/// still name it — but a DIFFERENT target with no held key still mints
	/// fresh, and once the window closes (its epoch moves), the next offer
	/// for the SAME target mints fresh too. Kills: overwriting `pending[T]`
	/// while the window is outstanding.
	func testMigratedWindowEpochProposesUnderTheHeldKey() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		let ownID = try XCTUnwrap(alice.auth.mine.current)
		let recv = try XCTUnwrap(alice.recvGroup)

		let (heldSigningKey, heldSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let heldKey = LeafKey(signingKey: heldSigningKey, signatureKey: heldSignatureKey)
		alice.leafKeys.recvClassical.pending[ownID] = heldKey
		alice.ownOfferWindow = OwnOfferWindowRecord(
			id: SessionTestSupport.classicalProvider.randomBytes(32),
			epoch: recv.classical.context.epoch,
			groupID: recv.classical.context.groupID,
			senderLeafIndex: recv.classical.myLeafIndex.value, count: 1)

		// (a) the held key is reused, not replaced.
		_ = try alice.prepareToEncrypt()
		XCTAssertEqual(
			alice.leafKeys.recvClassical.pending[ownID]?.signatureKey.data,
			heldKey.signatureKey.data)

		// (b) a target the window does NOT name — alice's own leaf now
		// "lags" a different id, with no held key for it — still mints
		// fresh even though the window is outstanding.
		let otherID = Data("window-other-target".utf8)
		try alice.auth.mine.commit(otherID)
		// Also lags send-classical now (the shared identity sequence) —
		// `committingRound`'s own catch-up needs SOME pending key there to
		// proceed; unrelated to what this test checks (recv-classical's
		// `mintTargetKey`), so any valid key satisfies it.
		let (dummySigningKey, dummySignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		alice.leafKeys.sendClassical.pending[otherID] = LeafKey(
			signingKey: dummySigningKey, signatureKey: dummySignatureKey)
		_ = try alice.prepareToEncrypt()
		let otherKey = try XCTUnwrap(alice.leafKeys.recvClassical.pending[otherID])
		XCTAssertNotEqual(otherKey.signatureKey.data, heldKey.signatureKey.data)
		XCTAssertEqual(
			alice.leafKeys.recvClassical.pending[ownID]?.signatureKey.data,
			heldKey.signatureKey.data, "the held target is untouched by the other mint")

		// (c) once the window closes (its epoch moved — modeled directly,
		// since a real fold also drains `stagedUpdates`/`pendingProposal`),
		// the SAME target's (`otherID`'s) next offer mints fresh, not
		// whatever `pending` still holds from before the window closed.
		alice.stagedUpdates = []
		alice.pendingProposal = nil
		alice.ownOfferWindow = nil
		_ = try alice.prepareToEncrypt()
		let afterWindowKey = try XCTUnwrap(alice.leafKeys.recvClassical.pending[otherID])
		XCTAssertNotEqual(afterWindowKey.signatureKey.data, otherKey.signatureKey.data)
	}

	/// A restore mid-epoch (after prepare + encrypt but before the peer's
	/// fold) still repeats the identical offer bytes on the next prepare —
	/// the reuse cache is `stagedUpdates`/`pendingProposal`, both durable
	/// archive fields, not transient, unpersisted call-local state. Kills:
	/// reuse keyed on something that does not survive a restore.
	func testRestoreMidEpochRepeatsTheSameOffer() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		let prepared = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("offer".utf8))

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: try alice.makeSessionArchive(kind: .checkpoint),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		var restoredMutable = restored
		let restoredPrepared = try restoredMutable.prepareToEncrypt()
		XCTAssertEqual(restoredPrepared.proposalMessage, prepared.proposalMessage)
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
		// The PQ resolver has no rotation-candidate arm (a PQ leaf move is
		// not a rotation), so the hand-built catch-up target below can never
		// resolve there by construction.
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
		// Same reason as `testSection3PQLeafCatchUpToAnAlreadyCanonicalID`:
		// the hand-built stuck-heal target has no rotation-candidate arm to
		// resolve through.
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
		// alice's AS up to `bobNewID` — the book's §A.5 trigger rule
		// (TwoMLSPQ `69a9f0e`, `protocol-flows.md:56`): nothing here
		// specially targets the stuck round.
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

	// MARK: - D1: no own-leaf key is ever held by two groups at once

	/// No `signatureKey` appears in TWO groups' `current ∪ pending` at
	/// once, checked repeatedly across establishment, §A.3, restore, and two
	/// full alternating §A.4 rounds, for both a plain and a born-dedicated
	/// pair. Rotation is deliberately out of this fixture: a rotation
	/// candidate's key legitimately stages into both classical sets at once
	/// (see the type doc's own "Result" paragraph).
	func testNoKeyHeldByTwoGroupsAcrossTheNativeLifecycle() throws {
		try assertNoKeySharedThroughoutLifecycle(dedicatedClientID: nil, runA4Rounds: true)
		try assertNoKeySharedThroughoutLifecycle(
			dedicatedClientID: Data("d2-dedicated".utf8), runA4Rounds: true)
	}

	private func assertNoKeySharedThroughoutLifecycle(
		dedicatedClientID: Data?, runA4Rounds: Bool
	) throws {
		var alice: TwoMLSSession
		var bob: TwoMLSSession
		if let dedicatedClientID {
			let established = try SessionTestSupport.establishedDedicatedAndApproved(
				dedicatedClientID: dedicatedClientID)
			alice = established.alice
			bob = established.bob
		} else {
			(alice, bob) = try SessionTestSupport.establishedAndExchanged()
		}
		assertNoOwnLeafKeyIsHeldByTwoGroups(alice)
		assertNoOwnLeafKeyIsHeldByTwoGroups(bob)

		// §A.3.
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		if dedicatedClientID != nil {
			// `establishedDedicatedAndApproved` delivers no Bob→Alice frame, so
			// Alice is unlicensed (`peerAppliedSendEpoch` is nil,
			// `TwoMLSSession+ClassicalCommit.swift` ~:378-390) and her owed bind
			// never discharges — `maybeStageNextRound`'s `owedBind == nil` guard
			// (`TwoMLSSession+Ratchet.swift` ~:297) holds forever. That's
			// evidence-gating (`protocol-flows.md`), not a bug: drive Bob's
			// first frame — the rule-4 catch-up offer — before Alice's bind, so
			// the round can actually discharge.
			_ = try bob.prepareToEncrypt()
			let hello = try bob.encrypt(Data("bob-hello".utf8)).frame
			let dec = try alice.processIncomingDecrypted(hello)
			try alice.queueProposal(digest: dec.queuedProposal.digest)
			XCTAssertTrue(try alice.prepareToEncrypt().didCommit)
			let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
			XCTAssertTrue(
				try bob.processIncomingDecrypted(boundFrame).didApplyRemoteCommit)
		} else {
			_ = try alice.prepareToEncrypt()
			let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
			_ = try bob.processIncomingDecrypted(boundFrame)
		}
		assertNoOwnLeafKeyIsHeldByTwoGroups(alice)
		assertNoOwnLeafKeyIsHeldByTwoGroups(bob)

		// Two full §A.4 rounds, each driven by whichever side currently
		// holds the turn.
		for round in 0..<(runA4Rounds ? 2 : 0) {
			if bob.myPQTurn {
				_ = try bob.prepareToEncrypt()
				_ = try bob.encrypt(Data("m-\(round)".utf8))
				let ekFrame = try XCTUnwrap(
					bob.pqPendingOutbound(), "round \(round), bob's turn")
				let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
				_ = try bob.pqRatchetBind(ctFrame)
				let prepared = try bob.prepareToEncrypt()
				XCTAssertTrue(prepared.didCommit)
				let roundBoundFrame = try bob.encrypt(Data("bound-\(round)".utf8))
					.frame
				_ = try alice.processIncomingDecrypted(roundBoundFrame)
			} else {
				XCTAssertTrue(alice.myPQTurn)
				_ = try alice.prepareToEncrypt()
				_ = try alice.encrypt(Data("m-\(round)".utf8))
				let ekFrame = try XCTUnwrap(
					alice.pqPendingOutbound(), "round \(round), alice's turn")
				let ctFrame = try bob.pqRatchetRespond(ekFrame).frame
				_ = try alice.pqRatchetBind(ctFrame)
				let prepared = try alice.prepareToEncrypt()
				XCTAssertTrue(prepared.didCommit)
				let roundBoundFrame = try alice.encrypt(Data("bound-\(round)".utf8))
					.frame
				_ = try bob.processIncomingDecrypted(roundBoundFrame)
			}
			assertNoOwnLeafKeyIsHeldByTwoGroups(alice)
			assertNoOwnLeafKeyIsHeldByTwoGroups(bob)
		}

		let aliceRestored = try TwoMLSSession.restore(
			core: nil, checkpoint: try alice.makeSessionArchive(kind: .checkpoint),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobRestored = try TwoMLSSession.restore(
			core: nil, checkpoint: try bob.makeSessionArchive(kind: .checkpoint),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		assertNoOwnLeafKeyIsHeldByTwoGroups(aliceRestored)
		assertNoOwnLeafKeyIsHeldByTwoGroups(bobRestored)
	}

	private func assertNoOwnLeafKeyIsHeldByTwoGroups(
		_ session: TwoMLSSession, file: StaticString = #filePath, line: UInt = #line
	) {
		func allKeys(_ set: GroupKeySet) -> Set<Data> {
			var keys = Set<Data>()
			if let current = set.current { keys.insert(current.signatureKey.data) }
			for (_, key) in set.pending { keys.insert(key.signatureKey.data) }
			return keys
		}
		let sets: [(name: String, keys: Set<Data>)] = [
			("sendClassical", allKeys(session.leafKeys.sendClassical)),
			("recvClassical", allKeys(session.leafKeys.recvClassical)),
			("sendPQ", allKeys(session.leafKeys.sendPQ)),
			("recvPQ", allKeys(session.leafKeys.recvPQ)),
		]
		for i in 0..<sets.count {
			for j in (i + 1)..<sets.count {
				let shared = sets[i].keys.intersection(sets[j].keys)
				XCTAssertTrue(
					shared.isEmpty,
					"\(sets[i].name) and \(sets[j].name) share a key: \(shared)",
					file: file, line: line)
			}
		}
	}
}
