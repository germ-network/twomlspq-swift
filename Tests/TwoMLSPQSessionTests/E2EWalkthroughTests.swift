import Foundation
import MLSCodec
import MLSCombiner
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// The flagship continuous swift↔swift walkthrough: the full lifecycle —
/// cold principals through establishment, routine messaging, a folding
/// commit, and credential rotation — as ONE narrative test, from scratch.
/// Unlike every other suite in this module, it does NOT start from
/// `SessionTestSupport.established()`/`establishedAndExchanged()`, but
/// inlines their exact sequence (Principal mints an invitation, a peer
/// initiates to its published combiner KP, the invitation receives) so this
/// test is itself the self-contained, living-spec walkthrough those
/// fixtures encode.
///
/// This lifecycle is classical-only — there are no standalone §A.4/§A.5
/// side-band steps (those are `RatchetTests`/`RekeyTests`' own territory,
/// always starting from the `establishedAndExchanged` fixture) — so none
/// are added here.
@available(iOS 26, macOS 26, *)
final class E2EWalkthroughTests: XCTestCase {
	func testFullSessionWalkthroughFromColdIdentitiesThroughCredentialRotation() throws {
		// [1] Cold principals.
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		// [2] Bob mints an invitation around a fresh combiner KP (classical +
		// PQ halves — the published shape Alice initiates to); Alice's
		// CLASSICAL return KP (§A.1: Bob's send group starts classical-only,
		// so the establishment reply carries only the classical half;
		// Alice's PQ KP travels later, in §A.3, hash-bound to the bootstrap
		// commitment) is minted fresh by `initiate(principal:)` itself.
		var (bobInvitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let bobCombinerKP = try XCTUnwrap(bobInvitation.combinerKeyPackage)

		// [3] Rust's `parse_mls_key_package` step has no session-layer
		// equivalent — swift key packages are already typed
		// `MLS.RFC9420.KeyPackage` values, never opaque bytes to parse — so
		// this asserts directly on the typed halves instead: both of Bob's
		// halves share one clientId.
		XCTAssertEqual(
			try basicIdentifier(bobCombinerKP.classical.leafNode.credential),
			try basicIdentifier(bobCombinerKP.pq.leafNode.credential))

		// [4] Establishment (`0x01` APQWelcome both directions). Alice
		// initiates; Bob's invitation receives and is established
		// immediately; Alice becomes established only once she processes
		// Bob's first inbound frame. The welcome Alice joins Group_B from is
		// `bob.currentStaple` (the invitation-spawned session's own welcome
		// staple) — not `pqPendingOutbound()`, the unrelated §A.4 PQ
		// side-band leg — and it rides as the `0x01` staple on Bob's first
		// `0x03` frame, as `SessionTestSupport.established()`/
		// `establishedAndExchanged()` thread it.
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: bobCombinerKP)
		var alice = initiated.session
		let welcomeA = initiated.welcome
		let aliceClassicalKP = alice.identity.keyPackage.classical

		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let received = try bobInvitation.receive(
			welcome: welcomeA, theirClassicalKeyPackage: aliceClassicalKP,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		var bob = received.session
		let welcomeB = bob.currentStaple
		XCTAssertTrue(bob.isEstablished)
		XCTAssertFalse(alice.isEstablished)

		// The forward table now resolves this spawn token to Bob's recv-side
		// classical group id, and the session acknowledges it.
		XCTAssertEqual(
			bobInvitation.forwardGroupID(spawnToken: spawnToken),
			bob.recvGroup?.classical.context.groupID)
		XCTAssertNoThrow(try bob.forwarded(spawnToken: spawnToken))

		_ = try bob.prepareToEncrypt()
		let bobFirstFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let (bobFirstStaple, _, _) = try Frames.decodeMessageFrame(bobFirstFrame)
		XCTAssertEqual(
			bobFirstStaple, welcomeB,
			"Bob's first frame staples EstablishResult.welcome, not the PQ side-band")
		_ = try alice.processIncoming(bobFirstFrame)
		XCTAssertTrue(alice.isEstablished)
		XCTAssertTrue(bob.isEstablished)

		// [5] Routine round: Alice -> Bob, no commit.
		_ = try alice.prepareToEncrypt()
		let helloFrame = try alice.encrypt(Data("hello bob".utf8)).frame
		let helloDecrypted = try bob.processIncoming(helloFrame)
		XCTAssertEqual(helloDecrypted.applicationMessage, Data("hello bob".utf8))
		XCTAssertFalse(helloDecrypted.didApplyRemoteCommit)

		// [6] Folding commit: Bob proposes (rides his own `0x03` frame),
		// Alice queues + commits — a queued remote proposal always forces a
		// fold — refreshing both leaves and the cross-party PSK.
		let aliceSendEpochBeforeFold = try XCTUnwrap(
			alice.sendGroup?.classical.context.epoch)
		_ = try bob.prepareToEncrypt()
		let bobProposalFrame = try bob.encrypt(Data("bob update".utf8)).frame
		let proposalDecrypted = try alice.processIncoming(bobProposalFrame)
		_ = try alice.queueProposal(digest: proposalDecrypted.queuedProposal.digest)

		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(
			foldPrepared.didCommit, "a queued remote proposal forces a folding commit")
		XCTAssertEqual(
			alice.sendGroup?.classical.context.epoch, aliceSendEpochBeforeFold + 1)

		let committedFrame = try alice.encrypt(Data("committed".utf8)).frame
		let committedDecrypted = try bob.processIncoming(committedFrame)
		XCTAssertTrue(committedDecrypted.didApplyRemoteCommit)
		XCTAssertEqual(committedDecrypted.applicationMessage, Data("committed".utf8))
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, aliceSendEpochBeforeFold + 1)

		// [7] Continued bidirectional messaging post-refresh: Bob -> Alice.
		_ = try bob.prepareToEncrypt()
		let replyFrame = try bob.encrypt(Data("reply".utf8)).frame
		let replyDecrypted = try alice.processIncoming(replyFrame)
		XCTAssertEqual(replyDecrypted.applicationMessage, Data("reply".utf8))

		// [8] Principal credential rotation: Alice proposes a successor on
		// her next frame (`prepareToEncrypt(rotating:)` folds Rust's
		// `stage_rotation` + `prepare_to_encrypt(Some(id))` into one call, so
		// `.pending` is only observable AFTER it, not between two separate
		// calls as in the Rust source); Bob approves and folds it — his
		// commit defines Alice's canonical next credential; the staple back
		// canonicalizes Alice onto it. Rust's `remote_commit.new_recipient`
		// has no swift id-bearing field — it is `ownCredentialCanonicalized`
		// (a Bool) plus `myPrincipalState`.
		let newAliceID = try SessionTestSupport.identity("alice2").clientID
		_ = try alice.prepareToEncrypt(rotating: newAliceID)
		XCTAssertEqual(
			alice.myPrincipalState,
			.pending(old: alice.identity.clientID, new: newAliceID))

		let rotatingFrame = try alice.encrypt(Data("rotating".utf8)).frame
		let rotatingDecrypted = try bob.processIncoming(rotatingFrame)
		XCTAssertEqual(rotatingDecrypted.queuedProposal.proposing, newAliceID)
		_ = try bob.queueProposal(digest: rotatingDecrypted.queuedProposal.digest)

		let rotationPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(rotationPrepared.didCommit)
		XCTAssertEqual(rotationPrepared.committedRemoteClientID, newAliceID)

		let canonicalizeFrame = try bob.encrypt(Data("canonicalize".utf8)).frame
		let canonicalizeDecrypted = try alice.processIncoming(canonicalizeFrame)
		XCTAssertTrue(canonicalizeDecrypted.ownCredentialCanonicalized)
		XCTAssertEqual(alice.myPrincipalState, .sync(newAliceID))
	}
}
