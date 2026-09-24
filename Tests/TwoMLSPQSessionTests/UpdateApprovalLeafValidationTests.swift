import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// `validateOfferedUpdate` (`queueProposal`'s own validation) now runs the
/// embedded replacement leaf's own RFC 9420 section 7.3 validity — `LeafNode.
/// verifySignature` and `.validatePolicy` — not just the enclosing
/// proposal's framing signature. `committingRound` also now takes
/// `queuedProposal` at entry and withdraws a still-outstanding
/// authorization on any later failure, rather than leaving an approval
/// silently re-triable forever.
@available(iOS 26, macOS 26, *)
final class UpdateApprovalLeafValidationTests: XCTestCase {

	/// Hand-forges a validly-FRAMED "Alice Update" targeting bob's send
	/// group (Group_B) — the enclosing proposal signed under Alice's REAL,
	/// currently-occupying classical key, so `Group.verifying(proposal:)`
	/// accepts the framing; `mutateLeaf` then tampers with the embedded
	/// replacement leaf before it is (optionally) re-signed. Mirrors
	/// `LeafCapabilityGateTests.forgedRogueUpdate`'s technique.
	private func forgedUpdate(
		mutateLeaf: (inout MLS.RFC9420.LeafNode) -> Void,
		signLeafWith signingKeyOverride: MLS.SignatureSecretKey? = nil
	) throws -> (committer: TwoMLSSession, message: Data, digest: Data, proposingID: Data) {
		let provider = SessionTestSupport.classicalProvider
		let (alice, bob, _, _, _, _) = try SessionTestSupport.established(
			alice: "approval-alice-\(UUID())", bob: "approval-bob-\(UUID())")
		var received = bob
		_ = try received.prepareToEncrypt()

		let committerSend = try XCTUnwrap(received.sendGroup).classical
		let aliceLeafIndex = try XCTUnwrap(
			committerSend.tree.nonBlankLeaves()
				.first { $0.index != committerSend.myLeafIndex }?.index)
		let realLeafRecord = try XCTUnwrap(committerSend.tree.leaf(at: aliceLeafIndex))
		let realLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: realLeafRecord.encoded)
		guard case .basic(let aliceID) = realLeaf.credential else {
			XCTFail("expected a Basic credential")
			throw TwoMLSError.unsupportedCredential
		}

		var rogueLeaf = realLeaf
		rogueLeaf.source = .update
		mutateLeaf(&rogueLeaf)

		let aliceSigningKey = try alice.sendClassicalSigningKey()
		rogueLeaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKeyOverride ?? aliceSigningKey,
			label: "LeafNodeTBS",
			content: try rogueLeaf.toBeSigned(
				placement: .inGroup(
					groupID: committerSend.context.groupID,
					leafIndex: aliceLeafIndex)))

		let content = MLS.RFC9420.FramedContent(
			groupID: committerSend.context.groupID, epoch: committerSend.context.epoch,
			sender: .member(aliceLeafIndex), authenticatedData: Data(),
			content: .proposal(.update(rogueLeaf)))
		let forged = try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: committerSend.context,
			confirmationTag: nil, signingKey: aliceSigningKey,
			membershipKey: committerSend.epoch.membershipKey)
		let message = try MLS.RFC9420.Message.publicMessage(forged).mlsEncoded()

		guard case .basic(let leafID) = rogueLeaf.credential else {
			XCTFail("expected a Basic credential")
			throw TwoMLSError.unsupportedCredential
		}
		_ = aliceID
		return (
			committer: received, message: message,
			digest: provider.randomBytes(8), proposingID: leafID
		)
	}

	/// RFC 9420 section 7.3 (via `LeafNode.validatePolicy(.updateProposal(replacing:))`):
	/// "the encryption_key must differ from the replaced leaf's" — an
	/// Update whose replacement leaf keeps the SAME encryption key as the
	/// leaf it replaces is rejected, even though nothing else about it is
	/// rogue (real capabilities, same credential/signature key). Mutation:
	/// removing the `validatePolicy` call makes this fail (nothing else in
	/// `validateOfferedUpdate` checks the encryption key at all).
	func testQueueProposalRejectsAnUnchangedEncryptionKey() throws {
		let round = try forgedUpdate(mutateLeaf: { _ in
			// No-op: `rogueLeaf` starts as an exact copy of the real
			// leaf, so its `encryptionKey` is already unchanged unless
			// mutated — the point of this test.
		})
		var committer = round.committer
		committer.offeredProposal = (
			digest: round.digest, proposing: round.proposingID, message: round.message
		)
		XCTAssertThrowsError(try committer.queueProposal(digest: round.digest)) { error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
		XCTAssertNotNil(committer.offeredProposal, "the rejected offer is restored")
		XCTAssertNil(committer.queuedProposal)
	}

	/// A bad `LeafNodeTBS` signature on an ID-CHANGING offer (a genuine
	/// rotation shape, not a same-id refresh) is rejected before the new id
	/// is ever authorized — `authorizedNext` gains nothing. Mutation:
	/// removing the `verifySignature` call makes this fail (the enclosing
	/// `verifying(proposal:)` call only authenticates the FRAMING, never
	/// this embedded leaf's own signature, so an unsigned/garbage-signed
	/// replacement leaf would otherwise ride straight through to
	/// authorization).
	func testQueueProposalRejectsABadLeafSignatureOnAnIDChangingOffer() throws {
		let newID = Data("approval-rotated-\(UUID())".utf8)
		let (garbleSigningKey, _) = try TwoMLSIdentity.mintSignatureKeypair()
		let (_, freshEncryptionKey) = try SessionTestSupport.classicalProvider
			.hpkeGenerateKeyPair()
		let round = try forgedUpdate(
			mutateLeaf: { leaf in
				leaf.credential = .basic(identity: newID)
				// A genuine rotation also moves the encryption key —
				// isolates this test to the SIGNATURE check alone,
				// distinct from `testQueueProposalRejectsAnUnchangedEncryptionKey`'s
				// own unchanged-key check.
				leaf.encryptionKey = freshEncryptionKey
			}, signLeafWith: garbleSigningKey)
		var committer = round.committer
		XCTAssertEqual(round.proposingID, newID)
		committer.offeredProposal = (
			digest: round.digest, proposing: round.proposingID, message: round.message
		)
		XCTAssertThrowsError(try committer.queueProposal(digest: round.digest)) { error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
		XCTAssertFalse(committer.auth.theirs.authorizedNext.contains(newID))
		XCTAssertFalse(committer.auth.theirs.knownIDs.contains(newID))
		XCTAssertNil(committer.queuedProposal)
	}

	/// `committingRound` takes `queuedProposal` at entry: an injected,
	/// undecodable `queuedProposal` (standing in for any later failure to
	/// build the fold, not only a capability-less leaf) makes the FIRST
	/// `prepareToEncrypt` throw, drops the queued fold (`queuedProposal ==
	/// nil`), and withdraws the still-outstanding authorization for its
	/// id; a SECOND call, with nothing left queued, succeeds normally.
	/// Mutation: removing the take (still reading `self.queuedProposal`
	/// directly, or not clearing it) or removing the revoke each make this
	/// fail differently — the take by leaving `queuedProposal` non-nil
	/// after the throw, the revoke by leaving the id in `authorizedNext`.
	func testInjectedInvalidQueuedProposalIsWithdrawnOnFailureAndRecovers() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established(
			alice: "approval-take-alice", bob: "approval-take-bob")
		_ = try bob.prepareToEncrypt()
		let helloFrame = try bob.encrypt(Data("hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(helloFrame)

		let newID = Data("approval-take-bob-rotated".utf8)
		_ = try bob.prepareToEncrypt(rotating: newID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try alice.processIncomingDecrypted(offerFrame)
		XCTAssertEqual(offerDecrypted.queuedProposal.proposing, newID)
		_ = try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		XCTAssertTrue(alice.auth.theirs.authorizedNext.contains(newID))
		XCTAssertNotNil(alice.queuedProposal)

		// Inject corruption directly into the queued slot — an undecodable
		// message, standing in for "the commit that would fold this fails
		// to build," whatever the reason.
		alice.queuedProposal = (
			digest: alice.queuedProposal!.digest, proposing: newID,
			message: Data("not-a-valid-mls-message".utf8)
		)

		XCTAssertThrowsError(try alice.prepareToEncrypt()) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidFoldEffects)
		}
		XCTAssertNil(alice.queuedProposal)
		XCTAssertFalse(
			alice.auth.theirs.authorizedNext.contains(newID),
			"the still-outstanding authorization is withdrawn")
		XCTAssertFalse(alice.auth.theirs.history.contains(newID))

		// Second call: nothing left queued/owed — a plain routine round,
		// succeeds normally.
		XCTAssertNoThrow(try alice.prepareToEncrypt())
	}
}
