import Crypto
import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Slice 5: the classical FOLD path (no credential rotation). A routine fold
/// round is offer → approve → commit → staple apply: the proposer's
/// `prepareToEncrypt` stages an `Upd(self)` into its receive group (the
/// approver's send group); the approver surfaces it (`processIncoming`'s
/// `DecryptResult.queuedProposal`), approves it (`queueProposal(digest:)`),
/// and its own next `prepareToEncrypt` folds it into an `includePath: true`
/// commit — refreshing both leaves — stapled bare `0x00` (fold-only) or
/// paired with an owed bind as `0x05` (MF6). Mirrors the proven PQ fold
/// mechanism (`pqRekeyRespond`/`pqRekeyApply`) ported onto the classical
/// group.
@available(iOS 26, macOS 26, *)
final class FoldTests: XCTestCase {
	// MARK: - Helpers

	/// Drive one offer leg: `proposer` stages+sends an `Upd(self)`, `approver`
	/// receives it. Returns the offer's digest/proposing/raw message bytes —
	/// everything a test needs either to `queueProposal` normally or to
	/// hand-craft a tampered/forged frame.
	@discardableResult
	private func surfaceOffer(
		from proposer: inout TwoMLSSession, to approver: inout TwoMLSSession,
		app: Data = Data("offer".utf8)
	) throws -> (digest: Data, proposing: Data, message: Data) {
		_ = try proposer.prepareToEncrypt()
		let frame = try proposer.encrypt(app)
		_ = try approver.processIncoming(frame)
		let (_, proposalSection, _) = try Frames.decodeMessageFrame(frame)
		let (proposing, message) = try Frames.decodeProposalSection(proposalSection)
		let digest = try SessionTestSupport.classicalProvider.hash(message)
		return (digest: digest, proposing: proposing, message: message)
	}

	// MARK: - The full routine fold round

	/// Offer → approve → commit → staple apply, end to end: Bob offers,
	/// Alice approves and folds it into her next `prepareToEncrypt`
	/// (`didCommit`/`committedRemoteClientID`/epoch 1→2, stapled bare
	/// `0x00`), Bob applies it (`didApplyRemoteCommit`), and app traffic
	/// round-trips both directions afterward.
	func testFullRoutineFoldRoundRefreshesBothLeavesAndRoundTrips() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let groupAEpochBefore = try XCTUnwrap(alice.sendGroup?.classical.context.epoch)
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, groupAEpochBefore)

		let offer = try surfaceOffer(from: &bob, to: &alice)
		try alice.queueProposal(digest: offer.digest)

		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		XCTAssertEqual(prepared.committedRemoteClientID, Data("bob".utf8))
		XCTAssertEqual(alice.sendGroup?.classical.context.epoch, groupAEpochBefore + 1)

		let frame = try alice.encrypt(Data("alice-fold".utf8))
		let (staple, _, _) = try Frames.decodeMessageFrame(frame)
		XCTAssertEqual(staple.first, Frames.mlsMessageStapleTag)

		let decrypted = try bob.processIncoming(frame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertEqual(decrypted.applicationMessage, Data("alice-fold".utf8))
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, groupAEpochBefore + 1)

		// Round-trip both directions post-fold.
		_ = try alice.prepareToEncrypt()
		let aliceMsg = try alice.encrypt(Data("post-fold-alice".utf8))
		let fromAlice = try bob.processIncoming(aliceMsg)
		XCTAssertEqual(fromAlice.applicationMessage, Data("post-fold-alice".utf8))

		_ = try bob.prepareToEncrypt()
		let bobMsg = try bob.encrypt(Data("post-fold-bob".utf8))
		let fromBob = try alice.processIncoming(bobMsg)
		XCTAssertEqual(fromBob.applicationMessage, Data("post-fold-bob".utf8))
	}

	// MARK: - Fold + bind on one `0x05` commit (MF1/MF6)

	/// An owed PQ bind rides the SAME commit that folds an approved peer
	/// Update: Bob owes a bind (via the §A.4 ratchet), Alice offers Bob an
	/// Update which Bob approves, and Bob's next `prepareToEncrypt` folds AND
	/// discharges in one commit, stapled `0x05`.
	func testFoldAndBindRideOneCommit() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame)
		try bob.pqRatchetBind(ctFrame)
		XCTAssertNotNil(bob.owedBind)

		let offer = try surfaceOffer(from: &alice, to: &bob)
		try bob.queueProposal(digest: offer.digest)

		let groupBEpochBefore = try XCTUnwrap(bob.sendGroup?.classical.context.epoch)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		XCTAssertEqual(prepared.committedRemoteClientID, Data("alice".utf8))
		XCTAssertEqual(bob.sendGroup?.classical.context.epoch, groupBEpochBefore + 1)
		XCTAssertNil(bob.owedBind)

		let frame = try bob.encrypt(Data("fold-and-bind".utf8))
		let (staple, _, _) = try Frames.decodeMessageFrame(frame)
		XCTAssertEqual(staple.first, Frames.apqPrivateMessageTag)

		let decrypted = try alice.processIncoming(frame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertEqual(alice.recvGroup?.classical.context.epoch, groupBEpochBefore + 1)
		XCTAssertTrue(alice.myPQTurn)

		_ = try alice.prepareToEncrypt()
		let msg = try alice.encrypt(Data("post-fold-bind".utf8))
		let fromAlice = try bob.processIncoming(msg)
		XCTAssertEqual(fromAlice.applicationMessage, Data("post-fold-bind".utf8))
	}

	// MARK: - The send-side `0xFF02` ledger (MF4)

	/// Two fold commits land at ONE own-send epoch of the party applying
	/// them (Bob never commits his own send group between the two) — without
	/// the ledger/gate, the second apply's cross-PSK resolution would attempt
	/// a second, failing export off the already-consumed leaf
	/// (`componentSecretConsumed`).
	func testTwoFoldsAtOneOwnSendEpochExerciseTheLedgerGate() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let offer1 = try surfaceOffer(from: &bob, to: &alice)
		try alice.queueProposal(digest: offer1.digest)
		_ = try alice.prepareToEncrypt()
		let frame1 = try alice.encrypt(Data("fold-1".utf8))
		let decrypted1 = try bob.processIncoming(frame1)
		XCTAssertTrue(decrypted1.didApplyRemoteCommit)

		let offer2 = try surfaceOffer(from: &bob, to: &alice)
		try alice.queueProposal(digest: offer2.digest)
		_ = try alice.prepareToEncrypt()
		let frame2 = try alice.encrypt(Data("fold-2".utf8))
		let decrypted2 = try bob.processIncoming(frame2)
		XCTAssertTrue(decrypted2.didApplyRemoteCommit)

		XCTAssertEqual(alice.sendGroup?.classical.context.epoch, 3)
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, 3)
	}

	/// Crossed concurrent commits: Alice's fold commit (on Group_A) injects
	/// the cross-party `0xFF02` sourced from her view of Group_B at epoch 1;
	/// before Bob applies it, Bob independently commits his OWN send group
	/// (Group_B) past epoch 1 folding a separate offer from Alice. Applying
	/// Alice's (now-crossed) commit needs Group_B's epoch-1 export, which
	/// Bob's own sendGroup.classical can no longer produce live (the -02
	/// exporter tree retains only the current epoch) — resolved only via the
	/// ledger Bob's own commit remembered before advancing past it.
	func testCrossedConcurrentCommitsResolveViaLedgerForDepartedEpoch() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		// Bob's offer for his OWN later fold, surfaced first — before alice's
		// staple changes to her fold-1 commit below, so surfacing it doesn't
		// prematurely deliver that commit to bob via the carrier frame's
		// re-ridden staple.
		let offer2 = try surfaceOffer(from: &alice, to: &bob)

		// Alice builds (but does not yet deliver) a fold commit on Group_A
		// that injects the cross-party PSK off her view of Group_B, still at
		// epoch 1.
		let offer1 = try surfaceOffer(from: &bob, to: &alice)
		try alice.queueProposal(digest: offer1.digest)
		_ = try alice.prepareToEncrypt()
		let aliceFoldFrame = try alice.encrypt(Data("alice-fold".utf8))

		// Bob independently commits his OWN send group (Group_B) — crossed
		// with alice's in-flight commit above — advancing it past the epoch
		// (1) that commit's injected `0xFF02` referenced.
		try bob.queueProposal(digest: offer2.digest)
		_ = try bob.prepareToEncrypt()
		let bobFoldFrame = try bob.encrypt(Data("bob-fold".utf8))
		XCTAssertEqual(bob.sendGroup?.classical.context.epoch, 2)
		XCTAssertNotNil(bob.sendCrossPSKLedger[1])

		// Only now does alice's crossed commit reach bob — its injected PSK
		// resolves only via the ledger bob's own commit above remembered
		// before advancing past epoch 1 (the -02 exporter tree retains only
		// the current epoch's frontier, so a live re-export is impossible).
		let decrypted = try bob.processIncoming(aliceFoldFrame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)

		let fromBob = try alice.processIncoming(bobFoldFrame)
		XCTAssertTrue(fromBob.didApplyRemoteCommit)
	}

	// MARK: - Mutation-verify: tampered `0x00`

	/// A tampered `0x00` staple throws and burns no state — the genuine
	/// commit still applies afterward.
	func testTamperedFoldCommitThrowsAndBurnsNoState() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let offer = try surfaceOffer(from: &bob, to: &alice)
		try alice.queueProposal(digest: offer.digest)
		_ = try alice.prepareToEncrypt()
		let frame = try alice.encrypt(Data("fold".utf8))

		let (staple, proposal, app) = try Frames.decodeMessageFrame(frame)
		var tamperedStaple = staple
		tamperedStaple[tamperedStaple.index(before: tamperedStaple.endIndex)] ^= 0xFF
		let tamperedFrame = Frames.encodeMessageFrame(
			staple: tamperedStaple, proposal: proposal, app: app)

		let recvEpochBefore = bob.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try bob.processIncoming(tamperedFrame))
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, recvEpochBefore)

		let decrypted = try bob.processIncoming(frame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertEqual(decrypted.applicationMessage, Data("fold".utf8))
	}

	// MARK: - `queueProposal` rejections

	/// An approval digest that doesn't match the surfaced offer is
	/// `.proposalRejected`, not a silent no-op — and the offer survives to be
	/// approved correctly afterward.
	func testQueueProposalRejectsDigestMismatch() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let offer = try surfaceOffer(from: &bob, to: &alice)
		var wrongDigest = offer.digest
		wrongDigest[wrongDigest.index(before: wrongDigest.endIndex)] ^= 0xFF

		XCTAssertThrowsError(try alice.queueProposal(digest: wrongDigest)) { error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
		XCTAssertNoThrow(try alice.queueProposal(digest: offer.digest))
	}

	/// An offered "proposal" that doesn't even decode as a publicMessage
	/// Update is `.proposalRejected`.
	func testQueueProposalRejectsUndecodableOffer() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8))
		let (staple, _, app) = try Frames.decodeMessageFrame(bobFrame)

		let garbage = Data("not-an-mls-message".utf8)
		let craftedProposal = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: garbage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncoming(craftedFrame)
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
	}

	/// An offered Update genuinely framed by the APPROVER'S OWN leaf (never a
	/// legitimate peer offer) is `.proposalRejected` — `queueProposal` must
	/// reject a self-Update, not just a different proposal type.
	func testQueueProposalRejectsOwnLeafUpdate() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		guard var sendGroupA = alice.sendGroup else {
			XCTFail("expected alice to be established")
			return
		}
		let (ownUpdateMessage, _) = try sendGroupA.classical.proposeUpdate(
			SessionTestSupport.classicalProvider, signingKey: alice.identity.signingKey,
			framing: .publicMessage)
		let ownUpdateBytes = try ownUpdateMessage.mlsEncoded()

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8))
		let (staple, _, app) = try Frames.decodeMessageFrame(bobFrame)
		let craftedProposal = Frames.encodeProposalSection(
			proposing: Data("alice".utf8), message: ownUpdateBytes)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncoming(craftedFrame)
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
	}

	/// A genuine peer Update whose frame-carried (unauthenticated) `proposing`
	/// claim does not match the verified leaf's own `.basic` identity is
	/// `.proposalRejected` (§11 MF5) — `proposing` rides outside the AAD, so
	/// the wire claim alone proves nothing.
	func testQueueProposalRejectsProposingMismatch() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8))
		let (staple, proposal, app) = try Frames.decodeMessageFrame(bobFrame)
		let (_, bobUpdateMessage) = try Frames.decodeProposalSection(proposal)

		let craftedProposal = Frames.encodeProposalSection(
			proposing: Data("mallory".utf8), message: bobUpdateMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncoming(craftedFrame)
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
	}

	// MARK: - Fold effects whitelist

	/// A commit that folds the approved peer Update AND an extra Add is
	/// rejected as `.invalidFoldEffects` before it is ever applied —
	/// `CommitEffects` has no public initializer, so this drives a real
	/// over-broad commit through swift-mls directly (mirroring
	/// `RekeyTests.testRekeyApplyRejectsCommitWithExtraAddEffect`).
	func testFoldEffectsWithAnAddThrowsInvalidFoldEffects() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let offer = try surfaceOffer(from: &bob, to: &alice)
		try alice.queueProposal(digest: offer.digest)

		guard let sendGroupA = alice.sendGroup else {
			XCTFail("expected alice to be established")
			return
		}
		let mallory = try SessionTestSupport.identity("mallory-fold")

		let badCommitBytes = try withDeployedWireWidth { () throws -> Data in
			guard
				case .publicMessage(let updatePub) = try MLS.RFC9420.Message(
					mlsEncoded: offer.message)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			let verified = try sendGroupA.classical.verifying(
				SessionTestSupport.classicalProvider, proposal: updatePub)
			var proposalStore = MLS.RFC9420.ProposalStore()
			let ref = try proposalStore.insert(
				verified, SessionTestSupport.classicalProvider)

			let transition = try sendGroupA.classical.committing(
				SessionTestSupport.classicalProvider,
				proposals: [
					.reference(ref),
					.proposal(.add(mallory.keyPackage.classical)),
				],
				proposalStore: proposalStore, signingKey: alice.identity.signingKey,
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage)
			return try transition.takeOutput().message.mlsEncoded()
		}

		let badStaple = Frames.encodeMlsMessageStaple(badCommitBytes)
		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8))
		let (_, proposal, app) = try Frames.decodeMessageFrame(carrierFrame)
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposal, app: app)

		let recvEpochBefore = bob.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try bob.processIncoming(badFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidFoldEffects)
		}
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, recvEpochBefore)
	}

	// MARK: - Credential-rotation rejection (the fold/rekey boundary, slice 6)

	/// Author a credential-ROTATING `Upd(self)` for bob's own leaf: a fresh
	/// Ed25519 keypair minted exactly like `TwoMLSIdentity.generate`
	/// (`TwoMLSIdentity.swift:103-106`), installed via swift-mls's rotation
	/// API (`NewSigningIdentity`/`signingClosure(_:current:new:)`) with the
	/// SAME `.basic` clientID — a signature-key-only rotation, still
	/// `.credentialReplaced` per swift-mls's own effect classification
	/// (`CredentialRotationAuthoringTests`'s M1 case is the credential-only
	/// mirror image). Genuinely signed via the rotation ring, not forged, so
	/// only the fold-only credential/sigkey-unchanged boundary — never a
	/// signature failure — is what has to catch it. Proposes directly on
	/// bob's REAL `recvGroup` (mirrors `alice.sendGroup`, the group bob's
	/// real leaf sits in), exactly like `prepareToEncrypt` does for a routine
	/// offer — a throwaway copy would author a proposal whose fresh HPKE leaf
	/// secret is never retained anywhere, so a later fold's path-secret
	/// decryption for bob's own (new) leaf position would fail outright.
	private func authorBobCredentialRotation(bob: inout TwoMLSSession) throws -> Data {
		var mirror = try XCTUnwrap(bob.recvGroup)
		let sk = Curve25519.Signing.PrivateKey()
		let freshSigningKey = try MLS.SignatureSecretKey(sk.rawRepresentation)
		let freshSignatureKey = MLS.SignaturePublicKey(sk.publicKey.rawRepresentation)

		let (message, _) = try mirror.classical.proposeUpdate(
			SessionTestSupport.classicalProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.classicalProvider,
				current: bob.identity.signingKey, new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: bob.identity.clientID),
				signatureKey: freshSignatureKey))
		bob.recvGroup = mirror
		return try message.mlsEncoded()
	}

	/// §15/slice 6 boundary, layer (a): a genuinely-signed credential
	/// rotation offered as bob's `Upd(self)` — same clientID, fresh signature
	/// key — is `.proposalRejected` at `queueProposal`, exactly like any
	/// other malformed offer (§11 MF5/M1): slice 5 is fold-only, and
	/// `validateOfferedUpdate`'s credential/signature-key-unchanged guard is
	/// what catches it BEFORE it ever reaches a commit.
	func testQueueProposalRejectsCredentialRotation() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let rotatingMessage = try authorBobCredentialRotation(bob: &bob)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8))
		let (staple, _, app) = try Frames.decodeMessageFrame(bobFrame)
		let craftedProposal = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncoming(craftedFrame)
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
	}

	/// §15/slice 6 boundary, layer (b): the apply-side counterpart. A
	/// hand-built commit that FOLDS bob's credential-rotating Upd BY
	/// REFERENCE (mirroring `testFoldEffectsWithAnAddThrowsInvalidFoldEffects`'s
	/// over-broad-commit construction, swapping the extra Add for the
	/// poisoned proposal itself) is `.invalidFoldEffects` on delivery, never
	/// applied — the fold-only whitelist
	/// (`TwoPartyRules.validateTwoPartyUpdateCommit`) throws on
	/// `.credentialReplaced` exactly like it does on an Add, and the
	/// recipient's epoch is unchanged (no state burned). The rotating
	/// message is seeded directly into bob's `stagedUpdates` (`@testable`
	/// internal accessor) standing in for what `prepareToEncrypt` would have
	/// appended had bob's own authoring path ever produced a rotation —
	/// today it never does, so this pins the RECEIVE-side backstop rather
	/// than assuming the authoring guard is the only line of defense.
	func testFoldedCredentialRotationThrowsInvalidFoldEffects() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let rotatingMessage = try authorBobCredentialRotation(bob: &bob)
		bob.stagedUpdates.append(
			(
				digest: try SessionTestSupport.classicalProvider.hash(
					rotatingMessage),
				message: rotatingMessage
			))

		guard let sendGroupA = alice.sendGroup else {
			XCTFail("expected alice to be established")
			return
		}

		let badCommitBytes = try withDeployedWireWidth { () throws -> Data in
			guard
				case .publicMessage(let updatePub) = try MLS.RFC9420.Message(
					mlsEncoded: rotatingMessage)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			let verified = try sendGroupA.classical.verifying(
				SessionTestSupport.classicalProvider, proposal: updatePub)
			var proposalStore = MLS.RFC9420.ProposalStore()
			let ref = try proposalStore.insert(
				verified, SessionTestSupport.classicalProvider)

			let transition = try sendGroupA.classical.committing(
				SessionTestSupport.classicalProvider,
				proposals: [.reference(ref)],
				proposalStore: proposalStore, signingKey: alice.identity.signingKey,
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage)
			return try transition.takeOutput().message.mlsEncoded()
		}

		let badStaple = Frames.encodeMlsMessageStaple(badCommitBytes)
		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8))
		let (_, proposal, app) = try Frames.decodeMessageFrame(carrierFrame)
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposal, app: app)

		let recvEpochBefore = bob.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try bob.processIncoming(badFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidFoldEffects)
		}
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, recvEpochBefore)
	}

	// MARK: - Epoch classification (MF7, shared by `0x00` and `0x05`)

	/// A `0x00` commit framed strictly ahead of the receive group's live
	/// epoch is `.epochDesync`, not processed — hand-built via two successive
	/// manual commits on a detached copy of Group_A, neither delivered, so
	/// the second is framed one epoch beyond what Bob's real
	/// `recvGroup.classical` has ever seen.
	func testAheadFoldCommitThrowsEpochDesync() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		var fixtureBob = bob
		guard var groupACopy = alice.sendGroup else {
			XCTFail("expected alice to be established")
			return
		}

		func commitOnce(_ group: inout MLS.RFC9420.Group) throws -> Data {
			let transition = try group.committing(
				SessionTestSupport.classicalProvider, proposals: [],
				signingKey: alice.identity.signingKey,
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage)
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let advanced = try sent.takePending().apply(onto: adopted)
			group = advanced.group
			return commitBytes
		}
		// Epoch 1 -> 2, never delivered to bob.
		_ = try commitOnce(&groupACopy.classical)
		// Epoch 2 -> 3: this is the one fed to bob, one epoch ahead of what
		// his real recvGroup.classical (still at epoch 1) has seen.
		let aheadCommitBytes = try commitOnce(&groupACopy.classical)

		let aheadStaple = Frames.encodeMlsMessageStaple(aheadCommitBytes)
		_ = try fixtureBob.prepareToEncrypt()
		let carrierFrame = try fixtureBob.encrypt(Data("carrier".utf8))
		let (_, proposal, app) = try Frames.decodeMessageFrame(carrierFrame)
		let aheadFrame = Frames.encodeMessageFrame(
			staple: aheadStaple, proposal: proposal, app: app)

		let recvEpochBefore = fixtureBob.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try fixtureBob.processIncoming(aheadFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .epochDesync)
		}
		XCTAssertEqual(fixtureBob.recvGroup?.classical.context.epoch, recvEpochBefore)
	}

	/// A `0x00` staple that merely re-rides a fold commit already applied
	/// off an earlier frame (now strictly behind the receive group's live
	/// epoch) is an idempotent skip, not an error — `didApplyRemoteCommit`
	/// is `false` and the epoch is unchanged.
	func testBehindFoldCommitIsSkippedIdempotently() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let offer = try surfaceOffer(from: &bob, to: &alice)
		try alice.queueProposal(digest: offer.digest)
		_ = try alice.prepareToEncrypt()
		let frame = try alice.encrypt(Data("fold".utf8))

		let decrypted = try bob.processIncoming(frame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		let epochAfter = bob.recvGroup?.classical.context.epoch

		// Alice's next send re-rides the SAME (now-behind, already-applied)
		// `0x00` staple until her next commit supersedes it.
		_ = try alice.prepareToEncrypt()
		let nextFrame = try alice.encrypt(Data("post-fold".utf8))
		let redelivered = try bob.processIncoming(nextFrame)
		XCTAssertFalse(redelivered.didApplyRemoteCommit)
		XCTAssertEqual(redelivered.applicationMessage, Data("post-fold".utf8))
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, epochAfter)
	}
}
