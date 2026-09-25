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

/// The classical FOLD path (no credential rotation). A routine fold
/// round is offer → approve → commit → staple apply: the proposer's
/// `prepareToEncrypt` stages an `Upd(self)` into its receive group (the
/// approver's send group); the approver surfaces it (`processIncoming`'s
/// `DecryptResult.queuedProposal`), approves it (`queueProposal(digest:)`),
/// and its own next `prepareToEncrypt` folds it into an `includePath: true`
/// commit — refreshing both leaves — stapled bare `0x00` (fold-only) or
/// paired with an owed bind as `0x05`. Mirrors the proven PQ fold
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
		app: Data = Data("offer".utf8), rotating: Data? = nil
	) throws -> (digest: Data, proposing: Data, message: Data) {
		_ = try proposer.prepareToEncrypt(rotating: rotating)
		let frame = try proposer.encrypt(app).frame
		_ = try approver.processIncomingDecrypted(frame)
		// `frame` is header-sealed on exit; `approver` is the one whose
		// receive window opens it (its sendGroup mirrors `proposer`'s recv
		// group).
		let (_, proposalSection, _) = try Frames.decodeMessageFrame(
			approver.openOrRaw(frame))
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
		_ = try alice.queueProposal(digest: offer.digest)

		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		XCTAssertEqual(prepared.committedRemoteClientID, Data("bob".utf8))
		XCTAssertEqual(alice.sendGroup?.classical.context.epoch, groupAEpochBefore + 1)

		let frame = try alice.encrypt(Data("alice-fold".utf8)).frame
		// `frame` is header-sealed on exit; `bob` (the intended
		// recipient) is the one whose receive window opens it.
		let (staple, _, _) = try Frames.decodeMessageFrame(bob.openOrRaw(frame))
		// The fold-only staple IS the bare MLSMessage: `0x00` is the message's
		// own `ProtocolVersion` high byte (`mls10` = `00 01`), never a wrapper
		// tag — pin the 4-byte `mls10 + public_message` prefix and that the
		// whole slot decodes as a `.publicMessage` commit (the staple carries a
		// `ComponentID`-bearing `0xFF02` PSK proposal, so decode under the
		// deployed wire width).
		XCTAssertEqual(staple.first, Frames.mlsMessageStapleTag)
		XCTAssertEqual(staple.prefix(4), Data([0x00, 0x01, 0x00, 0x01]))
		try withDeployedWireConventions {
			guard
				case .publicMessage(let commitPub) = try MLS.RFC9420.Message(
					mlsEncoded: staple)
			else {
				return XCTFail("expected a publicMessage commit staple")
			}
			XCTAssertEqual(
				commitPub.content.epoch, groupAEpochBefore,
				"the staple commit is framed at the sender's PRE-apply epoch")
			guard case .commit = commitPub.content.content else {
				return XCTFail("expected the staple to decode as a commit")
			}
		}

		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertEqual(decrypted.applicationMessage, Data("alice-fold".utf8))
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, groupAEpochBefore + 1)

		// Round-trip both directions post-fold.
		_ = try alice.prepareToEncrypt()
		let aliceMsg = try alice.encrypt(Data("post-fold-alice".utf8)).frame
		let fromAlice = try bob.processIncomingDecrypted(aliceMsg)
		XCTAssertEqual(fromAlice.applicationMessage, Data("post-fold-alice".utf8))

		_ = try bob.prepareToEncrypt()
		let bobMsg = try bob.encrypt(Data("post-fold-bob".utf8)).frame
		let fromBob = try alice.processIncomingDecrypted(bobMsg)
		XCTAssertEqual(fromBob.applicationMessage, Data("post-fold-bob".utf8))
	}

	// MARK: - Fold + bind on one `0x05` commit

	/// An owed PQ bind rides the SAME commit that folds an approved peer
	/// Update: Bob owes a bind (via the §A.4 ratchet), Alice offers Bob an
	/// Update which Bob approves, and Bob's next `prepareToEncrypt` folds AND
	/// discharges in one commit, stapled `0x05`.
	func testFoldAndBindRideOneCommit() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		_ = try bob.pqRatchetBind(ctFrame)
		XCTAssertNotNil(bob.owedBind)

		let offer = try surfaceOffer(from: &alice, to: &bob)
		_ = try bob.queueProposal(digest: offer.digest)

		let groupBEpochBefore = try XCTUnwrap(bob.sendGroup?.classical.context.epoch)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		XCTAssertEqual(prepared.committedRemoteClientID, Data("alice".utf8))
		XCTAssertEqual(bob.sendGroup?.classical.context.epoch, groupBEpochBefore + 1)
		XCTAssertNil(bob.owedBind)

		let frame = try bob.encrypt(Data("fold-and-bind".utf8)).frame
		// Opened via `alice` (the intended recipient).
		let (staple, _, _) = try Frames.decodeMessageFrame(alice.openOrRaw(frame))
		XCTAssertEqual(staple.first, Frames.apqPrivateMessageTag)

		let decrypted = try alice.processIncomingDecrypted(frame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertEqual(alice.recvGroup?.classical.context.epoch, groupBEpochBefore + 1)
		XCTAssertTrue(alice.myPQTurn)

		_ = try alice.prepareToEncrypt()
		let msg = try alice.encrypt(Data("post-fold-bind".utf8)).frame
		let fromAlice = try bob.processIncomingDecrypted(msg)
		XCTAssertEqual(fromAlice.applicationMessage, Data("post-fold-bind".utf8))
	}

	// MARK: - The send-side `0xFF02` ledger

	/// Two fold commits land at ONE own-send epoch of the party applying
	/// them (Bob never commits his own send group between the two) — without
	/// the ledger/gate, the second apply's cross-PSK resolution would attempt
	/// a second, failing export off the already-consumed leaf
	/// (`componentSecretConsumed`).
	func testTwoFoldsAtOneOwnSendEpochExerciseTheLedgerGate() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let offer1 = try surfaceOffer(from: &bob, to: &alice)
		_ = try alice.queueProposal(digest: offer1.digest)
		_ = try alice.prepareToEncrypt()
		let frame1 = try alice.encrypt(Data("fold-1".utf8)).frame
		let decrypted1 = try bob.processIncomingDecrypted(frame1)
		XCTAssertTrue(decrypted1.didApplyRemoteCommit)

		let offer2 = try surfaceOffer(from: &bob, to: &alice)
		_ = try alice.queueProposal(digest: offer2.digest)
		_ = try alice.prepareToEncrypt()
		let frame2 = try alice.encrypt(Data("fold-2".utf8)).frame
		let decrypted2 = try bob.processIncomingDecrypted(frame2)
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
		_ = try alice.queueProposal(digest: offer1.digest)
		_ = try alice.prepareToEncrypt()
		let aliceFoldFrame = try alice.encrypt(Data("alice-fold".utf8)).frame

		// Bob independently commits his OWN send group (Group_B) — crossed
		// with alice's in-flight commit above — advancing it past the epoch
		// (1) that commit's injected `0xFF02` referenced.
		_ = try bob.queueProposal(digest: offer2.digest)
		_ = try bob.prepareToEncrypt()
		let bobFoldFrame = try bob.encrypt(Data("bob-fold".utf8)).frame
		XCTAssertEqual(bob.sendGroup?.classical.context.epoch, 2)
		XCTAssertNotNil(bob.sendCrossPSKLedger[1])

		// Only now does alice's crossed commit reach bob — its injected PSK
		// resolves only via the ledger bob's own commit above remembered
		// before advancing past epoch 1 (the -02 exporter tree retains only
		// the current epoch's frontier, so a live re-export is impossible).
		let decrypted = try bob.processIncomingDecrypted(aliceFoldFrame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)

		let fromBob = try alice.processIncomingDecrypted(bobFoldFrame)
		XCTAssertTrue(fromBob.didApplyRemoteCommit)
	}

	// MARK: - Mutation-verify: tampered `0x00`

	/// A tampered `0x00` staple throws and burns no state — the genuine
	/// commit still applies afterward.
	func testTamperedFoldCommitThrowsAndBurnsNoState() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let offer = try surfaceOffer(from: &bob, to: &alice)
		_ = try alice.queueProposal(digest: offer.digest)
		_ = try alice.prepareToEncrypt()
		let frame = try alice.encrypt(Data("fold".utf8)).frame

		// Open via `bob` (the recipient) to reach the plaintext frame to
		// tamper; the reconstructed (now-raw) `tamperedFrame` passes straight
		// through `processIncoming`'s `openOrRaw` (an unsealable blob is
		// returned as-is, the documented receiver convenience).
		let (staple, proposal, app) = try Frames.decodeMessageFrame(bob.openOrRaw(frame))
		var tamperedStaple = staple
		tamperedStaple[tamperedStaple.index(before: tamperedStaple.endIndex)] ^= 0xFF
		let tamperedFrame = Frames.encodeMessageFrame(
			staple: tamperedStaple, proposal: proposal, app: app)

		let recvEpochBefore = bob.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try bob.processIncomingDecrypted(tamperedFrame))
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, recvEpochBefore)

		let decrypted = try bob.processIncomingDecrypted(frame)
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
		let bobFrame = try bob.encrypt(Data("bob-app".utf8)).frame
		// Opened via `alice` (the recipient).
		let (staple, _, app) = try Frames.decodeMessageFrame(alice.openOrRaw(bobFrame))

		let garbage = Data("not-an-mls-message".utf8)
		let craftedProposal = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: garbage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncomingDecrypted(craftedFrame)
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
			SessionTestSupport.classicalProvider,
			signingKey: try alice.sendClassicalSigningKey(),
			framing: .publicMessage)
		let ownUpdateBytes = try ownUpdateMessage.mlsEncoded()

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8)).frame
		// Opened via `alice` (the recipient).
		let (staple, _, app) = try Frames.decodeMessageFrame(alice.openOrRaw(bobFrame))
		let craftedProposal = Frames.encodeProposalSection(
			proposing: Data("alice".utf8), message: ownUpdateBytes)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncomingDecrypted(craftedFrame)
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
	}

	/// A genuine peer Update whose frame-carried (unauthenticated) `proposing`
	/// claim does not match the verified leaf's own `.basic` identity is
	/// `.proposalRejected` — `proposing` rides outside the AAD, so
	/// the wire claim alone proves nothing.
	func testQueueProposalRejectsProposingMismatch() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8)).frame
		// Opened via `alice` (the recipient).
		let (staple, proposal, app) = try Frames.decodeMessageFrame(
			alice.openOrRaw(bobFrame))
		let (_, bobUpdateMessage) = try Frames.decodeProposalSection(proposal)

		let craftedProposal = Frames.encodeProposalSection(
			proposing: Data("mallory".utf8), message: bobUpdateMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncomingDecrypted(craftedFrame)
		XCTAssertThrowsError(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
	}

	// MARK: - Fold effects allow-list

	/// A commit that folds the approved peer Update AND an extra Add is
	/// rejected as `.invalidFoldEffects` before it is ever applied —
	/// `CommitEffects` has no public initializer, so this drives a real
	/// over-broad commit through swift-mls directly (mirroring
	/// `RekeyTests.testRekeyApplyRejectsCommitWithExtraAddEffect`).
	func testFoldEffectsWithAnAddThrowsUnexpectedProposal() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let offer = try surfaceOffer(from: &bob, to: &alice)
		_ = try alice.queueProposal(digest: offer.digest)

		guard let sendGroupA = alice.sendGroup else {
			XCTFail("expected alice to be established")
			return
		}
		let mallory = try SessionTestSupport.identity("mallory-fold")

		let badCommitBytes = try withDeployedWireConventions { () throws -> Data in
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
				proposalStore: proposalStore,
				signingKey: try alice.sendClassicalSigningKey(),
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage)
			return try transition.takeOutput().message.mlsEncoded()
		}

		let badStaple = Frames.encodeMlsMessageStaple(badCommitBytes)
		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8)).frame
		// Opened via `alice` (the recipient) — only the staple is real
		// here; the app section is a throwaway filler `handleStaple` rejects
		// before it is ever decrypted (below), so which peer's window opens
		// it doesn't otherwise matter.
		let (_, proposal, app) = try Frames.decodeMessageFrame(
			alice.openOrRaw(carrierFrame))
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposal, app: app)

		// The exact-id inline allow-list (`TwoPartyRules.validateInlineProposals`)
		// now catches the smuggled `Add` before `validating` ever runs — the
		// fold-only path's expected set never includes `.add` — so this now
		// throws `.unexpectedProposal` rather than reaching the post-apply
		// `.invalidFoldEffects` shape check. Same rejection, earlier gate.
		let recvEpochBefore = bob.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try bob.processIncomingDecrypted(badFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .unexpectedProposal)
		}
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, recvEpochBefore)
	}

	/// The exact-id tightening itself: a commit that folds the approved peer
	/// Update AND an EXTRA `application` PSK naming the cross-party
	/// component (`0xFF02`) but a pskID Bob never ledgered is rejected as
	/// `.unexpectedProposal` — Alice (the constructing side) supplies her
	/// own throwaway value for the forged id via `committing`'s `psk:`
	/// closure so the commit builds and signs genuinely; Bob's allow-list
	/// rejects it from the proposal list alone, never needing (or getting
	/// the chance) to resolve it. Proves the ordering claim: the allow-list
	/// runs on `applyFoldCommit`'s decoded `commitValue.proposals` BEFORE
	/// `recv.classical.validating` — an unresolvable/unexpected PSK id would
	/// otherwise surface as a `validating` failure instead.
	func testFoldWithExtraWrongIDApplicationPSKThrowsUnexpectedProposal() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let offer = try surfaceOffer(from: &bob, to: &alice)
		try alice.queueProposal(digest: offer.digest)

		guard let sendGroupA = alice.sendGroup else {
			XCTFail("expected alice to be established")
			return
		}

		let forgedIdentifier = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: TwoMLSSession.crossPartyComponentID,
			pskID: Data("forged-cross-party-psk".utf8),
			nonce: SessionTestSupport.classicalProvider.randomBytes(
				SessionTestSupport.classicalProvider.hashSize))
		let forgedSecret = SecretBytes(
			randomByteCount: SessionTestSupport.classicalProvider.hashSize)

		let badCommitBytes = try withDeployedWireConventions { () throws -> Data in
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
					.proposal(.preSharedKey(forgedIdentifier)),
				],
				proposalStore: proposalStore,
				signingKey: try alice.sendClassicalSigningKey(),
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage,
				psk: { identifier in
					identifier == forgedIdentifier ? forgedSecret : nil
				})
			return try transition.takeOutput().message.mlsEncoded()
		}

		let badStaple = Frames.encodeMlsMessageStaple(badCommitBytes)
		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8)).frame
		// Opened via `alice` (the recipient) — see the sibling test
		// above for why the app section's own opener doesn't matter here.
		let (_, proposal, app) = try Frames.decodeMessageFrame(
			alice.openOrRaw(carrierFrame))
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposal, app: app)

		let recvEpochBefore = bob.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try bob.processIncomingDecrypted(badFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .unexpectedProposal)
		}
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, recvEpochBefore)
	}

	// MARK: - Credential rotation now accepted (the fold/rekey boundary)

	/// Author a credential-ROTATING `Upd(self)` for bob's own leaf: a fresh
	/// Ed25519 keypair minted exactly like `TwoMLSIdentity.generate`
	/// (`TwoMLSIdentity.swift:103-106`), installed via swift-mls's rotation
	/// API (`NewSigningIdentity`/`signingClosure(_:current:new:)`) with the
	/// SAME `.basic` clientID — a signature-key-only rotation, still
	/// `.credentialReplaced` per swift-mls's own effect classification
	/// (swift-mls's `CredentialRotationAuthoringTests` has the credential-only
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
				current: try bob.recvClassicalSigningKey(), new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: bob.identity.clientID),
				signatureKey: freshSignatureKey))
		bob.recvGroup = mirror
		// This hand-built rotation bypasses `prepareToEncrypt`, which would
		// normally stage the fresh key itself — stage it here so a later
		// fold's `applyFoldCommit` can promote it (same id, new key). Assigned
		// directly, not via `stage`: a routine offer now mints fresh too (D3),
		// so bob's establishment exchange may already hold a DIFFERENT key at
		// this same target, and this hand-built rotation's key must replace
		// it, not collide with it.
		bob.leafKeys.recvClassical.pending[bob.identity.clientID] =
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey)
		return try message.mlsEncoded()
	}

	/// The fold/rekey boundary, layer (a): a genuinely-signed credential
	/// rotation offered as bob's `Upd(self)` — same clientID, fresh signature
	/// key — is now ACCEPTED at `queueProposal`: rotation support widens
	/// `validateOfferedUpdate` to admit a `.credentialReplaced` shape,
	/// consulting the Authentication Service
	/// (`auth.theirs.validSuccessorOfCurrent`, trivially true here since the
	/// id is unchanged) rather than rejecting any credential/signature-key
	/// change outright the way the fold path did before rotation support.
	func testQueueProposalAcceptsSameIDCredentialRotation() throws {
		// `authorBobCredentialRotation` hand-builds a SAME-id, fresh-key
		// rotation directly on bob's recv-classical leaf, bypassing
		// `prepareToEncrypt(rotating:)` (and so `rotationCandidate`)
		// entirely — the pre-existing resolver has no arm for a same-id
		// key-only rotation outside the ring either, so this was never
		// something it covered in the first place.
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let rotatingMessage = try authorBobCredentialRotation(bob: &bob)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-app".utf8)).frame
		// Opened via `alice` (the recipient).
		let (staple, _, app) = try Frames.decodeMessageFrame(alice.openOrRaw(bobFrame))
		let craftedProposal = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: rotatingMessage)
		let craftedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: craftedProposal, app: app)

		let decrypted = try alice.processIncomingDecrypted(craftedFrame)
		XCTAssertNoThrow(
			try alice.queueProposal(digest: decrypted.queuedProposal.digest))
	}

	/// The fold/rekey boundary, layer (b): the apply-side counterpart. A
	/// hand-built commit that FOLDS bob's credential-rotating Upd BY
	/// REFERENCE (mirroring `testFoldEffectsWithAnAddThrowsUnexpectedProposal`'s
	/// construction, swapping the extra Add for the rotating proposal itself)
	/// now applies cleanly: the reshaped `TwoPartyRules.
	/// validateTwoPartyUpdateCommit` treats a moved `.credentialReplaced` leaf
	/// as an equivalent leaf-move signal to `.updated`, and
	/// `AuthCore.adjudicate` accepts a same-id rotation (`pred == succ`
	/// trivially). Contrast `testFoldEffectsWithAnAddThrowsUnexpectedProposal`,
	/// which still rejects a genuine roster change riding the identical
	/// commit shape — rotation support widens exactly the credential axis, not the
	/// membership one. The rotating message is seeded directly into bob's
	/// `stagedUpdates` (`@testable` internal accessor) standing in for what
	/// `prepareToEncrypt(rotating:)` would have appended.
	func testFoldedCredentialRotationIsAcceptedAndAdvancesEpoch() throws {
		// Same reason as `testQueueProposalAcceptsSameIDCredentialRotation`:
		// `authorBobCredentialRotation` bypasses `rotationCandidate` entirely.
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

		// The app section must decrypt against bob's `recvGroup` (Group_A)
		// AFTER this fold lands — sealed on the SAME hypothetical post-fold
		// group the crafted commit produces, not on bob's own unrelated
		// Group_B (unlike the sibling roster-violation test above, this
		// commit is no longer expected to throw before reaching `unprotect`).
		let (commitBytes, appBytes) = try withDeployedWireConventions {
			() throws -> (Data, Data) in
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
				proposalStore: proposalStore,
				signingKey: try alice.sendClassicalSigningKey(),
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage)
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let advanced = try sent.takePending().apply(onto: adopted)
			var postFold = advanced.group
			let appPM = try postFold.protect(
				SessionTestSupport.classicalProvider,
				applicationData: Data("carrier".utf8), authenticatedData: Data(),
				signingKey: try alice.sendClassicalSigningKey())
			let appBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
			return (commitBytes, appBytes)
		}

		let staple = Frames.encodeMlsMessageStaple(commitBytes)
		let proposal = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: rotatingMessage)
		let frame = Frames.encodeMessageFrame(
			staple: staple, proposal: proposal, app: appBytes)

		let recvEpochBefore = try XCTUnwrap(bob.recvGroup?.classical.context.epoch)
		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		// D3: a same-id move (a key refresh only) surfaces neither flag —
		// only an id change would.
		XCTAssertFalse(decrypted.ownCredentialCanonicalized)
		XCTAssertNil(decrypted.newSender)
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, recvEpochBefore + 1)
	}

	// MARK: - Epoch classification (shared by `0x00` and `0x05`)

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
				signingKey: try alice.sendClassicalSigningKey(),
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
		let carrierFrame = try fixtureBob.encrypt(Data("carrier".utf8)).frame
		// Opened via `alice` (the recipient) — the app section is a
		// throwaway filler, same reasoning as the sibling tests above.
		let (_, proposal, app) = try Frames.decodeMessageFrame(
			alice.openOrRaw(carrierFrame))
		let aheadFrame = Frames.encodeMessageFrame(
			staple: aheadStaple, proposal: proposal, app: app)

		let recvEpochBefore = fixtureBob.recvGroup?.classical.context.epoch
		XCTAssertThrowsError(try fixtureBob.processIncomingDecrypted(aheadFrame)) { error in
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
		_ = try alice.queueProposal(digest: offer.digest)
		_ = try alice.prepareToEncrypt()
		let frame = try alice.encrypt(Data("fold".utf8)).frame

		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		let epochAfter = bob.recvGroup?.classical.context.epoch

		// Alice's next send re-rides the SAME (now-behind, already-applied)
		// `0x00` staple until her next commit supersedes it.
		_ = try alice.prepareToEncrypt()
		let nextFrame = try alice.encrypt(Data("post-fold".utf8)).frame
		let redelivered = try bob.processIncomingDecrypted(nextFrame)
		XCTAssertFalse(redelivered.didApplyRemoteCommit)
		XCTAssertEqual(redelivered.applicationMessage, Data("post-fold".utf8))
		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, epochAfter)
	}

	// MARK: - Single-occupancy, latest-wins

	/// A second, DIFFERENT-target offer, surfaced before the first is
	/// approved, replaces it outright: `processIncoming` unconditionally
	/// overwrites `offeredProposal` on every inbound frame, so the
	/// earlier digest is no longer approvable — only the latest one is. A
	/// same-target repeat would be a reuse, not a genuinely later offer, so
	/// the second leg here is a rotation.
	func testLaterOfferReplacesEarlierUnapprovedOfferSingleOccupancyLatestWins() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let bobRotated = Data("bob-rotated".utf8)
		let offer1 = try surfaceOffer(from: &bob, to: &alice, app: Data("first".utf8))
		let offer2 = try surfaceOffer(
			from: &bob, to: &alice, app: Data("second".utf8), rotating: bobRotated)
		XCTAssertNotEqual(offer1.digest, offer2.digest)

		XCTAssertThrowsError(try alice.queueProposal(digest: offer1.digest)) { error in
			XCTAssertEqual(error as? TwoMLSError, .proposalRejected)
		}
		XCTAssertNoThrow(try alice.queueProposal(digest: offer2.digest))
	}

	/// A host-relied invariant: the SAME target's offer repeats byte-for-
	/// byte across frames within one epoch (the per-epoch reuse rule), and
	/// approving the copy that arrives on a SECOND, later frame is
	/// idempotent — the same `queuedProposal` digest, and no duplicate
	/// authorization recorded for the offered id. Uses a ROTATING offer
	/// (an id change), not a routine one: `validateOfferedUpdate` only
	/// calls `auth.theirs.authorize` at all when the offered id is new to
	/// the sequence, so a routine same-id offer would trivially pass this
	/// assertion without ever exercising the authorize call this test
	/// means to pin. Kills: a second approval of the identical digest
	/// appending a second `authorizedNext` entry, or otherwise not being a
	/// clean no-op.
	func testReapprovingARepeatedIdenticalOfferOnANewFrameIsIdempotent() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let bobRotated = Data("bob-rotated-reapproved".utf8)

		// The first frame: surfaced, then approved.
		let offer1 = try surfaceOffer(
			from: &bob, to: &alice, app: Data("first".utf8), rotating: bobRotated)
		_ = try alice.queueProposal(digest: offer1.digest)
		let queuedAfterFirst = try XCTUnwrap(alice.queuedProposal)
		let authorizedCountAfterFirst = alice.auth.theirs.authorizedNext.count
		XCTAssertTrue(alice.auth.theirs.authorizedNext.contains(bobRotated))

		// A SECOND, later frame repeating the identical offer bytes (the
		// per-epoch reuse rule) — surfaced again (re-populating
		// `offeredProposal`), then re-approved.
		let offer2 = try surfaceOffer(
			from: &bob, to: &alice, app: Data("second".utf8), rotating: bobRotated)
		XCTAssertEqual(offer1.digest, offer2.digest, "reused within the same epoch")
		_ = try alice.queueProposal(digest: offer2.digest)
		let queuedAfterSecond = try XCTUnwrap(alice.queuedProposal)

		XCTAssertEqual(queuedAfterFirst.digest, queuedAfterSecond.digest)
		XCTAssertEqual(queuedAfterFirst.proposing, queuedAfterSecond.proposing)
		XCTAssertEqual(queuedAfterFirst.message, queuedAfterSecond.message)
		XCTAssertEqual(
			alice.auth.theirs.authorizedNext.count, authorizedCountAfterFirst,
			"re-approving the identical offer must not authorize it twice")

		// And the fold still proceeds normally off the re-approved offer.
		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
	}
}
