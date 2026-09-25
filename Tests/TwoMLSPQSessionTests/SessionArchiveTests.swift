import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Slice 8a (PR1): the session archive type + encode/decode +
/// restore/reconcile + decode invariants. Every test drives a live session
/// to some state, archives it, round-trips the archive through a test-owned
/// key (`SecretArchive.seal`/`.open` — the app-seal boundary this library
/// itself never crosses), restores, and confirms the restored session
/// continues exactly like the live one it was cloned from.
@available(iOS 26, macOS 26, *)
final class SessionArchiveTests: XCTestCase {
	private let testKey = SecretBytes(randomByteCount: 32)
	private let testAAD = Data("twomlspq-session-archive-tests".utf8)

	/// The app-seal round-trip every test drives an archive through, so
	/// these tests exercise the exact boundary a real caller crosses
	/// (`SecretArchive` in, sealed `Data`, sealed `Data` back to an opened
	/// `SecretArchive`) rather than handing `restore` the unsealed value
	/// `makeSessionArchive` returned.
	private func sealAndOpen(_ archive: SecretArchive) throws -> SecretArchive {
		let sealed = try archive.seal(with: testKey, aad: testAAD)
		return try SecretArchive.open(sealed, with: testKey, aad: testAAD)
	}

	// MARK: - IdentityArchive: two independent per-half signing keys (D1)

	/// The two-key archive round-trip: `IdentityArchive`'s own encode/restore,
	/// isolated from the enclosing `SessionArchive` — both per-half pairs
	/// survive, remain independent (`signatureKey != pqSignatureKey`), and
	/// both derive-checks (classical + PQ, `restore()`) hold.
	func testIdentityArchiveRoundTripPreservesBothIndependentSigningPairs() throws {
		let identity = try TwoMLSIdentity.generate(
			clientID: Data("two-key-identity".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertNotEqual(identity.signatureKey, identity.pqSignatureKey)

		let archive = try IdentityArchive(identity, includeInitSecrets: true)
		let opened = try sealAndOpen(try SecretArchive(encoding: archive))
		let decoded = try opened.decode(IdentityArchive.self)
		let restored = try decoded.restore()

		XCTAssertEqual(restored.signatureKey, identity.signatureKey)
		XCTAssertEqual(restored.pqSignatureKey, identity.pqSignatureKey)
		XCTAssertNotEqual(restored.signatureKey, restored.pqSignatureKey)
		XCTAssertEqual(restored.signingKey.data, identity.signingKey.data)
		XCTAssertEqual(restored.pqSigningKey.data, identity.pqSigningKey.data)
	}

	/// A corrupted `pqSignatureKey` (independent of the classical derive-check)
	/// must fail its OWN derive-check at `restore()` — `.archiveInvalid`, not a
	/// silently-adopted wrong key.
	func testIdentityArchiveRestoreRejectsCorruptPQSignatureKey() throws {
		let identity = try TwoMLSIdentity.generate(
			clientID: Data("corrupt-pq-key".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var archive = try IdentityArchive(identity, includeInitSecrets: true)
		archive.pqSignatureKey = Data(repeating: 0xAB, count: 32)

		XCTAssertThrowsError(try archive.restore()) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A corrupted `pqSigningKey` SECRET (public left intact) must fail the PQ
	/// derive-check at `restore()` — `pub(pqSigningKey) != pqSignatureKey` →
	/// `.archiveInvalid`. The public-key corruption test above cannot reach this
	/// path (the leaf-presents-key check would also fire); this isolates the
	/// secret→public derivation guard.
	func testIdentityArchiveRestoreRejectsCorruptPQSigningKeySecret() throws {
		let identity = try TwoMLSIdentity.generate(
			clientID: Data("corrupt-pq-secret".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var archive = try IdentityArchive(identity, includeInitSecrets: true)
		archive.pqSigningKey = SecretBytes(randomByteCount: 32)

		XCTAssertThrowsError(try archive.restore()) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - 1. established + exchanged

	func testEstablishedCheckpointRoundTripContinuesSendingAndReceiving() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		let opened = try sealAndOpen(archive)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		// PR3c: a SESSION archive carries KP′ init secrets only
		// pre-establishment (an in-flight initiator) — an ESTABLISHED session
		// still omits both, since they're already spent by then. This
		// round-trip only re-confirms that `nil`; the load-bearing carry
		// check — an in-flight initiator's LIVE classical secret IS archived
		// — is `testInFlightInitiatorArchiveCarriesLiveClassicalInitSecret`.
		XCTAssertNil(restored.identity.classicalInitSecretKey)
		XCTAssertNil(restored.identity.pqInitSecretKey)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("hello".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("hello".utf8))

		_ = try bob.prepareToEncrypt()
		let reply = try bob.encrypt(Data("hi".utf8)).frame
		let replyDecrypted = try restored.processIncomingDecrypted(reply)
		XCTAssertEqual(replyDecrypted.applicationMessage, Data("hi".utf8))
	}

	/// The load-bearing carry check for `includeInitSecrets: recvGroup ==
	/// nil` (PR3c): an in-flight initiator (post-`initiate`, before joining
	/// its receive group) still holds a LIVE classical init secret, and the
	/// session archive must now CARRY it — omitting it (the pre-PR3c
	/// behavior) left a restored in-flight initiator permanently unable to
	/// join Group_B (`.sessionNotReady`). The established round-trip above
	/// confirms the mirror case still holds: an ESTABLISHED session still
	/// omits both (already spent). The full restore-then-complete proof is
	/// `testRestoredInFlightInitiatorCompletesEstablishmentAndExchangesAfterRestore`
	/// below.
	func testInFlightInitiatorArchiveCarriesLiveClassicalInitSecret() throws {
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		// Precondition: the runtime secret is genuinely live, else vacuous.
		XCTAssertNotNil(initiated.session.identity.classicalInitSecretKey)
		XCTAssertNil(initiated.session.recvGroup)

		let archive = try initiated.session.makeSessionArchive(kind: .checkpoint)
		let body = try sealAndOpen(archive).decode(SessionArchive.self)
		XCTAssertNotNil(body.identity.classicalInitSecretKey)
		// The initiator's PQ init secret is never read (founding Group_A's
		// PQ half takes only the leaf secret); it is cleared as dead at
		// `initiate`, so it stays absent regardless of the carry flag.
		XCTAssertNil(body.identity.pqInitSecretKey)
	}

	/// The gate's OTHER half: an ESTABLISHED session (`recvGroup != nil`)
	/// archive omits init secrets even when the runtime identity still holds
	/// LIVE ones — the `recvGroup == nil` condition is load-bearing, not an
	/// accident of the secrets being spent by then. Fails if the gate is
	/// ever simplified to unconditional-carry.
	func testEstablishedSessionArchiveOmitsInitSecretsEvenWhenIdentityHoldsThem() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		// Inject a fresh identity carrying LIVE init secrets into the
		// established session; the `recvGroup == nil` gate must still omit
		// them, since this session is established.
		alice.identity = try SessionTestSupport.identity("intruder")
		XCTAssertNotNil(alice.identity.classicalInitSecretKey)

		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		let body = try sealAndOpen(archive).decode(SessionArchive.self)
		XCTAssertNil(body.identity.classicalInitSecretKey)
		XCTAssertNil(body.identity.pqInitSecretKey)
	}

	/// `initialTheirKP` (slice 9, PR3b) DOES survive a session archive
	/// round-trip — unlike the init secrets above, it carries no secret
	/// material (the PEER's own published KP), and it's exactly what a
	/// restored in-flight initiator needs to keep re-sealing
	/// `pendingOutbound()`. Stops at `pendingOutbound()` deliberately, to
	/// isolate this one field's round-trip from the rest of the
	/// establishment flow; the full restore-then-join-Group_B completion
	/// (needing PR3c's carried classical init secret too) is
	/// `testRestoredInFlightInitiatorCompletesEstablishmentAndExchangesAfterRestore`
	/// below.
	func testInFlightInitiatorArchiveCarriesInitialTheirKPForPendingOutbound() throws {
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		let archive = try initiated.session.makeSessionArchive(kind: .checkpoint)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: try sealAndOpen(archive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let envelope = try restored.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		XCTAssertEqual(frame.welcome, initiated.welcome)
		XCTAssertEqual(
			frame.returnKeyPackage,
			try initiated.session.identity.keyPackage.classical.mlsEncoded())
	}

	/// The headline PR3c proof: a session archived mid-establishment — an
	/// in-flight INITIATOR, post-`initiate`, before joining Group_B —
	/// restores and goes on to COMPLETE establishment exactly like the live
	/// session would have. Combines PR3b's `initialTheirKP` (re-seal the
	/// envelope) with this PR's carried classical init secret (join Group_B
	/// off the peer's first frame): `initiate` -> archive -> restore ->
	/// restored `pendingOutbound()` -> `Invitation.openInitial` recovers
	/// `welcome`/`returnKeyPackage` -> `receive` (spawns Bob's session) ->
	/// Bob's first frame -> the RESTORED initiator `processIncoming`s it and
	/// joins Group_B (`isEstablished` true) -> app messages flow both ways.
	/// Without PR3c's archive change this throws
	/// `TwoMLSError.sessionNotReady` at the `processIncoming` step (joining
	/// Group_B needs `identity.classicalJoinCredentials`, which needs the
	/// now-nil classical init secret) — verified by temporarily reverting
	/// the source change.
	func testRestoredInFlightInitiatorCompletesEstablishmentAndExchangesAfterRestore()
		throws
	{
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		let archive = try initiated.session.makeSessionArchive(kind: .checkpoint)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: try sealAndOpen(archive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertFalse(restored.isEstablished)

		let envelope = try restored.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		let returnKP = try MLS.RFC9420.KeyPackage(
			mlsEncoded: try XCTUnwrap(frame.returnKeyPackage))
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: try XCTUnwrap(frame.welcome), theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try restored.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		var bob = received.session
		XCTAssertTrue(bob.isEstablished)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame

		// The restored initiator joins Group_B off Bob's first frame here —
		// exactly the step that throws `.sessionNotReady` without PR3c's
		// carried classical init secret.
		let decrypted = try restored.processIncomingDecrypted(bobFrame)
		XCTAssertTrue(restored.isEstablished)
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-hello".utf8))

		_ = try restored.prepareToEncrypt()
		let aliceFrame = try restored.encrypt(Data("alice-hello".utf8)).frame
		let bobDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		XCTAssertEqual(bobDecrypted.applicationMessage, Data("alice-hello".utf8))
	}

	// MARK: - 2. classical fold, then Core@higher-seq over Checkpoint@lower-seq

	/// A Core-kind archive never carries a PQ snapshot (regardless of
	/// whether the live half has one), so a non-nil `sendGroup.pq` after
	/// this restore can only have come from the spliced-in Checkpoint —
	/// that, plus the newer classical epoch, is the proof the splice ran.
	func testCoreNewerThanCheckpointSplicesPQAndContinues() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let checkpointArchive = try alice.makeSessionArchive(
			kind: .checkpoint)

		// A routine classical fold: Bob offers, Alice approves and folds it
		// into her next commit — classical-only, PQ untouched.
		_ = try bob.prepareToEncrypt()
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		_ = try alice.processIncomingDecrypted(offerFrame)
		// PR2: opened via `alice` (the recipient).
		let (_, offerProposalSection, _) = try Frames.decodeMessageFrame(
			alice.openOrRaw(offerFrame))
		let (_, offerMessage) = try Frames.decodeProposalSection(offerProposalSection)
		let offerDigest = try SessionTestSupport.classicalProvider.hash(offerMessage)
		_ = try alice.queueProposal(digest: offerDigest)

		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let foldFrame = try alice.encrypt(Data("folded".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)

		let coreStateSeq = alice.stateSeq
		let coreArchive = try alice.makeSessionArchive(kind: .core)

		let openedCheckpoint = try sealAndOpen(checkpointArchive)
		let openedCore = try sealAndOpen(coreArchive)
		var restored = try TwoMLSSession.restore(
			core: openedCore, checkpoint: openedCheckpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		XCTAssertNotNil(restored.sendGroup?.pq)
		XCTAssertEqual(
			restored.sendGroup?.classical.context.epoch,
			alice.sendGroup?.classical.context.epoch)
		// The winning (Core) body's own `stateSeq` — not the Checkpoint's —
		// is what the restored session's live counter picks up.
		XCTAssertEqual(restored.stateSeq, coreStateSeq)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("post-restore".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("post-restore".utf8))

		// The spliced-in PQ half is functional, not just present: complete a
		// full A.4 round with the restored session as the responder.
		XCTAssertTrue(bob.myPQTurn)
		if bob.pqPendingOutbound() == nil {
			_ = try bob.prepareToEncrypt()
			_ = try bob.encrypt(Data("stage-ek".utf8))
		}
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try restored.pqRatchetRespond(ekFrame).frame
		_ = try bob.pqRatchetBind(ctFrame)
		let ratchetPrepared = try bob.prepareToEncrypt()
		XCTAssertTrue(ratchetPrepared.didCommit)
		let ratchetBoundFrame = try bob.encrypt(Data("pq-round-bound".utf8)).frame
		let ratchetDecrypted = try restored.processIncomingDecrypted(ratchetBoundFrame)
		XCTAssertEqual(ratchetDecrypted.applicationMessage, Data("pq-round-bound".utf8))
		XCTAssertTrue(restored.myPQTurn)
	}

	// MARK: - 3. mid-A.3 (Group_B.pq deferred)

	func testMidA3CheckpointRestoreThenBootstrapCompletes() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		// Mid-A.3: Alice hasn't joined Group_B.pq yet.
		XCTAssertNil(alice.recvGroup?.pq)
		XCTAssertNotNil(alice.bootstrapKPSecret)
		XCTAssertNotNil(alice.pqInflight)

		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		let opened = try sealAndOpen(archive)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		_ = try restored.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(restored.isFullyEstablished)

		let prepared = try restored.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let frame = try restored.encrypt(Data("bound".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
	}

	// MARK: - 4. mid-A.4 (pqInflight held: the responder's secret + parked CT)

	func testMidA4RespondingCheckpointRestoreThenRoundCompletes() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		guard case .responding = alice.pqInflight else {
			return XCTFail("expected alice to hold `.responding` after sealing")
		}

		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		let opened = try sealAndOpen(archive)
		var restoredAlice = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		_ = try bob.pqRatchetBind(ctFrame)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8)).frame

		let decrypted = try restoredAlice.processIncomingDecrypted(boundFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
		XCTAssertTrue(restoredAlice.myPQTurn)
	}

	// MARK: - 5. fail-closed: divergent PQ manifest

	func testCoreNewerWithDivergentPQManifestIsRejected() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let checkpointArchive = try alice.makeSessionArchive(kind: .checkpoint)

		// A full PQ round moves Alice's recv PQ epoch — the Checkpoint above
		// never saw it.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		_ = try bob.pqRatchetBind(ctFrame)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8)).frame
		_ = try alice.processIncomingDecrypted(boundFrame)

		let coreArchive = try alice.makeSessionArchive(kind: .core)

		let openedCheckpoint = try sealAndOpen(checkpointArchive)
		let openedCore = try sealAndOpen(coreArchive)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: openedCore, checkpoint: openedCheckpoint,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// The fingerprint half of `validateManifestAgreement` is a distinct
	/// check from the epoch half above: two bodies can agree on
	/// `recvPQEpoch` while still disagreeing on the PQ key set that epoch
	/// names — the case the epoch comparison alone can't see (see
	/// `PQEpochManifest`'s own doc). A Core newer than the Checkpoint, with
	/// both PQ epochs equal but the Checkpoint's `recvPQKeysFingerprint`
	/// forged different, must still be rejected.
	func testCoreNewerWithEqualEpochsButDivergentPQFingerprintIsRejected() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let checkpointArchive = try alice.makeSessionArchive(kind: .checkpoint)

		// A routine classical fold — PQ untouched, so the Core's manifest
		// still literally agrees with the Checkpoint's until the forge below.
		_ = try bob.prepareToEncrypt()
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		_ = try alice.processIncomingDecrypted(offerFrame)
		let (_, offerProposalSection, _) = try Frames.decodeMessageFrame(
			alice.openOrRaw(offerFrame))
		let (_, offerMessage) = try Frames.decodeProposalSection(offerProposalSection)
		let offerDigest = try SessionTestSupport.classicalProvider.hash(offerMessage)
		_ = try alice.queueProposal(digest: offerDigest)
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("folded".utf8))

		let coreArchive = try alice.makeSessionArchive(kind: .core)
		let coreBody = try coreArchive.decode(SessionArchive.self)
		var checkpointBody = try checkpointArchive.decode(SessionArchive.self)
		XCTAssertEqual(coreBody.recvPQEpoch, checkpointBody.recvPQEpoch)
		XCTAssertEqual(coreBody.sendPQEpoch, checkpointBody.sendPQEpoch)

		checkpointBody.recvPQKeysFingerprint = GroupKeySetFingerprint(
			current: Data("forged-fingerprint".utf8), pending: [])
		XCTAssertNotEqual(
			coreBody.recvPQKeysFingerprint, checkpointBody.recvPQKeysFingerprint)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: try SecretArchive(encoding: coreBody),
				checkpoint: try sealAndOpen(
					try SecretArchive(encoding: checkpointBody)),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A single Checkpoint — no Core at all, the common restart path, where
	/// `validateManifestAgreement` (splice path only) never even runs — whose
	/// top-level `recvPQKeysFingerprint` disagrees with its OWN archived
	/// `leafKeys.recvPQ` set must still be rejected. Nothing upstream of
	/// `buildSession` proves a Checkpoint's claimed fingerprint is truthful
	/// against the PQ key material the SAME body carries; this is the direct
	/// proof that `buildSession` itself now does.
	func testCheckpointWithFingerprintDisagreeingWithItsOwnLeafKeysIsRejected() throws {
		let alice = try RatchetTests.fullyEstablishedTurnOnBob().alice
		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		let genuineFingerprint = body.recvPQKeysFingerprint
		body.recvPQKeysFingerprint = GroupKeySetFingerprint(
			current: Data("forged-solo-fingerprint".utf8), pending: [])
		XCTAssertNotEqual(body.recvPQKeysFingerprint, genuineFingerprint)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - 6. fail-closed: cross-session mispair

	func testCrossSessionMispairIsRejected() throws {
		let aliceA = try SessionTestSupport.established(alice: "alice-a", bob: "bob-a")
			.alice
		let aliceB = try SessionTestSupport.established(alice: "alice-b", bob: "bob-b")
			.alice

		let coreFromA = try aliceA.makeSessionArchive(kind: .core)
		let checkpointFromB = try aliceB.makeSessionArchive(kind: .checkpoint)

		let openedCore = try sealAndOpen(coreFromA)
		let openedCheckpoint = try sealAndOpen(checkpointFromB)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: openedCore, checkpoint: openedCheckpoint,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - 7. fail-closed: header fields

	func testWrongVersionAndSuiteAreRejected() throws {
		let alice = try SessionTestSupport.established().alice
		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)

		body.version = 2
		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
		body.version = 1

		body.classicalSuite = 0xFFFF
		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	func testKindMismatchIsRejected() throws {
		let alice = try SessionTestSupport.established().alice
		// A Core-kind archive handed in as the (mandatory) Checkpoint slot.
		let coreArchive = try alice.makeSessionArchive(kind: .core)
		let opened = try sealAndOpen(coreArchive)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: opened,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - leafKeys' PQ sets: Checkpoint-only, spliced like the trees

	/// A Core body whose `leafKeys` wrongly carries a PQ set (a Core never
	/// should — the PQ sets ride only in a Checkpoint, exactly like
	/// `GroupEntry.pq` itself) is rejected at `validateHeader`, even though
	/// every other field is a genuine, otherwise-valid Core.
	func testCoreCarryingPQLeafKeySetsIsRejected() throws {
		let (alice, _) = try RatchetTests.fullyEstablishedTurnOnBob()
		let checkpointArchive = try alice.makeSessionArchive(kind: .checkpoint)
		let coreArchive = try alice.makeSessionArchive(kind: .core)

		var coreBody = try coreArchive.decode(SessionArchive.self)
		XCTAssertNil(coreBody.leafKeys.sendPQ)
		coreBody.leafKeys.sendPQ = GroupKeySetArchive(alice.leafKeys.sendPQ)

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: try SecretArchive(encoding: coreBody),
				checkpoint: try sealAndOpen(checkpointArchive),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A Checkpoint body missing either PQ set is rejected — the mandatory
	/// Checkpoint slot must always be able to supply both, since a Core
	/// never can. `validateHeader` is what actually fires first for this
	/// exact corruption, but it isn't the only guard that would: even
	/// without it, `LeafKeysArchive.restore()`'s own `guard let sendPQ,
	/// let recvPQ` inside `buildSession` independently catches the same
	/// absence as a defense-in-depth backstop.
	func testCheckpointMissingPQLeafKeySetsIsRejected() throws {
		let alice = try RatchetTests.fullyEstablishedTurnOnBob().alice
		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		XCTAssertNotNil(body.leafKeys.sendPQ)
		body.leafKeys.sendPQ = nil

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A spliced restore (newer Core + older Checkpoint, PQ untouched
	/// between the two) takes `leafKeys.sendPQ`/`recvPQ` from the
	/// Checkpoint, since the Core never carries them at all.
	func testSplicedRestoreTakesLeafKeysPQSetsFromCheckpoint() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let checkpointArchive = try alice.makeSessionArchive(kind: .checkpoint)

		// A routine classical fold — PQ, and so `leafKeys.sendPQ`/`recvPQ`,
		// untouched — exactly like the tree-splice test above.
		_ = try bob.prepareToEncrypt()
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		_ = try alice.processIncomingDecrypted(offerFrame)
		let (_, offerProposalSection, _) = try Frames.decodeMessageFrame(
			alice.openOrRaw(offerFrame))
		let (_, offerMessage) = try Frames.decodeProposalSection(offerProposalSection)
		let offerDigest = try SessionTestSupport.classicalProvider.hash(offerMessage)
		_ = try alice.queueProposal(digest: offerDigest)
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("folded".utf8))

		let coreArchive = try alice.makeSessionArchive(kind: .core)
		let restored = try TwoMLSSession.restore(
			core: try sealAndOpen(coreArchive),
			checkpoint: try sealAndOpen(checkpointArchive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		XCTAssertEqual(
			restored.leafKeys.sendPQ.current?.signatureKey,
			alice.leafKeys.sendPQ.current?.signatureKey)
		XCTAssertEqual(
			restored.leafKeys.recvPQ.current?.signatureKey,
			alice.leafKeys.recvPQ.current?.signatureKey)
	}

	// MARK: - Decode invariant: the pinned bootstrap commitment length

	func testShortBootstrapCommitmentIsRejected() throws {
		let bob = try SessionTestSupport.establishedAndExchanged().bob
		// Bob is the responder: `expectedBootstrapKPCommitment` is set on him.
		XCTAssertNotNil(bob.expectedBootstrapKPCommitment)

		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		body.expectedBootstrapKPCommitment = Data([1, 2, 3])

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - Blocker (diff review): the initiator's normal mid-A.3 restore

	/// Alice's baseline Checkpoint is minted at `initiate` with `recvGroup ==
	/// nil` (so `recvClassicalGroupID == nil`); her very next Core, taken
	/// once Bob's first frame has joined her into Group_B, has it set. A
	/// restore pairing that Core with the baseline Checkpoint must not
	/// reject on that ordinary transition — and A.3 must still complete
	/// (bootstrap + bind) off the restored session afterward.
	func testInitiatorCoreAfterJoiningOverBaselineCheckpointRestoresAndCompletesA3() throws {
		let established = try SessionTestSupport.established()
		var alice = established.alice
		var bob = established.bob

		let checkpointArchive = try alice.makeSessionArchive(kind: .checkpoint)
		XCTAssertNil(alice.recvGroup)

		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(frame)
		XCTAssertNotNil(alice.recvGroup)

		let coreArchive = try alice.makeSessionArchive(kind: .core)

		let openedCheckpoint = try sealAndOpen(checkpointArchive)
		let openedCore = try sealAndOpen(coreArchive)
		var restored = try TwoMLSSession.restore(
			core: openedCore, checkpoint: openedCheckpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		// Both directions continue.
		_ = try restored.prepareToEncrypt()
		let outFrame = try restored.encrypt(Data("hello".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(outFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("hello".utf8))

		_ = try bob.prepareToEncrypt()
		let replyFrame = try bob.encrypt(Data("hi".utf8)).frame
		let replyDecrypted = try restored.processIncomingDecrypted(replyFrame)
		XCTAssertEqual(replyDecrypted.applicationMessage, Data("hi".utf8))

		// A.3 then completes off the restored session.
		let kpFrame = try restored.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try restored.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(restored.isFullyEstablished)

		let prepared = try restored.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try restored.encrypt(Data("bound".utf8)).frame
		let boundDecrypted = try bob.processIncomingDecrypted(boundFrame)
		XCTAssertEqual(boundDecrypted.applicationMessage, Data("bound".utf8))
	}

	// MARK: - `validateIdentityAgreement`, isolated from the step-7 pair check

	func testValidateIdentityAgreementRejectsMismatchedClientID() throws {
		let alice = try SessionTestSupport.established().alice
		let checkpoint = try alice.makeSessionArchive(kind: .checkpoint)
			.decode(SessionArchive.self)
		var core = checkpoint
		core.identity.clientID = Data("someone-else".utf8)

		XCTAssertThrowsError(
			try TwoMLSSession.validateIdentityAgreement(
				core: core, checkpoint: checkpoint)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// NIT9/§7: the PQ half's signature key is compared too, symmetric with
	/// the classical `signatureKey` check above (D1 — the two per-half keys
	/// are independent, so a mispair on either must be caught).
	func testValidateIdentityAgreementRejectsMismatchedPQSignatureKey() throws {
		let alice = try SessionTestSupport.established().alice
		let checkpoint = try alice.makeSessionArchive(kind: .checkpoint)
			.decode(SessionArchive.self)
		var core = checkpoint
		core.identity.pqSignatureKey = Data(repeating: 0xFF, count: 32)

		XCTAssertThrowsError(
			try TwoMLSSession.validateIdentityAgreement(
				core: core, checkpoint: checkpoint)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	func testValidateIdentityAgreementRejectsMismatchedSendGroupID() throws {
		let alice = try SessionTestSupport.established().alice
		let checkpoint = try alice.makeSessionArchive(kind: .checkpoint)
			.decode(SessionArchive.self)
		var core = checkpoint
		core.sendClassicalGroupID = Data("wrong-group".utf8)

		XCTAssertThrowsError(
			try TwoMLSSession.validateIdentityAgreement(
				core: core, checkpoint: checkpoint)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// The exact blocker shape, isolated to just this one check: a
	/// Checkpoint minted before the recv group exists (`nil`) paired with an
	/// older-or-equal-stateSeq... no — a NEWER Core that has since joined it
	/// (`Some`) must be allowed, since `nil` names the OLDER blob.
	func testValidateIdentityAgreementAllowsRecvGroupIDGoingNilToSomeOnTheNewerSide() throws {
		let alice = try SessionTestSupport.established().alice
		var checkpoint = try alice.makeSessionArchive(kind: .checkpoint)
			.decode(SessionArchive.self)
		checkpoint.recvClassicalGroupID = nil
		checkpoint.stateSeq = 1
		var core = checkpoint
		core.recvClassicalGroupID = Data("group-b".utf8)
		core.stateSeq = 2

		XCTAssertNoThrow(
			try TwoMLSSession.validateIdentityAgreement(
				core: core, checkpoint: checkpoint))
	}

	/// The mirror shape (a nil on the newer side) must still be rejected —
	/// `nil` is only tolerated when it names the OLDER blob.
	func testValidateIdentityAgreementRejectsRecvGroupIDGoingSomeToNilOnTheNewerSide() throws {
		let alice = try SessionTestSupport.established().alice
		var checkpoint = try alice.makeSessionArchive(kind: .checkpoint)
			.decode(SessionArchive.self)
		checkpoint.recvClassicalGroupID = Data("group-b".utf8)
		checkpoint.stateSeq = 1
		var core = checkpoint
		core.recvClassicalGroupID = nil
		core.stateSeq = 2

		XCTAssertThrowsError(
			try TwoMLSSession.validateIdentityAgreement(
				core: core, checkpoint: checkpoint)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - Tie: equal stateSeq takes the Checkpoint outright

	func testTieStateSeqTakesCheckpointNotCore() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		// The live `stateSeq` only ever moves forward on its own, so the tie
		// this test exercises (unreachable via the live cadence alone) is
		// forced explicitly here — `@testable`-only, never something the
		// public API lets an app do.
		alice.stateSeq = 5
		let checkpointArchive = try alice.makeSessionArchive(kind: .checkpoint)

		_ = try bob.prepareToEncrypt()
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		_ = try alice.processIncomingDecrypted(offerFrame)
		// PR2: opened via `alice` (the recipient).
		let (_, offerProposalSection, _) = try Frames.decodeMessageFrame(
			alice.openOrRaw(offerFrame))
		let (_, offerMessage) = try Frames.decodeProposalSection(offerProposalSection)
		let offerDigest = try SessionTestSupport.classicalProvider.hash(offerMessage)
		_ = try alice.queueProposal(digest: offerDigest)
		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		_ = try alice.encrypt(Data("folded".utf8))

		// Tagged at the SAME stateSeq as the (older, pre-fold) Checkpoint.
		alice.stateSeq = 5
		let coreArchive = try alice.makeSessionArchive(kind: .core)

		let restored = try TwoMLSSession.restore(
			core: try sealAndOpen(coreArchive),
			checkpoint: try sealAndOpen(checkpointArchive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		// A tie (`>=`) takes the Checkpoint outright — its pre-fold epoch,
		// never the Core's newer one.
		XCTAssertEqual(restored.sendGroup?.classical.context.epoch, 1)
	}

	// MARK: - `.initiating` (held ML-KEM secret) restore

	func testInitiatingCheckpointRestoreThenRoundCompletes() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		guard case .initiating = bob.pqInflight else {
			return XCTFail("expected bob to hold `.initiating` after self-staging")
		}
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())

		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		let opened = try sealAndOpen(archive)
		var restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		_ = try restoredBob.pqRatchetBind(ctFrame)
		let prepared = try restoredBob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try restoredBob.encrypt(Data("bound".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(boundFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
	}

	// MARK: - `.rekeyInitiated` restore

	func testRekeyInitiatedCheckpointRestoreThenRoundCompletes() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		let updFrame = try bob.pqRekeyBegin().frame
		guard case .rekeyInitiated = bob.pqInflight else {
			return XCTFail("expected bob to hold `.rekeyInitiated` after pqRekeyBegin")
		}

		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		let opened = try sealAndOpen(archive)
		var restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let commitFrame = try alice.pqRekeyRespond(updFrame).frame
		_ = try restoredBob.pqRekeyApply(commitFrame)
		let prepared = try restoredBob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try restoredBob.encrypt(Data("rekey-bound".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(boundFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("rekey-bound".utf8))
	}

	/// The id-moving variant: bob's own recv-PQ leaf lags, so his parked
	/// `Upd′` carries `mine.current` and stages its fresh key under
	/// `recvPQ.pending[mine.current]` — that pending entry, and the parked
	/// Upd′ itself, must both survive a checkpoint round-trip: the restored
	/// session re-serves the IDENTICAL bytes, then completes the round the
	/// same as the live session would. Kills: `pending[mine.current]` not
	/// persisted; a restore check that rejects a parked target ≠ presented
	/// id.
	func testIdMovingParkedUpdSurvivesCheckpointRestoreAndCompletes() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let bobNewID = Data("bob-archive-catchup".utf8)

		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		// Bob holds the PQ turn, so his own offer's `encrypt` self-drives
		// an incidental A.4 — discard it so `pqRekeyBegin` below is
		// unobstructed.
		if case .initiating = bob.pqInflight {
			bob.pqInflight = nil
			bob.pendingSideBand = nil
		}
		let offerDecrypted = try alice.processIncomingDecrypted(offerFrame)
		_ = try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(bob.myPrincipalState, .sync(bobNewID))
		XCTAssertTrue(bob.myPQTurn)

		let begin = try bob.pqRekeyBegin()
		guard case .rekeyInitiated(let updBytes) = bob.pqInflight else {
			return XCTFail("expected bob to hold `.rekeyInitiated` after pqRekeyBegin")
		}
		let stagedKey = try XCTUnwrap(bob.leafKeys.recvPQ.pending[bobNewID])

		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		let opened = try sealAndOpen(archive)
		var restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(
			restoredBob.leafKeys.recvPQ.pending[bobNewID]?.signatureKey,
			stagedKey.signatureKey)

		// Re-serve gives identical bytes (idempotent re-serve, :49-54).
		let reserved = try restoredBob.pqRekeyBegin()
		guard case .rekeyInitiated(let reservedBytes) = restoredBob.pqInflight else {
			return XCTFail(
				"expected the restored session to still hold `.rekeyInitiated`")
		}
		XCTAssertEqual(reservedBytes, updBytes)

		let commitFrame = try alice.pqRekeyRespond(reserved.frame).frame
		_ = try restoredBob.pqRekeyApply(commitFrame)
		XCTAssertTrue(restoredBob.leafKeys.recvPQ.pending.isEmpty)
		let recvPQLeaf = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(restoredBob.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(recvPQLeaf.credential), bobNewID)
	}

	/// The self-driven catch-up's own `encrypt` returns `.checkpoint`
	/// (never `.core`) — restoring from that checkpoint (`core: nil`)
	/// carries the parked round along, and an explicit `pqRekeyBegin()`
	/// re-serves the IDENTICAL plaintext (AD included), same as an
	/// explicitly-begun round would. The `.checkpoint` kind assertion
	/// below is mutation-invisible on its own — the sticky upgrade already
	/// produces it whenever `encrypt` would otherwise answer `.core`, so
	/// this test's actual kill is downstream: restoring and re-serving
	/// proves the archive really carries the self-staged round and its
	/// `pending` key, not just the kind bit.
	func testSelfDrivenCatchUpReturnsACheckpointThatRestoresTheParkedUpd() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let bobNewID = Data("bob-self-driven-archive".utf8)

		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		if case .initiating = bob.pqInflight {
			bob.pqInflight = nil
			bob.pendingSideBand = nil
		}
		let offerDecrypted = try alice.processIncomingDecrypted(offerFrame)
		try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		XCTAssertTrue(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)
		XCTAssertEqual(bob.myPrincipalState, .sync(bobNewID))
		XCTAssertTrue(bob.myPQTurn)

		// The self-drive, not an explicit `pqRekeyBegin` call.
		_ = try bob.prepareToEncrypt()
		let selfDriven = try bob.encrypt(Data("self-driven".utf8))
		XCTAssertEqual(selfDriven.update.kind, .checkpoint)
		guard case .rekeyInitiated(let updBytes) = bob.pqInflight else {
			return XCTFail("expected the self-drive to have staged `.rekeyInitiated`")
		}

		let opened = try sealAndOpen(selfDriven.update.archive)
		var restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let reserved = try restoredBob.pqRekeyBegin()
		guard case .rekeyInitiated(let reservedBytes) = restoredBob.pqInflight else {
			return XCTFail(
				"expected the restored session to still hold `.rekeyInitiated`")
		}
		XCTAssertEqual(reservedBytes, updBytes)

		let commitFrame = try alice.pqRekeyRespond(reserved.frame).frame
		_ = try restoredBob.pqRekeyApply(commitFrame)
		let recvPQLeaf = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(restoredBob.recvGroup?.pq))
		XCTAssertEqual(try basicIdentifier(recvPQLeaf.credential), bobNewID)
	}

	// MARK: - Pin safety check (book group-rules.md rule 4)

	/// A `pinned` id nobody presents — no live PQ leaf carries it and it is
	/// not even a known candidate — is rejected. Mutation: dropping the
	/// subset check against `presented` makes this fail.
	func testRestoreRejectsAStalePin() throws {
		let bob = try RatchetTests.fullyEstablishedTurnOnBob().bob
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		body.auth.mine.pinned = [Data("nobody-presents-this".utf8)]

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A `pinned` id that IS presented but is also an authorized-but-not-
	/// yet-canonical candidate (`authorizedNext` minus `history`) is
	/// rejected — pinning a candidate would block its own canonicalization.
	/// Mutation: dropping the candidate-exclusion clause from the allowed-
	/// pins computation (checking subset-of-`presented` alone) makes this
	/// fail.
	func testRestoreRejectsAPinnedCandidate() throws {
		let bob = try RatchetTests.fullyEstablishedTurnOnBob().bob
		let bobID = bob.identity.clientID
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		// `bobID` is presented (bob's own founding leaf, in both his PQ
		// trees) but re-shaped here as an outstanding candidate: dropped
		// from `history`, re-added only to `authorizedNext`.
		body.auth.mine.history = []
		body.auth.mine.authorizedNext = [bobID]
		body.auth.mine.pinned = [bobID]

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A presented id covered by NEITHER `history` NOR `pinned` NOR
	/// `authorizedNext` — stranded, as if the id had been evicted from
	/// history with nothing ever pinning it — is rejected. Mutation:
	/// dropping the "every presented id is covered" check makes this fail.
	func testRestoreRejectsAStrandedPresentedID() throws {
		let bob = try RatchetTests.fullyEstablishedTurnOnBob().bob
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		body.auth.mine.history = []
		// The live session's own archive already pins the presented id
		// correctly (`pqPinnedAuth()`) — clear it too, so the coverage gap
		// this test targets is genuine, not masked by the still-legitimate
		// pin.
		body.auth.mine.pinned = []

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A duplicate entry in `pinned` is rejected on its own, independent of
	/// coverage. Mutation: dropping the no-duplicates check makes this fail.
	func testRestoreRejectsADuplicatePin() throws {
		let bob = try RatchetTests.fullyEstablishedTurnOnBob().bob
		let bobID = bob.identity.clientID
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		// `bobID` is already covered by `history`, so this is otherwise a
		// no-op pin — only the duplicate itself is invalid.
		body.auth.mine.pinned = [bobID, bobID]

		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A healthy archive — pins already the normal form the live engine
	/// maintains (every currently-presented id, here just bob's own
	/// founding id, still in `history` too) — restores without complaint,
	/// and a live state update afterward leaves it exactly stable
	/// (idempotent recompute). An UNDER-populated `pinned` (a genuine
	/// pre-fix archive, which never called `.pin()` at all) is tolerated
	/// too — not exact equality — as long as nothing presented goes
	/// uncovered by `history`/`authorizedNext` alone; the next state
	/// update self-heals it to this same normal form.
	func testRestoreAcceptsHealthyPinsAndStaysNormalizedAfterward() throws {
		let bob = try RatchetTests.fullyEstablishedTurnOnBob().bob
		let bobID = bob.identity.clientID
		XCTAssertEqual(bob.auth.mine.pinned, [bobID])
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		// An under-populated (pre-fix-shaped) `pinned` — still tolerated,
		// since `bobID` remains covered by `history` alone.
		body.auth.mine.pinned = []
		let opened = try sealAndOpen(try SecretArchive(encoding: body))
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(restored.auth.mine.pinned, [])

		_ = try restored.prepareToEncrypt()
		_ = try restored.encrypt(Data("still-healthy".utf8))
		XCTAssertEqual(restored.auth.mine.pinned, [bobID])
	}

	// MARK: - fail-closed: every group the recorded state implies

	// Each stripped group takes its manifest fields with it, so the
	// manifest-vs-rebuilt-groups check can't be what rejects the body.

	private func checkpointBody(_ session: TwoMLSSession) throws -> SessionArchive {
		try session.makeSessionArchive(kind: .checkpoint).decode(SessionArchive.self)
	}

	private func restoreCheckpoint(_ body: SessionArchive) throws -> TwoMLSSession {
		try TwoMLSSession.restore(
			core: nil, checkpoint: try SecretArchive(encoding: body),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	private func assertRestoreRejects(
		_ body: SessionArchive, file: StaticString = #filePath, line: UInt = #line
	) {
		XCTAssertThrowsError(try restoreCheckpoint(body), file: file, line: line) { error in
			XCTAssertEqual(
				error as? TwoMLSError, .archiveInvalid, file: file, line: line)
		}
	}

	func testCheckpointWithOnlyRequiredFieldsIsRejected() throws {
		let established = try SessionTestSupport.established()
		for session in [established.alice, established.bob] {
			let full = try checkpointBody(session)
			assertRestoreRejects(
				SessionArchive(
					version: full.version, classicalSuite: full.classicalSuite,
					pqSuite: full.pqSuite, kind: full.kind,
					stateSeq: full.stateSeq,
					identity: full.identity, auth: full.auth,
					currentStaple: full.currentStaple,
					initiated: full.initiated,
					pqTurnMine: full.pqTurnMine,
					stagedUpdates: full.stagedUpdates,
					sendCrossPSKLedger: full.sendCrossPSKLedger,
					leafKeys: full.leafKeys,
					sendPQKeysFingerprint: full.sendPQKeysFingerprint,
					recvPQKeysFingerprint: full.recvPQKeysFingerprint))
		}
	}

	func testCheckpointMissingSendGroupIsRejected() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		for session in [alice, bob] {
			var body = try checkpointBody(session)
			body.sendGroup = nil
			body.sendClassicalGroupID = nil
			body.sendPQEpoch = nil
			assertRestoreRejects(body)
		}
	}

	/// The pre-join initiator is the one state without a recv group; it
	/// records that by still carrying its classical init secret.
	func testCheckpointMissingRecvGroupIsRejectedOutsidePreJoinInitiator() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		XCTAssertNil(alice.recvGroup)
		var preJoin = try checkpointBody(alice)
		XCTAssertNoThrow(try restoreCheckpoint(preJoin))
		preJoin.identity.classicalInitSecretKey = nil
		assertRestoreRejects(preJoin)

		_ = try bob.prepareToEncrypt()
		_ = try alice.processIncomingDecrypted(
			try bob.encrypt(Data("bob-hello".utf8)).frame)
		for session in [alice, bob] {
			var body = try checkpointBody(session)
			body.recvGroup = nil
			body.recvClassicalGroupID = nil
			body.recvPQEpoch = nil
			assertRestoreRejects(body)
		}
	}

	/// The §A.3 round registers at `initiate`, so a pre-join initiator's own
	/// `.bootstrapInitiated` archive restores — the round it names cannot
	/// have gone any further than registration without the join it would
	/// also need.
	func testCheckpointPreJoinInitiatorAcceptsOnlyAnUnregisteredOrFreshRound() throws {
		let (alice, _, _, _, _, _) = try SessionTestSupport.established()
		XCTAssertNil(alice.recvGroup)
		guard case .bootstrapInitiated = alice.pqInflight else {
			return XCTFail("expected `initiate` to register `.bootstrapInitiated`")
		}
		XCTAssertNoThrow(try restoreCheckpoint(try checkpointBody(alice)))

		// Anything past registration — here, the responder's own round
		// state — implies a recv group this archive doesn't carry.
		var body = try checkpointBody(alice)
		body.pqInflight = .bootstrapResponded
		assertRestoreRejects(body)
	}

	/// Group_B's PQ half is absent until §A.3 founds it (the responder's
	/// send) or joins it (the initiator's recv); from then on the round
	/// state or an export watermark names it.
	func testCheckpointMissingGroupBPQHalfIsRejectedOnceA3ReachesIt() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertNil(bob.sendGroup?.pq)
		XCTAssertNoThrow(try restoreCheckpoint(try checkpointBody(bob)))

		_ = try bob.pqBootstrapRespond(try alice.pqBootstrapBegin().frame)
		guard case .bootstrapResponded = bob.pqInflight else {
			return XCTFail("expected bob to hold `.bootstrapResponded`")
		}
		var respondedBob = try checkpointBody(bob)
		respondedBob.sendGroup?.pq = nil
		respondedBob.sendPQEpoch = nil
		assertRestoreRejects(respondedBob)

		let (settledAlice, settledBob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertNotNil(settledBob.lastSendPQExported)
		XCTAssertNotNil(settledAlice.lastCrossInjectedPQ)

		var bobBody = try checkpointBody(settledBob)
		bobBody.sendGroup?.pq = nil
		bobBody.sendPQEpoch = nil
		assertRestoreRejects(bobBody)

		var aliceBody = try checkpointBody(settledAlice)
		aliceBody.recvGroup?.pq = nil
		aliceBody.recvPQEpoch = nil
		assertRestoreRejects(aliceBody)
	}

	func testManifestNamingAGroupTheBodyLacksIsRejected() throws {
		let alice = try SessionTestSupport.established().alice
		var body = try checkpointBody(alice)
		XCTAssertNil(body.recvGroup)
		body.recvClassicalGroupID = Data("group-b".utf8)
		assertRestoreRejects(body)
	}
}
