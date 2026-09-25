import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

// XCTest (not swift-testing): Swift Testing rejects an `@available`-gated
// `@Suite` TYPE (this whole session API is `@available(iOS 26, macOS 26)`,
// so the suite would have to carry that gate) — an ungated suite with
// per-test gates works, but this file follows the module's existing XCTest
// convention instead.
//
// Book §A.1: the host app payload carried in the establishment envelope,
// and app messages sent before the initiator joins the acceptor's group.
// Companion coverage lives alongside the existing suites (`EnvelopeTests`,
// `SessionArchiveTests`, `SessionMigrationTests`); this is the new file
// this change adds.
@available(iOS 26, macOS 26, *)
final class PreEstablishmentTests: XCTestCase {
	private let testKey = SecretBytes(randomByteCount: 32)
	private let testAAD = Data("pre-establishment-tests".utf8)

	private func sealAndOpen(_ archive: SecretArchive) throws -> SecretArchive {
		let sealed = try archive.seal(with: testKey, aad: testAAD)
		return try SecretArchive.open(sealed, with: testKey, aad: testAAD)
	}

	/// `SessionMigrationTests`' own conversion, duplicated here (that file's
	/// helper is private to its XCTestCase): a native session's per-role
	/// signing keys, migrator-shaped, so a mint fixture built from a fresh
	/// (non-owner-keyed) `initiate()` session's leaves can still resolve —
	/// `initiate` founds on FRESH leaves, never `identity`'s own, so the
	/// owner-keyed fallback conversion can't find them without this.
	private func migratedLeafKeys(from leafKeys: LeafKeys) -> MigratedLeafKeys {
		func convert(_ set: GroupKeySet) -> MigratedGroupKeys {
			MigratedGroupKeys(
				current: set.current.map {
					MigratedLeafKey(
						signingKey: $0.signingKey.data,
						signatureKey: $0.signatureKey.data)
				},
				pending: set.pending.map { target, key in
					MigratedPendingLeafKey(
						target: target,
						key: MigratedLeafKey(
							signingKey: key.signingKey.data,
							signatureKey: key.signatureKey.data))
				})
		}
		return MigratedLeafKeys(
			sendClassical: convert(leafKeys.sendClassical),
			recvClassical: convert(leafKeys.recvClassical),
			sendPQ: convert(leafKeys.sendPQ), recvPQ: convert(leafKeys.recvPQ))
	}

	/// A last-resort invitation plus native `initiate` — a fresh pre-join
	/// initiator (Alice) and the invitation Bob published it against.
	private func setup() throws -> (alice: TwoMLSSession, invitation: Invitation) {
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
		return (initiated.session, invitation)
	}

	// MARK: - Payload drain at the join

	/// A live pre-join initiator carrying a payload drains it the
	/// moment it joins Group_B, and the restore after that join succeeds.
	/// Kills: dropping the clear in `joinGroupB`.
	func testPayloadDrainsAtTheJoinAndRestoreAfterJoinSucceeds() throws {
		var (alice, invitation) = try setup()
		alice.initialAppPayload = Data("host app payload".utf8)
		XCTAssertNotNil(alice.initialAppPayload)

		// With a payload set, `pendingOutbound()` seals the payload-only
		// shape (the either/or composer) — `frame.welcome` is nil, so the
		// welcome/return-KP a real host would extract FROM the (opaque, to
		// this engine) payload are instead read straight off `alice` here.
		let envelope = try alice.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		XCTAssertEqual(frame.appPayload, alice.initialAppPayload)
		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try EstablishmentMessages.encodeKeyPackage(
				alice.identity.keyPackage.classical))
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: alice.currentStaple, theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		var bob = received.session
		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame

		_ = try alice.processIncoming(bobFrame)
		XCTAssertTrue(alice.isEstablished)
		XCTAssertNil(alice.initialAppPayload)

		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: try sealAndOpen(archive),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertTrue(restored.isEstablished)
	}

	/// A migrated pre-join initiator's payload is rejected at the mint once
	/// it carries no seal target (`initialTheirKP == nil`) — a payload
	/// with nothing left to carry it is dead state. Kills: dropping the
	/// new clause at the mint site.
	func testMintRejectsAPayloadWithNoSealTarget() throws {
		let (alice, _) = try setup()
		let send = try XCTUnwrap(alice.sendGroup)
		let identity = alice.identity
		let migrated = try MigratedSession(
			stateSeq: alice.stateSeq,
			initiated: alice.initiated,
			identity: MigratedSessionIdentity(
				clientID: identity.clientID,
				signingKey: identity.signingKey.data,
				signatureKey: identity.signatureKey.data,
				pqSigningKey: identity.pqSigningKey.data,
				pqSignatureKey: identity.pqSignatureKey.data,
				classicalLeafSecretKey: identity.classicalLeafSecretKey.data,
				classicalInitSecretKey: identity.classicalInitSecretKey?.data,
				pqLeafSecretKey: identity.pqLeafSecretKey.data,
				pqInitSecretKey: identity.pqInitSecretKey?.data,
				classicalKeyPackage: try identity.keyPackage.classical.mlsEncoded(),
				pqKeyPackage: try identity.keyPackage.pq.mlsEncoded()),
			auth: MigratedAuth(
				mine: MigratedPartySequence(
					history: alice.auth.mine.history,
					authorizedNext: alice.auth.mine.authorizedNext,
					pinned: alice.auth.mine.pinned),
				theirs: MigratedPartySequence(
					history: alice.auth.theirs.history,
					authorizedNext: alice.auth.theirs.authorizedNext,
					pinned: alice.auth.theirs.pinned)),
			sendGroup: MigratedGroupHalf(
				classical: try send.classical.archive(), pq: try send.pq?.archive()),
			currentStaple: alice.currentStaple,
			bootstrapKPSecret: try alice.bootstrapKPSecret.map {
				MigratedBootstrapKPSecret(
					leafSecretKey: $0.leafSecretKey.data,
					initSecretKey: $0.initSecretKey.data,
					keyPackage: try $0.keyPackage.mlsEncoded())
			},
			pqTurnMine: alice.pqTurnMine,
			pqInflight: alice.pqInflight.map {
				switch $0 {
				case .bootstrapInitiated: return .bootstrapInitiated
				case .bootstrapResponded: return .bootstrapResponded
				case .initiating(let eph):
					return .initiating(
						secretKey: eph.secretKey.data, ek: eph.ek)
				case .responding(let secret, let wireCT):
					return .responding(secret: secret, wireCT: wireCT)
				case .rekeyInitiated(let updMessage):
					return .rekeyInitiated(updMessage: updMessage)
				case .rekeyResponded: return .rekeyResponded
				}
			},
			pendingSideBand: alice.pendingSideBand,
			// No `initialTheirKP`: the seal target is absent.
			initialTheirKP: nil,
			leafKeys: migratedLeafKeys(from: alice.leafKeys),
			// A payload with nothing left to carry it — dead state.
			initialAppPayload: Data("host app payload".utf8))

		// `.core`, not `.checkpoint`: isolates the mint-site seal-target
		// guard this test targets from the checkpoint kind's trial restore,
		// which a bare `initiate()`-derived fixture fails for unrelated
		// reasons (it carries none of a live session's captured
		// routing/header-key state) — restore's OWN seal-target check is
		// the separate restore-half test, below.
		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .core, parts: migrated,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A hand-edited archive body carrying a payload but no `initialTheirKP`
	/// fails restore. Mirrors `LeafKeysTests`' mirrored-body pattern. Kills:
	/// dropping the new clause at the restore site.
	func testRestoreRejectsAPayloadWithNoSealTarget() throws {
		var (alice, _) = try setup()
		alice.initialAppPayload = Data("host app payload".utf8)

		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		var body = try sealAndOpen(archive).decode(SessionArchive.self)
		XCTAssertNotNil(body.initialAppPayload)
		XCTAssertNotNil(body.initialTheirKP)
		body.initialTheirKP = nil

		let edited = try sealAndOpen(try SecretArchive(encoding: body))
		XCTAssertThrowsError(
			try TwoMLSSession.restore(
				core: nil, checkpoint: edited,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - The payload slot and composer

	/// The setter's guards. Empty payload -> `.emptySection`. An
	/// acceptor (never a pre-join initiator) -> `.sessionNotReady`. A
	/// post-join initiator -> `.sessionNotReady`. Kills: removing any one
	/// guard.
	func testSetterGuards() throws {
		var (alice, invitation) = try setup()
		XCTAssertThrowsError(try alice.setInitialAppPayload(Data())) { error in
			XCTAssertEqual(error as? TwoMLSError, .emptySection)
		}

		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try EstablishmentMessages.encodeKeyPackage(
				alice.identity.keyPackage.classical))
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: alice.currentStaple, theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		var bob = received.session
		XCTAssertThrowsError(
			try bob.setInitialAppPayload(Data("host app payload".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncoming(bobFrame)
		XCTAssertTrue(alice.isEstablished)
		XCTAssertThrowsError(
			try alice.setInitialAppPayload(Data("host app payload".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
	}

	/// The setter's `initialTheirKP != nil` clause alone, isolated from
	/// every other guard (`initiated`, `recvGroup == nil`, the staple tag,
	/// all held true) — a state `receive()`'s always-established
	/// construction can never itself produce, so isolated here via direct
	/// field mutation. Kills: dropping the `initialTheirKP != nil` clause
	/// specifically (the acceptor/post-join scenarios above hold several
	/// guards false at once and can't isolate it).
	func testSetterGuardIsolatesMissingInitialTheirKP() throws {
		var (alice, _) = try setup()
		alice.initialTheirKP = nil
		XCTAssertThrowsError(
			try alice.setInitialAppPayload(Data("host app payload".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
	}

	/// The setter's `recvGroup == nil` clause alone, isolated the same way
	/// as the `initialTheirKP` isolation above.
	func testSetterGuardIsolatesRecvGroupPresent() throws {
		var (alice, invitation) = try setup()
		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try EstablishmentMessages.encodeKeyPackage(
				alice.identity.keyPackage.classical))
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: alice.currentStaple, theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		// Graft the ESTABLISHED acceptor's `recvGroup` onto Alice's own
		// still-pre-join fields (`initiated`/`initialTheirKP`/`currentStaple`
		// all stay hers) — an artificial state, but it isolates exactly the
		// `recvGroup == nil` clause.
		alice.recvGroup = received.session.recvGroup
		XCTAssertThrowsError(
			try alice.setInitialAppPayload(Data("host app payload".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
	}

	/// Once a payload is set, `pendingOutbound()`'s opened frame carries
	/// `appPayload` alone; `welcome`/`returnKeyPackage`/`stapledMessage` are
	/// all nil. Kills: emitting both shapes, or ignoring the payload.
	func testEitherOrPayloadShape() throws {
		var (alice, invitation) = try setup()
		let payload = Data("host app payload".utf8)
		_ = try alice.setInitialAppPayload(payload)

		let envelope = try alice.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		XCTAssertEqual(frame.appPayload, payload)
		XCTAssertNil(frame.welcome)
		XCTAssertNil(frame.returnKeyPackage)
		XCTAssertNil(frame.stapledMessage)
	}

	/// A second setter call replaces the payload, and the next envelope
	/// carries the REPLACEMENT. Kills: set-once behavior.
	func testSetterReplacesAnEarlierPayload() throws {
		var (alice, invitation) = try setup()
		_ = try alice.setInitialAppPayload(Data("first payload".utf8))
		let second = Data("second payload".utf8)
		_ = try alice.setInitialAppPayload(second)

		let envelope = try alice.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		XCTAssertEqual(frame.appPayload, second)
	}

	/// The setter's success advances `currentStapleSeq` to its own
	/// `stateSeq` — the durability watermark a pre-join `prepareToEncrypt`'s
	/// `PrepareResult.dependsOnSeq` mirrors. Kills: a missing
	/// `markStapleInstalled()` in the setter.
	func testSetterAdvancesTheDurabilityWatermark() throws {
		var (alice, _) = try setup()
		let before = alice.currentStapleSeq
		let update = try alice.setInitialAppPayload(Data("host app payload".utf8))
		XCTAssertGreaterThan(update.stateSeq, before)
		XCTAssertEqual(alice.currentStapleSeq, update.stateSeq)
	}

	/// The payload survives a pre-join restore (setter's `.core` update
	/// plus the baseline checkpoint), and the restored session's
	/// `pendingOutbound()` carries it. Kills: the archive dropping the
	/// payload field on the live encode.
	func testPayloadSurvivesPreJoinRestore() throws {
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
		var alice = initiated.session
		let payload = Data("host app payload".utf8)
		_ = try alice.setInitialAppPayload(payload)

		let checkpoint = try alice.makeSessionArchive(kind: .checkpoint)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: try sealAndOpen(checkpoint),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let envelope = try restored.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		XCTAssertEqual(frame.appPayload, payload)
	}

	// MARK: - Pre-join send

	/// The pre-join `prepareToEncrypt` — empty `proposalMessage`,
	/// `proposalHash == H(currentStaple)`, `didCommit == false`, and no
	/// `pendingProposal` set. `rotating:` non-nil -> `.sessionNotReady`.
	/// `noCustody ⊇ {.sendClassical}` -> `.leafCustodyUnavailable`. Kills:
	/// staging into a nil recv group, a wrong hash, a missing custody
	/// guard.
	func testPreJoinPrepareIsStatelessAndKeyedToTheStaple() throws {
		var (alice, _) = try setup()
		let result = try alice.prepareToEncrypt()
		XCTAssertEqual(result.proposalMessage, Data())
		XCTAssertEqual(
			result.proposalHash,
			try SessionTestSupport.classicalProvider.hash(alice.currentStaple))
		XCTAssertFalse(result.didCommit)
		XCTAssertNil(result.committedRemoteClientID)
		XCTAssertNil(alice.pendingProposal)

		XCTAssertThrowsError(
			try alice.prepareToEncrypt(rotating: Data("someone-else".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}

		alice.noCustody = [.sendClassical]
		XCTAssertThrowsError(try alice.prepareToEncrypt()) { error in
			XCTAssertEqual(error as? TwoMLSError, .leafCustodyUnavailable)
		}
	}

	/// The pre-join `encrypt` shape, in the BARE shape (no payload set).
	/// The envelope opens via `openInitial` with `stapledMessage.first ==
	/// 0x09`; the rest decodes as an MLSMessage `privateMessage` with
	/// `groupID == sendGroup.classical.context.groupID` and epoch 1.
	/// `isEstablishmentEnvelope == true`, and two encrypts give distinct
	/// envelope bytes. Kills: header-sealing instead of HPKE, a wrong tag,
	/// a missing staple, a reused ephemeral, the wrong group.
	func testPreJoinEncryptShape() throws {
		var (alice, invitation) = try setup()
		let sendGroupID = try XCTUnwrap(alice.sendGroup).classical.context.groupID

		_ = try alice.prepareToEncrypt()
		let first = try alice.encrypt(Data("hello, pre-join".utf8))
		XCTAssertTrue(first.isEstablishmentEnvelope)

		guard case .establishment(let frame) = try invitation.openInitial(first.frame)
		else {
			return XCTFail("expected .establishment")
		}
		let staple = try XCTUnwrap(frame.stapledMessage)
		XCTAssertEqual(staple.first, Frames.preEstablishmentAppTag)
		let appBytes = try Frames.decodePreEstablishmentApp(staple)
		guard case .privateMessage(let pm) = try MLS.RFC9420.Message(mlsEncoded: appBytes)
		else {
			return XCTFail("expected a privateMessage app section")
		}
		XCTAssertEqual(pm.groupID, sendGroupID)
		XCTAssertEqual(pm.epoch, 1)

		_ = try alice.prepareToEncrypt()
		let second = try alice.encrypt(Data("hello again, pre-join".utf8))
		XCTAssertNotEqual(first.frame, second.frame)
	}

	/// The pre-join `encrypt` shape once a payload is set: the opened
	/// envelope carries `appPayload == p` alone — `welcome` and
	/// `returnKeyPackage` are both nil — with the `0x09` staple still
	/// present alongside it. `encryptPreEstablishment` must build its
	/// envelope through the shared either/or composer rather than sealing
	/// the bare sections directly; a mutation that has it do the latter
	/// (bypassing `composeInitialEnvelope`) passes every OTHER native test
	/// in this file but fails this one.
	func testPreJoinEncryptCarriesThePayloadShapeOnceSet() throws {
		var (alice, invitation) = try setup()
		let payload = Data("host app payload".utf8)
		_ = try alice.setInitialAppPayload(payload)

		_ = try alice.prepareToEncrypt()
		let sent = try alice.encrypt(Data("hello, pre-join".utf8))
		guard case .establishment(let frame) = try invitation.openInitial(sent.frame) else {
			return XCTFail("expected .establishment")
		}
		XCTAssertEqual(frame.appPayload, payload)
		XCTAssertNil(frame.welcome)
		XCTAssertNil(frame.returnKeyPackage)
		XCTAssertNotNil(frame.stapledMessage)
	}

	/// `encrypt`'s OWN `noCustody` guard, isolated from
	/// `sendClassicalSigningKey()`'s own (key-absence-driven) check by
	/// leaving the send-classical key in place and setting only the
	/// `noCustody` flag — the artificial state the pre-join prepare test
	/// above can't isolate this from, since removing the guard there still
	/// leaves the key-lookup's independent check to fail closed. Kills:
	/// dropping `encryptPreEstablishment`'s own custody guard specifically.
	func testPreJoinEncryptGuardsNoCustodySeparatelyFromPrepare() throws {
		var (alice, _) = try setup()
		_ = try alice.prepareToEncrypt()
		alice.noCustody = [.sendClassical]
		XCTAssertThrowsError(try alice.encrypt(Data("blocked".utf8))) { error in
			XCTAssertEqual(error as? TwoMLSError, .leafCustodyUnavailable)
		}
	}

	/// Atomicity. A fault injected between `protect` and the
	/// write-back leaves `sendGroup` byte-identical to its pre-call
	/// snapshot (`GroupEntry` — includes the message-protection ratchet
	/// state, so ANY consumed generation would show up as a diff) — the
	/// next `encrypt` then protects at the same generation the peer
	/// expects, rather than skipping one the faulted attempt silently
	/// spent. Kills: writing `sendGroup` back before the compose.
	func testPreJoinEncryptWriteBackIsAtomic() throws {
		var (alice, _) = try setup()
		_ = try alice.prepareToEncrypt()

		let before = try XCTUnwrap(alice.sendGroup).makeGroupEntry(kind: .checkpoint)
		TwoMLSSessionTestHooks.armFault(
			"encryptPreEstablishment.afterProtectBeforeWriteBack")
		XCTAssertThrowsError(try alice.encrypt(Data("faulted".utf8))) { error in
			XCTAssertTrue(error is InjectedTestFault)
		}
		TwoMLSSessionTestHooks.disarmAllFaults()
		let after = try XCTUnwrap(alice.sendGroup).makeGroupEntry(kind: .checkpoint)
		XCTAssertEqual(before, after)

		// The session is not bricked: a retry (fault no longer armed)
		// completes normally.
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("recovered".utf8))
	}

	/// Cutover. A pre-join prepare followed by a join, followed by
	/// `encrypt`, throws `.noPendingProposal` (the stale prepare fails
	/// closed). Post-join prepare/encrypt then gives
	/// `isEstablishmentEnvelope == false`, and Bob's `processIncoming`
	/// yields a `0x03` frame. `pendingOutbound()` throws once joined. Kills:
	/// a branch predicate that isn't `recvGroup == nil`, and a stale
	/// pre-join prepare leaking across the join.
	func testCutoverAtTheJoin() throws {
		var (alice, invitation) = try setup()
		_ = try alice.prepareToEncrypt()

		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try EstablishmentMessages.encodeKeyPackage(
				alice.identity.keyPackage.classical))
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: alice.currentStaple, theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		var bob = received.session
		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncoming(bobFrame)
		XCTAssertTrue(alice.isEstablished)

		XCTAssertThrowsError(try alice.encrypt(Data("stale".utf8))) { error in
			XCTAssertEqual(error as? TwoMLSError, .noPendingProposal)
		}

		_ = try alice.prepareToEncrypt()
		let postJoin = try alice.encrypt(Data("post-join".utf8))
		XCTAssertFalse(postJoin.isEstablishmentEnvelope)
		let opened = try bob.processIncoming(postJoin.frame)
		guard case .decrypted(let decrypted) = opened else {
			return XCTFail("expected .decrypted")
		}
		XCTAssertEqual(decrypted.applicationMessage, Data("post-join".utf8))
		// `postJoin.frame` is header-sealed (PR2's "Sealed on exit"), unlike
		// a pre-join raw HPKE envelope — `openOrRaw` recovers the plain
		// `0x03` tag underneath.
		XCTAssertEqual(bob.openOrRaw(postJoin.frame).first, Frames.messageFrameTag)

		XCTAssertThrowsError(try alice.pendingOutbound()) { error in
			XCTAssertEqual(error as? TwoMLSError, .noPendingEstablishmentEnvelope)
		}
	}

	/// `canSend` is true pre-join, false with `sendClassical`
	/// no-custody, and true post-join. Kills: the widened predicate.
	func testCanSendPreJoinAndPostJoin() throws {
		var (alice, invitation) = try setup()
		XCTAssertTrue(alice.canSend)

		alice.noCustody = [.sendClassical]
		XCTAssertFalse(alice.canSend)
		alice.noCustody = []

		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try EstablishmentMessages.encodeKeyPackage(
				alice.identity.keyPackage.classical))
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: alice.currentStaple, theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		var bob = received.session
		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncoming(bobFrame)
		XCTAssertTrue(alice.canSend)
	}

	/// The parked §A.3 bootstrap KP is unaffected: `pqBootstrapEnvelope()`
	/// stays non-nil before and after two pre-join encrypts, and
	/// `pqInflight`/`pendingSideBand` are unchanged. Kills: a pre-join
	/// encrypt disturbing the parked `0x13`.
	func testPreJoinEncryptDoesNotDisturbTheParkedBootstrapKP() throws {
		var (alice, _) = try setup()
		XCTAssertNotNil(try alice.pqBootstrapEnvelope())
		guard case .bootstrapInitiated = alice.pqInflight else {
			return XCTFail("expected .bootstrapInitiated")
		}
		let pendingBefore = alice.pendingSideBand

		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("one".utf8))
		_ = try alice.prepareToEncrypt()
		_ = try alice.encrypt(Data("two".utf8))

		XCTAssertNotNil(alice.pqBootstrapEnvelope())
		guard case .bootstrapInitiated = alice.pqInflight else {
			return XCTFail("expected .bootstrapInitiated")
		}
		XCTAssertEqual(alice.pendingSideBand, pendingBefore)
	}

	// MARK: - The `0x09` Frames codec

	func testPreEstablishmentAppCodecRoundTrips() throws {
		let body = Data("an MLSMessage-framed PrivateMessage".utf8)
		let encoded = Frames.encodePreEstablishmentApp(body)
		XCTAssertEqual(encoded.first, Frames.preEstablishmentAppTag)
		let decoded = try Frames.decodePreEstablishmentApp(encoded)
		XCTAssertEqual(decoded, body)
	}

	func testPreEstablishmentAppCodecRejectsAnEmptyBody() throws {
		let encoded = Data([Frames.preEstablishmentAppTag])
		XCTAssertThrowsError(try Frames.decodePreEstablishmentApp(encoded)) { error in
			XCTAssertEqual(error as? TwoMLSError, .truncatedSection)
		}
	}

	func testPreEstablishmentAppCodecRejectsAWrongTag() throws {
		let encoded = Data([0x00]) + Data("body".utf8)
		XCTAssertThrowsError(try Frames.decodePreEstablishmentApp(encoded)) { error in
			XCTAssertEqual(error as? TwoMLSError, .unsupportedFrameTag(0x00))
		}
	}
}
