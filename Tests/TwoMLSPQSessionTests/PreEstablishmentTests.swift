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
}
