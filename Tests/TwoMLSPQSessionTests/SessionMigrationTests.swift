import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// GER-2433 slice B: the public parts-to-archive session minter. The minted
/// archive must be what `TwoMLSSession.restore` accepts and semantically
/// what `makeSessionArchive` would have produced — the cross-module migrator
/// calls this with raw parts read from a legacy Rust session, so it must
/// work without a live `TwoMLSSession` (the group halves arrive as
/// format-2 snapshot `SecretArchive`s, the value `Group.archive()` produces
/// and what a Rust exporter's bytes ingest via
/// `SecretArchive(decodingPlaintext:)`).
@available(iOS 26, macOS 26, *)
final class SessionMigrationTests: XCTestCase {
	/// Decomposes a live session into the exact raw parts a migrator would
	/// read off a legacy Rust session (same byte representations the native
	/// state holds). The kind is deliberately NOT part of the parts: the
	/// migrator supplies the same parts to either mint.
	private func migratedParts(_ session: TwoMLSSession) throws -> MigratedSession {
		let send = try XCTUnwrap(session.sendGroup)
		let sendClassicalSnapshot = try send.classical.archive()
		let sendPQSnapshot = try send.pq?.archive()
		return try MigratedSession(
			stateSeq: session.stateSeq,
			initiated: session.initiated,
			identity: MigratedSessionIdentity(
				clientID: session.identity.clientID,
				signingKey: session.identity.signingKey.data,
				signatureKey: session.identity.signatureKey.data,
				pqSigningKey: session.identity.pqSigningKey.data,
				pqSignatureKey: session.identity.pqSignatureKey.data,
				classicalLeafSecretKey: session.identity.classicalLeafSecretKey
					.data,
				classicalInitSecretKey: session.identity.classicalInitSecretKey?
					.data,
				pqLeafSecretKey: session.identity.pqLeafSecretKey.data,
				pqInitSecretKey: session.identity.pqInitSecretKey?.data,
				classicalKeyPackage: try session.identity.keyPackage.classical
					.mlsEncoded(),
				pqKeyPackage: try session.identity.keyPackage.pq.mlsEncoded()),
			auth: MigratedAuth(
				mine: MigratedPartySequence(
					history: session.auth.mine.history,
					authorizedNext: session.auth.mine.authorizedNext,
					pinned: session.auth.mine.pinned),
				theirs: MigratedPartySequence(
					history: session.auth.theirs.history,
					authorizedNext: session.auth.theirs.authorizedNext,
					pinned: session.auth.theirs.pinned)),
			sendGroup: MigratedGroupHalf(
				classical: sendClassicalSnapshot,
				pq: sendPQSnapshot),
			recvGroup: try session.recvGroup.map {
				MigratedGroupHalf(
					classical: try $0.classical.archive(),
					pq: try $0.pq?.archive())
			},
			currentStaple: session.currentStaple,
			pendingProposal: session.pendingProposal.map {
				MigratedProposal(
					proposing: $0.proposing, message: $0.message, hash: $0.hash)
			},
			joinedWelcomeDigest: session.joinedWelcomeDigest,
			bootstrapKPSecret: try session.bootstrapKPSecret.map {
				MigratedBootstrapKPSecret(
					leafSecretKey: $0.leafSecretKey.data,
					initSecretKey: $0.initSecretKey.data,
					keyPackage: try $0.keyPackage.mlsEncoded())
			},
			expectedBootstrapKPCommitment: session.expectedBootstrapKPCommitment,
			pqTurnMine: session.pqTurnMine,
			owedBind: session.owedBind.map {
				MigratedOwedBind(
					pqCommitMessage: $0.pqCommitMessage, tEpoch: $0.tEpoch,
					pqEpoch: $0.pqEpoch)
			},
			pqInflight: session.pqInflight.map {
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
			pendingSideBand: session.pendingSideBand,
			peerAppliedSendEpoch: session.peerAppliedSendEpoch,
			lastCrossInjected: session.lastCrossInjected,
			lastCrossInjectedPQ: session.lastCrossInjectedPQ,
			lastSendPQExported: session.lastSendPQExported,
			offeredProposal: session.offeredProposal.map {
				MigratedDigestedProposal(
					digest: $0.digest, proposing: $0.proposing,
					message: $0.message)
			},
			queuedProposal: session.queuedProposal.map {
				MigratedDigestedProposal(
					digest: $0.digest, proposing: $0.proposing,
					message: $0.message)
			},
			stagedUpdates: session.stagedUpdates.map {
				MigratedStagedUpdate(digest: $0.digest, message: $0.message)
			},
			sendCrossPSKLedger: session.sendCrossPSKLedger.mapValues {
				MigratedExportedPsk(
					componentID: $0.componentID.rawValue, pskID: $0.pskID,
					psk: $0.psk)
			},
			rotationCandidate: session.rotationCandidate.map {
				MigratedRotationCandidate(
					clientID: $0.clientID, signingKey: $0.signingKey.data,
					signatureKey: $0.signatureKey.data,
					proposedAtRecvEpoch: $0.proposedAtRecvEpoch)
			},
			spawnToken: session.spawnToken,
			listenRendezvous: session.listenRendezvous,
			recvHeaderKeys: session.recvHeaderKeys,
			recvHeaderKeysPQ: session.recvHeaderKeysPQ,
			sendAttachmentLedger: session.sendAttachmentLedger,
			recvAttachmentLedger: session.recvAttachmentLedger,
			initialTheirKP: try session.initialTheirKP.map {
				(
					classical: try $0.classical.mlsEncoded(),
					pq: try $0.pq.mlsEncoded()
				)
			},
			recvLeafPrincipal: session.recvLeafPrincipal.map {
				MigratedRecvLeafPrincipal(
					clientID: $0.clientID, signingKey: $0.signingKey.data,
					signatureKey: $0.signatureKey.data,
					pqSigningKey: $0.pqSigningKey.data,
					pqSignatureKey: $0.pqSignatureKey.data)
			},
			owesEstablishmentEnvelope: session.owesEstablishmentEnvelope)
	}

	/// A fully-established session pair — post-A.3 bootstrap plus one
	/// complete PQ round (`RatchetTests`' own flow), landing at PQ epoch 2,
	/// quiescent (no inflight/owed state), ledgers and windows populated.
	private func fullyEstablishedPair() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession
	) {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		// The full A.4 round (mirrors
		// RatchetTests.testBobInitiatedRatchetRoundAdvancesGroupBPQAndReturnsTurn):
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		_ = try bob.pqRatchetBind(ctFrame)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8)).frame
		_ = try alice.processIncomingDecrypted(boundFrame)

		XCTAssertTrue(alice.myPQTurn)
		return (alice: alice, bob: bob)
	}

	/// The strongest expressible equivalence check (SecretArchive exposes no
	/// plaintext byte accessor and `seal` randomizes its nonce): every
	/// `SessionArchive` field compares equal between the minted and the
	/// native body — the group entries and `auth` via their `Equatable`
	/// conformances, the rest field by field.
	private func assertMintedMatchesNative(
		_ minted: SecretArchive, _ native: SecretArchive, kind: BlobKind
	) throws {
		let mintedBody = try minted.decode(SessionArchive.self)
		let nativeBody = try native.decode(SessionArchive.self)

		XCTAssertEqual(mintedBody.version, nativeBody.version)
		XCTAssertEqual(mintedBody.classicalSuite, nativeBody.classicalSuite)
		XCTAssertEqual(mintedBody.pqSuite, nativeBody.pqSuite)
		XCTAssertEqual(mintedBody.kind, nativeBody.kind)
		XCTAssertEqual(mintedBody.kind, kind)
		XCTAssertEqual(mintedBody.stateSeq, nativeBody.stateSeq)
		XCTAssertEqual(mintedBody.sendPQEpoch, nativeBody.sendPQEpoch)
		XCTAssertEqual(mintedBody.recvPQEpoch, nativeBody.recvPQEpoch)
		XCTAssertEqual(
			mintedBody.sendClassicalGroupID, nativeBody.sendClassicalGroupID)
		XCTAssertEqual(
			mintedBody.recvClassicalGroupID, nativeBody.recvClassicalGroupID)

		let mintedIdentity = mintedBody.identity
		let nativeIdentity = nativeBody.identity
		XCTAssertEqual(mintedIdentity.clientID, nativeIdentity.clientID)
		XCTAssertEqual(mintedIdentity.signingKey, nativeIdentity.signingKey)
		XCTAssertEqual(mintedIdentity.signatureKey, nativeIdentity.signatureKey)
		XCTAssertEqual(mintedIdentity.pqSigningKey, nativeIdentity.pqSigningKey)
		XCTAssertEqual(
			mintedIdentity.pqSignatureKey, nativeIdentity.pqSignatureKey)
		XCTAssertEqual(
			mintedIdentity.classicalLeafSecretKey,
			nativeIdentity.classicalLeafSecretKey)
		XCTAssertEqual(
			mintedIdentity.classicalInitSecretKey,
			nativeIdentity.classicalInitSecretKey)
		XCTAssertEqual(mintedIdentity.pqLeafSecretKey, nativeIdentity.pqLeafSecretKey)
		XCTAssertEqual(mintedIdentity.pqInitSecretKey, nativeIdentity.pqInitSecretKey)
		XCTAssertEqual(
			mintedIdentity.classicalKeyPackage, nativeIdentity.classicalKeyPackage)
		XCTAssertEqual(mintedIdentity.pqKeyPackage, nativeIdentity.pqKeyPackage)

		XCTAssertEqual(mintedBody.auth, nativeBody.auth)
		XCTAssertEqual(mintedBody.sendGroup, nativeBody.sendGroup)
		XCTAssertEqual(mintedBody.recvGroup, nativeBody.recvGroup)

		XCTAssertEqual(mintedBody.currentStaple, nativeBody.currentStaple)
		XCTAssertEqual(mintedBody.pendingProposal, nativeBody.pendingProposal)
		XCTAssertEqual(
			mintedBody.joinedWelcomeDigest, nativeBody.joinedWelcomeDigest)
		XCTAssertEqual(mintedBody.initiated, nativeBody.initiated)
		XCTAssertEqual(
			mintedBody.bootstrapKPSecret?.leafSecretKey,
			nativeBody.bootstrapKPSecret?.leafSecretKey)
		XCTAssertEqual(
			mintedBody.bootstrapKPSecret?.initSecretKey,
			nativeBody.bootstrapKPSecret?.initSecretKey)
		XCTAssertEqual(
			mintedBody.bootstrapKPSecret?.keyPackage,
			nativeBody.bootstrapKPSecret?.keyPackage)
		XCTAssertEqual(
			mintedBody.expectedBootstrapKPCommitment,
			nativeBody.expectedBootstrapKPCommitment)
		XCTAssertEqual(mintedBody.pqTurnMine, nativeBody.pqTurnMine)
		XCTAssertEqual(
			mintedBody.owedBind?.pqCommitMessage, nativeBody.owedBind?.pqCommitMessage)
		XCTAssertEqual(mintedBody.owedBind?.tEpoch, nativeBody.owedBind?.tEpoch)
		XCTAssertEqual(mintedBody.owedBind?.pqEpoch, nativeBody.owedBind?.pqEpoch)
		XCTAssertEqual(mintedBody.pqInflight, nativeBody.pqInflight)
		XCTAssertEqual(mintedBody.pendingSideBand, nativeBody.pendingSideBand)
		XCTAssertEqual(
			mintedBody.peerAppliedSendEpoch, nativeBody.peerAppliedSendEpoch)
		XCTAssertEqual(
			mintedBody.lastCrossInjected, nativeBody.lastCrossInjected)
		XCTAssertEqual(
			mintedBody.lastCrossInjectedPQ, nativeBody.lastCrossInjectedPQ)
		XCTAssertEqual(
			mintedBody.lastSendPQExported, nativeBody.lastSendPQExported)
		XCTAssertEqual(mintedBody.offeredProposal, nativeBody.offeredProposal)
		XCTAssertEqual(mintedBody.queuedProposal, nativeBody.queuedProposal)
		XCTAssertEqual(mintedBody.stagedUpdates, nativeBody.stagedUpdates)
		XCTAssertEqual(
			mintedBody.sendCrossPSKLedger.entries.count,
			nativeBody.sendCrossPSKLedger.entries.count)
		for (epoch, mintedPsk) in mintedBody.sendCrossPSKLedger.entries {
			let nativePsk = try XCTUnwrap(
				nativeBody.sendCrossPSKLedger.entries[epoch])
			XCTAssertEqual(mintedPsk.componentID, nativePsk.componentID)
			XCTAssertEqual(mintedPsk.pskID, nativePsk.pskID)
			XCTAssertEqual(mintedPsk.psk, nativePsk.psk)
		}
		XCTAssertEqual(
			mintedBody.rotationCandidate?.clientID,
			nativeBody.rotationCandidate?.clientID)
		XCTAssertEqual(
			mintedBody.rotationCandidate?.signingKey,
			nativeBody.rotationCandidate?.signingKey)
		XCTAssertEqual(
			mintedBody.rotationCandidate?.signatureKey,
			nativeBody.rotationCandidate?.signatureKey)
		XCTAssertEqual(
			mintedBody.rotationCandidate?.proposedAtRecvEpoch,
			nativeBody.rotationCandidate?.proposedAtRecvEpoch)
		XCTAssertEqual(mintedBody.spawnToken, nativeBody.spawnToken)
		XCTAssertEqual(
			mintedBody.listenRendezvous?.entries, nativeBody.listenRendezvous?.entries)
		XCTAssertEqual(
			mintedBody.recvHeaderKeys?.entries, nativeBody.recvHeaderKeys?.entries)
		XCTAssertEqual(
			mintedBody.recvHeaderKeysPQ?.entries,
			nativeBody.recvHeaderKeysPQ?.entries)
		XCTAssertEqual(
			mintedBody.initialTheirKP?.classical, nativeBody.initialTheirKP?.classical)
		XCTAssertEqual(mintedBody.initialTheirKP?.pq, nativeBody.initialTheirKP?.pq)
		XCTAssertEqual(
			mintedBody.sendAttachmentLedger?.entries.mapValues { $0.wrappedValue },
			nativeBody.sendAttachmentLedger?.entries.mapValues { $0.wrappedValue })
		XCTAssertEqual(
			mintedBody.recvAttachmentLedger?.entries.mapValues { $0.wrappedValue },
			nativeBody.recvAttachmentLedger?.entries.mapValues { $0.wrappedValue })
		XCTAssertEqual(
			mintedBody.owesEstablishmentEnvelope,
			nativeBody.owesEstablishmentEnvelope)
		XCTAssertEqual(
			mintedBody.recvLeafPrincipal?.clientID,
			nativeBody.recvLeafPrincipal?.clientID)
		XCTAssertEqual(
			mintedBody.recvLeafPrincipal?.signingKey,
			nativeBody.recvLeafPrincipal?.signingKey)
		XCTAssertEqual(
			mintedBody.recvLeafPrincipal?.signatureKey,
			nativeBody.recvLeafPrincipal?.signatureKey)
		XCTAssertEqual(
			mintedBody.recvLeafPrincipal?.pqSigningKey,
			nativeBody.recvLeafPrincipal?.pqSigningKey)
		XCTAssertEqual(
			mintedBody.recvLeafPrincipal?.pqSignatureKey,
			nativeBody.recvLeafPrincipal?.pqSignatureKey)
	}

	// MARK: - AC 1: equivalence with the native path

	func testMintedCheckpointDecodesToTheNativeBody() throws {
		let (alice, _) = try fullyEstablishedPair()
		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)
	}

	func testMintedCoreDecodesToTheNativeBody() throws {
		let (alice, _) = try fullyEstablishedPair()
		let native = try alice.makeSessionArchive(kind: .core)
		let minted = try SessionMigration.mintArchive(
			kind: .core, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .core)
	}

	/// A mid-A.4 `.responding` mint: the held `S`/parked CT map, the body
	/// matches the native one, and the restored session completes the round.
	func testMintedMidFlightResponderRoundTripsAndCompletesRound() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		guard case .responding = alice.pqInflight else {
			return XCTFail("expected alice to hold `.responding` after sealing")
		}

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)

		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		_ = try bob.pqRatchetBind(ctFrame)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8)).frame
		let decrypted = try restored.processIncomingDecrypted(boundFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
	}

	// MARK: - AC 2: restore + use

	func testMintedCheckpointRestoresAndKeepsMessaging() throws {
		var (alice, bob) = try fullyEstablishedPair()
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertTrue(restored.isFullyEstablished)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("hello".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("hello".utf8))

		_ = try bob.prepareToEncrypt()
		let reply = try bob.encrypt(Data("hi".utf8)).frame
		let replyDecrypted = try restored.processIncomingDecrypted(reply)
		XCTAssertEqual(replyDecrypted.applicationMessage, Data("hi".utf8))
	}

	/// The responder-side mint: `initiated == false` flips restore's
	/// standard/deferred interpretation of the two halves (Bob's sendGroup is
	/// the classical-only Group_B, his recvGroup the full Group_A).
	func testMintedResponderCheckpointRestoresAndKeepsMessaging() throws {
		var (alice, bob) = try fullyEstablishedPair()
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(bob),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertTrue(restored.isFullyEstablished)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("from-restored-bob".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("from-restored-bob".utf8))
	}

	// MARK: - AC 4: spent/edge — pre-establishment initiator

	/// A pre-establishment initiator (`recvGroup == nil`) mints with its
	/// classical init secret carried, restores, and COMPLETES establishment —
	/// the full PR3c flow a migrated mid-establishment session needs.
	func testMintedPreEstablishmentInitiatorCompletesEstablishment() throws {
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

		let parts = try migratedParts(initiated.session)
		XCTAssertNotNil(parts.identity.classicalInitSecretKey)
		XCTAssertNil(parts.identity.pqInitSecretKey)
		let native = try initiated.session.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		// The pre-establishment state is the only fixture where
		// `bootstrapKPSecret`/`initialTheirKP`/the init secret are non-nil —
		// compare it against the native body too (the fully-established
		// fixtures leave those nil, so an offered↔queued or digest↔proposing
		// swap there would go unseen).
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertFalse(restored.isEstablished)

		let envelope = try restored.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope)
		else {
			return XCTFail("expected .establishment")
		}
		let returnKP = try MLS.RFC9420.KeyPackage(
			mlsEncoded: try XCTUnwrap(frame.returnKeyPackage))
		let received = try invitation.receive(
			welcome: try XCTUnwrap(frame.welcome),
			theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try restored.bootstrapKPCommitment(),
			spawnToken: SessionTestSupport.classicalProvider.randomBytes(16))
		var bob = received.session
		XCTAssertTrue(bob.isEstablished)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try restored.processIncomingDecrypted(bobFrame)
		XCTAssertTrue(restored.isEstablished)
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-hello".utf8))
	}

	// MARK: - Windows: safe-to-empty vs must-carry

	/// The three re-derivable windows may mint EMPTY — restore re-captures
	/// the current epoch's entries at once (only the retained past-epoch
	/// entries are lost, the documented scope choice).
	func testEmptyDerivableWindowsMintAndRestore() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice)
		parts.listenRendezvous = [:]
		parts.recvHeaderKeys = [:]
		parts.recvHeaderKeysPQ = [:]
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(restored.listenRendezvous.count, 1)
		XCTAssertEqual(restored.recvHeaderKeys.count, 1)
		XCTAssertEqual(restored.recvHeaderKeysPQ.count, 1)
	}

	/// The attachment ledgers are NOT safe to empty: the live path consumes
	/// the current epoch's `0xFF03` exporter leaf at group creation, so
	/// restore's re-capture of a ledger missing that epoch throws — the mint
	/// (whose trial restore runs the same capture) must reject it loudly.
	func testEmptyAttachmentLedgerIsRejectedAtMint() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice)
		parts.sendAttachmentLedger = [:]

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - AC 3: mutation-verify

	func testCorruptedClassicalSigningKeyIsRejectedAtMint() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice)
		parts.identity.signingKey = SecretBytes(randomByteCount: 32)

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A VALID but different ML-KEM leaf secret — one that passes the 96-B
	/// integrity check — is rejected by the derived-public vs KeyPackage
	/// comparison, which is the check that actually catches a mis-mapped key.
	func testValidButWrongPqLeafSecretIsRejectedAtMint() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice)
		let (wrongSecret, _) = try SessionTestSupport.pqProvider.hpkeGenerateKeyPair()
		parts.identity.pqLeafSecretKey = wrongSecret.data

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// Swapping the classical leaf and init secrets (two VALID X25519 keys)
	/// is rejected — the half-swap mis-mapping this minter exists to catch.
	/// Needs the pre-establishment fixture (the only state where an init
	/// secret is supplied at all).
	func testSwappedClassicalLeafAndInitSecretsAreRejectedAtMint() throws {
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal,
			their: try XCTUnwrap(invitation.combinerKeyPackage))
		var parts = try migratedParts(initiated.session)
		let leaf = parts.identity.classicalLeafSecretKey
		parts.identity.classicalLeafSecretKey =
			try XCTUnwrap(parts.identity.classicalInitSecretKey)
		parts.identity.classicalInitSecretKey = leaf

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// An init secret supplied for an ESTABLISHED session — the native path
	/// can never produce one (`includeInitSecrets: recvGroup == nil`) — is
	/// rejected at mint.
	func testInitSecretSuppliedForEstablishedSessionIsRejected() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice)
		parts.identity.classicalInitSecretKey = SecretBytes(randomByteCount: 32)

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A PQ init secret is rejected even for a pre-establishment initiator —
	/// the native path clears it at `initiate` before any archive can exist.
	/// The gate fires BEFORE the identity cross-checks (which a correctly
	/// mapped legacy PQ init secret would otherwise pass), so the rejection
	/// is the gate's regardless of the supplied value's validity — hence a
	/// freshly generated key suffices here.
	func testPqInitSecretIsAlwaysRejected() throws {
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal,
			their: try XCTUnwrap(invitation.combinerKeyPackage))
		var parts = try migratedParts(initiated.session)
		let (pqInitSecret, _) = try SessionTestSupport.pqProvider.hpkeGenerateKeyPair()
		parts.identity.pqInitSecretKey = pqInitSecret.data

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A topology violation — no recv group with `initiated == false` — is
	/// rejected at mint (no native path produces it: the responder's
	/// `receive` always sets its recv group). NOTE the mirror mis-mapping —
	/// swapping the two halves' snapshots on an ESTABLISHED session — is
	/// deliberately NOT tested as a rejection: both topologies are internally
	/// self-consistent (the pair-identity checks are per-pair, custody is
	/// symmetric), so no mint-time signal distinguishes them. The migrator's
	/// own send/recv mapping discipline is what prevents that one.
	func testResponderTopologyWithoutRecvGroupIsRejected() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice)
		parts.initiated = false
		parts.recvGroup = nil

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// The standard (full-combiner) pair's PQ snapshot is mandatory —
	/// `restoreStandardPair` fail-closes on its absence.
	func testStandardHalfWithoutPQSnapshotIsRejected() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice)
		parts.sendGroup.pq = nil

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A provider that doesn't back its suite is `.cipherSuiteMismatch`
	/// (the `TwoMLSIdentity.generate` precedent), not a profile-internal
	/// snapshot error.
	func testWrongSuiteProviderIsRejected() throws {
		let (alice, _) = try fullyEstablishedPair()
		let wrongProvider = SwiftCryptoProvider().cipherSuiteProvider(for: .p256Aes128)!

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: try migratedParts(alice),
				classicalProvider: wrongProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .cipherSuiteMismatch)
		}
	}

	// MARK: - Reconcile: a minted Core + Checkpoint pair restores as one

	/// Both kinds mint from ONE parts set (the migrator's actual usage) and
	/// the pair reconciles: the newer Core wins the stateSeq comparison and
	/// splices the Checkpoint's PQ halves in — the minted core's only
	/// consumer path, since a Core alone is never restorable.
	func testMintedCoreAndCheckpointPairReconcilesAndMessages() throws {
		var (alice, bob) = try fullyEstablishedPair()
		let parts = try migratedParts(alice)

		var checkpointParts = parts
		checkpointParts.stateSeq = 5
		let checkpoint = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: checkpointParts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var coreParts = parts
		coreParts.stateSeq = 6
		let core = try SessionMigration.mintArchive(
			kind: .core, parts: coreParts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		var restored = try TwoMLSSession.restore(
			core: core, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertTrue(restored.isFullyEstablished)
		XCTAssertEqual(restored.stateSeq, 6)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("paired".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("paired".utf8))
	}

	// MARK: - Custody arms: born-dedicated recvLeafPrincipal

	/// The born-dedicated acceptor (`SessionTestSupport.establishedDedicated`):
	/// Bob's session identity is the dedicated principal D while his
	/// Group_A leaves still present the INVITATION identity — custody
	/// resolves through `recvLeafPrincipal`, so the parts must carry it, and
	/// the minted archive must restore with that custody intact. No messaging
	/// leg here: Bob cannot send until the contract-26 handoff envelope is
	/// installed and approved, and Alice isn't established until his first
	/// frame — that full flow is BornDedicatedTests' territory; the custody
	/// arms (and their negative, next test) are what this file must prove.
	func testMintedBornDedicatedAcceptorRestoresWithCustodyIntact() throws {
		let established = try SessionTestSupport.establishedDedicated(bob: "bob-d")
		let bob = established.bob
		XCTAssertTrue(bob.owesEstablishmentEnvelope)
		XCTAssertNotNil(bob.recvLeafPrincipal)
		XCTAssertNotEqual(bob.identity.clientID, bob.recvLeafPrincipal?.clientID)

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(bob),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(
			restored.recvLeafPrincipal?.clientID,
			bob.recvLeafPrincipal?.clientID)
		XCTAssertEqual(
			restored.recvLeafPrincipal?.signatureKey,
			bob.recvLeafPrincipal?.signatureKey)
		XCTAssertEqual(
			restored.recvLeafPrincipal?.pqSignatureKey,
			bob.recvLeafPrincipal?.pqSignatureKey)
		XCTAssertEqual(restored.identity.clientID, bob.identity.clientID)
		XCTAssertTrue(restored.owesEstablishmentEnvelope)
	}

	/// The negative arm: dropping `recvLeafPrincipal` from a born-dedicated
	/// acceptor's parts leaves the invitation-keyed leaves unresolvable —
	/// the custody check (not the trial restore) must catch it at mint.
	func testBornDedicatedPartsMissingRecvLeafPrincipalIsRejected() throws {
		let established = try SessionTestSupport.establishedDedicated(bob: "bob-d")
		var parts = try migratedParts(established.bob)
		parts.recvLeafPrincipal = nil

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}
}
