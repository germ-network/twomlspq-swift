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
		// The temporary conversion must land on exactly the same four
		// stored key sets (current + pending, by target) as the live path's
		// own seeding/staging — this is the direct parity check for "the
		// conversion crosses halves or ignores staged/parked proposals."
		XCTAssertEqual(mintedBody.leafKeys, nativeBody.leafKeys)
		XCTAssertEqual(
			mintedBody.sendPQKeysFingerprint, nativeBody.sendPQKeysFingerprint)
		XCTAssertEqual(
			mintedBody.recvPQKeysFingerprint, nativeBody.recvPQKeysFingerprint)
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

	/// The deployed Rust engine pins only the A.3 founding ids (book
	/// group-rules.md rule 4's own example, not its full rule) — a strict
	/// subset of what the live engine's normal form actually needs. Rust-
	/// shaped parts here supply an unrelated, stale legacy pin; the mint
	/// must ignore it and derive the minted archive's pins itself, from
	/// what the RESTORED PQ trees actually present. Mutation: copying
	/// `parts.auth.mine.pinned`/`parts.auth.theirs.pinned` straight through
	/// (instead of deriving via `livePQPresentedIDs`/`AuthCore.withPQPins`)
	/// makes this fail.
	func testMintDerivesPinsFromRestoredPQTreesAndDropsAStaleLegacyPin() throws {
		let (alice, _) = try fullyEstablishedPair()
		let aliceID = alice.identity.clientID
		var parts = try migratedParts(alice)
		parts.auth.mine.pinned = [Data("legacy-rust-founding-pin-only".utf8)]
		parts.auth.theirs.pinned = [Data("legacy-rust-founding-pin-only".utf8)]

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let mintedBody = try minted.decode(SessionArchive.self)

		XCTAssertEqual(mintedBody.auth.mine.pinned, [aliceID])
		XCTAssertFalse(
			mintedBody.auth.mine.pinned.contains(
				Data("legacy-rust-founding-pin-only".utf8)))

		// The minted archive must still restore and keep messaging — proves
		// the derived pins are themselves well-formed, not merely present.
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		_ = try restored.prepareToEncrypt()
		_ = try restored.encrypt(Data("post-mint".utf8))
	}

	/// A mid-rotation session — an outstanding `rotationCandidate` plus its
	/// still-staged classical Upd(self) in `stagedUpdates` — must convert
	/// to matching `recvClassical`/`sendClassical` `pending` entries, not
	/// silently drop them: the direct parity check for "the conversion...
	/// ignores staged/parked proposals" (the classical half; PQ has no
	/// resolvable-but-new-key migrated scenario here).
	func testMintedMidRotationConvertsStagedUpdateAndLeafKeysMatch() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		let newID = Data("alice-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		XCTAssertNotNil(alice.rotationCandidate)
		XCTAssertFalse(alice.stagedUpdates.isEmpty)

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)

		let mintedBody = try minted.decode(SessionArchive.self)
		XCTAssertFalse(
			mintedBody.leafKeys.recvClassical.pending.isEmpty,
			"the staged rotating Upd(self) must convert into recvClassical.pending")
		XCTAssertFalse(
			mintedBody.leafKeys.sendClassical.pending.isEmpty,
			"the outstanding candidate must convert into sendClassical.pending")
	}

	/// Isolates conversion item (c) — the staged-proposal scan — from item
	/// (a) — the outstanding-candidate check — which would otherwise cover
	/// for it: the parts here rename `rotationCandidate.clientID` from C to
	/// a DISTINCT C′, keeping C's own key material, while the staged Upd
	/// (encoded earlier, under C) still names C. Item (a) can only ever
	/// produce `pending[C′]` now (the candidate's OWN reported id); only
	/// item (c), decoding the staged Upd itself, can produce `pending[C]`.
	/// Both must be present, with the SAME key. A build that comments out
	/// item (c) entirely makes `pending[C]` vanish while `pending[C′]`
	/// still exists — this is the test that catches it.
	func testMintedConversionItemCPopulatesTheStagedTargetIndependentlyOfItemA() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		let c = Data("alice-c".utf8)
		_ = try alice.prepareToEncrypt(rotating: c)
		let candidate = try XCTUnwrap(alice.rotationCandidate)
		XCTAssertFalse(alice.stagedUpdates.isEmpty)

		var parts = try migratedParts(alice)
		let cPrime = Data("alice-c-prime".utf8)
		parts.rotationCandidate?.clientID = cPrime

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let mintedBody = try minted.decode(SessionArchive.self)

		let fromItemC = try XCTUnwrap(
			mintedBody.leafKeys.recvClassical.pending.first { $0.target == c })
		let fromItemA = try XCTUnwrap(
			mintedBody.leafKeys.recvClassical.pending.first { $0.target == cPrime })
		XCTAssertEqual(fromItemC.key.signatureKey, candidate.signatureKey.data)
		XCTAssertEqual(fromItemA.key.signatureKey, candidate.signatureKey.data)
	}

	/// The miss path: with NO outstanding candidate at all (and no
	/// `recvLeafPrincipal`), the staged Upd(C) that item (c) would
	/// otherwise convert can no longer resolve under any of
	/// `lookupClassical`'s three arms — mint must fail closed rather than
	/// silently drop the entry.
	func testMintedConversionRejectsAStagedUpdateWithNoCandidateToResolveIt() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		let c = Data("alice-c".utf8)
		_ = try alice.prepareToEncrypt(rotating: c)
		XCTAssertFalse(alice.stagedUpdates.isEmpty)

		var parts = try migratedParts(alice)
		parts.rotationCandidate = nil

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
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

	// MARK: - Mint parity across more of the rotation/A.3 lifecycle

	/// Mint parity right after the peer folds a rotation offer: recv-
	/// classical has converged (the candidate's key is now `current`), but
	/// send-classical still lags (the outstanding candidate's key is still
	/// only `pending`) — a DIFFERENT point in the lifecycle from the
	/// mid-rotation (staged-but-unfolded) test above.
	func testMintedRotationFoldedMatchesNative() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let newID = Data("alice-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		let foldDecrypted = try alice.processIncomingDecrypted(foldFrame)
		XCTAssertTrue(foldDecrypted.ownCredentialCanonicalized)

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)
	}

	/// Mint parity once the rotation has FULLY converged — both leaves
	/// present the new id, and the outstanding candidate's `pending`
	/// entries are gone (promoted to `current` on both classical sets).
	func testMintedRotationConvergedMatchesNative() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let newID = Data("alice-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
		let catchUpDecrypted = try bob.processIncomingDecrypted(catchUpFrame)
		XCTAssertEqual(catchUpDecrypted.newSender, newID)
		XCTAssertEqual(alice.myPrincipalState, .sync(newID))

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)

		let mintedBody = try minted.decode(SessionArchive.self)
		XCTAssertTrue(
			mintedBody.leafKeys.sendClassical.pending.isEmpty,
			"a converged rotation leaves no outstanding send-classical pending entry")
	}

	/// Mint parity for the pre-A.3 initiator: fully established classically
	/// — Group_A (`sendGroup`, the initiator's own founding pair) already
	/// carries its PQ half, but Group_B (`recvGroup`, classical-only until
	/// the §A.3 bootstrap) does not yet — `recvPQ` converts to its
	/// identity-keyed reservation.
	func testMintedPreA3InitiatorMatchesNative() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertNotNil(alice.sendGroup?.pq)
		XCTAssertNil(alice.recvGroup?.pq)

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertNil(restored.recvGroup?.pq)
	}

	/// The mirror image on the acceptor: bob's `recvGroup` (Group_A) already
	/// carries PQ (founded at invitation-accept time), but his `sendGroup`
	/// (Group_B) is still classical-only pre-A.3 — `sendPQ` converts to its
	/// identity-keyed reservation instead of `recvPQ`.
	func testMintedPreA3AcceptorMatchesNative() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertNotNil(bob.recvGroup?.pq)
		XCTAssertNil(bob.sendGroup?.pq)

		let native = try bob.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(bob),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertNil(restored.sendGroup?.pq)
	}

	/// Mint parity for the A.3-stalled initiator: the founder has sent its
	/// KP′ and is waiting on the peer's Welcome′ — `bootstrapKPSecret`
	/// held, `pqInflight == .bootstrapInitiated`, `recvGroup.pq` still nil.
	func testMintedA3StalledInitiatorMatchesNative() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		_ = try alice.pqBootstrapBegin()
		XCTAssertNotNil(alice.bootstrapKPSecret)
		guard case .bootstrapInitiated = alice.pqInflight else {
			return XCTFail(
				"expected alice to hold .bootstrapInitiated after pqBootstrapBegin")
		}
		XCTAssertNil(alice.recvGroup?.pq)

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)
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

	/// Book `wire-format.md`: every occupied leaf of the restored trees —
	/// and either half of a retained `initialTheirKP` — must advertise the
	/// `APQInfo` extension and the `AppDataUpdate` proposal, or mint
	/// refuses with `.archiveInvalid`.
	private func rogueKeyPackage(
		named name: String, capabilities: MLS.RFC9420.Capabilities
	) throws -> MLS.RFC9420.KeyPackage {
		let provider = SessionTestSupport.classicalProvider
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (_, leafPublicKey) = try provider.hpkeGenerateKeyPair()
		let (_, initPublicKey) = try provider.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublicKey, signatureKey: signatureKey,
			credential: .basic(identity: Data(name.utf8)), capabilities: capabilities,
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)), extensions: [],
			signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: provider.cipherSuite, initKey: initPublicKey,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return keyPackage
	}

	private static let rogueCapabilities = MLS.RFC9420.Capabilities(
		versions: [.mls10], cipherSuites: [TwoMLSSuite.classical, TwoMLSSuite.pq],
		extensions: [], proposals: [], credentials: [MLS.RFC9420.CredentialType(.basic)])

	/// Each half checked independently: a rogue CLASSICAL half with a
	/// well-capable PQ one still throws, and vice versa.
	func testCapabilityLessInitialTheirKPIsRejectedAtMint() throws {
		let (alice, _) = try fullyEstablishedPair()
		let wellCapableKP = try rogueKeyPackage(
			named: "well-capable-their-kp",
			capabilities: TwoMLSIdentity.leafCapabilities)
		let rogueKP = try rogueKeyPackage(
			named: "rogue-their-kp", capabilities: Self.rogueCapabilities)

		var classicalRogueParts = try migratedParts(alice)
		classicalRogueParts.initialTheirKP = (
			classical: try rogueKP.mlsEncoded(), pq: try wellCapableKP.mlsEncoded()
		)
		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: classicalRogueParts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}

		var pqRogueParts = try migratedParts(alice)
		pqRogueParts.initialTheirKP = (
			classical: try wellCapableKP.mlsEncoded(), pq: try rogueKP.mlsEncoded()
		)
		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: pqRogueParts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

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
	/// Also the conversion case where Group_A.pq (bob's `recvGroup.pq`) is a
	/// full pair from construction — no A.3 bootstrap needed for THIS half
	/// — so it already EXISTS at mint time, and its own leaf still presents
	/// the INVITATION identity's PQ key (nothing catches PQ up to D in this
	/// slice). `lookupPQ` must resolve it via `recvLeafPrincipal`'s PQ
	/// slot, not `identity`'s (which is D) — `assertMintedMatchesNative`
	/// below is the direct proof: it fails if that resolution is wrong.
	func testMintedBornDedicatedAcceptorRestoresWithCustodyIntact() throws {
		let established = try SessionTestSupport.establishedDedicated(bob: "bob-d")
		let bob = established.bob
		XCTAssertTrue(bob.owesEstablishmentEnvelope)
		let invitationCustody = try XCTUnwrap(bob.recvLeafPrincipal)
		XCTAssertNotEqual(bob.identity.clientID, invitationCustody.clientID)
		XCTAssertNotNil(
			bob.recvGroup?.pq, "Group_A.pq already exists at mint time")
		XCTAssertEqual(
			bob.leafKeys.recvPQ.current?.signatureKey, invitationCustody.pqSignatureKey,
			"recv-PQ still presents the invitation identity's key, not D's")

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(bob),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let native = try bob.makeSessionArchive(kind: .checkpoint)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)
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

	/// A one-sided rotation. Alice's classical rotation has FULLY
	/// converged to `newID` (both classical leaves present it, and the
	/// live session keeps `rotationCandidate` set even post-convergence —
	/// `GroupKeySet`'s own retention doesn't clear it), but her PQ leaves
	/// never moved at all — `sendGroup.pq`'s own leaf still presents her
	/// ORIGINAL PQ key. The migrated parts hand-build the deployed
	/// mapper's shape for this: `identity` is a FRESH, unrelated N,
	/// proving it is never consulted for a key nothing presents — every
	/// classical lookup instead resolves via the (untouched) candidate,
	/// exactly as the live session's own signing does. `recvLeafPrincipal`
	/// carries the ORIGINAL id, N's classical pair as an inert filler
	/// (never consulted — the candidate arm already covers classical), and
	/// the OLD PQ pair, which IS consulted: `sendPQ.current` must resolve
	/// to it, not to `identity`'s (N's, wrong) one — proved two ways: the
	/// minted value directly, and the restored session's own choke point,
	/// which independently re-derives the tree's actual presented key and
	/// would fail closed if the conversion had gotten this wrong.
	func testMintedOneSidedRotationResolvesSendPQToTheOriginalKey() throws {
		// Both PQ halves already exist, idle, turn on bob — reusing this
		// fixture (rather than hand-driving §A.3) starts past the PQ
		// bootstrap/ratchet entirely, so the classical rotation driven below
		// is the only PQ-adjacent thing this test needs to reason about.
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		let oldPQSigningKey = alice.identity.pqSigningKey
		let oldPQSignatureKey = alice.identity.pqSignatureKey
		let originalID = alice.identity.clientID

		let newID = Data("alice-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
		let catchUpDecrypted = try bob.processIncomingDecrypted(catchUpFrame)
		XCTAssertEqual(catchUpDecrypted.newSender, newID)
		XCTAssertEqual(alice.myPrincipalState, .sync(newID))
		XCTAssertNotNil(alice.rotationCandidate, "convergence doesn't clear the candidate")
		XCTAssertEqual(
			try TwoMLSSession.ownLeaf(of: alice.sendGroup!.pq!).signatureKey,
			alice.identity.pqSignatureKey,
			"send-PQ never moved off alice's original PQ key")

		let freshN = try TwoMLSIdentity.generate(
			clientID: Data("unrelated-n".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var parts = try migratedParts(alice)
		parts.identity = MigratedSessionIdentity(
			clientID: freshN.clientID, signingKey: freshN.signingKey.data,
			signatureKey: freshN.signatureKey.data,
			pqSigningKey: freshN.pqSigningKey.data,
			pqSignatureKey: freshN.pqSignatureKey.data,
			classicalLeafSecretKey: freshN.classicalLeafSecretKey.data,
			classicalInitSecretKey: nil, pqLeafSecretKey: freshN.pqLeafSecretKey.data,
			pqInitSecretKey: nil,
			classicalKeyPackage: try freshN.keyPackage.classical.mlsEncoded(),
			pqKeyPackage: try freshN.keyPackage.pq.mlsEncoded())
		parts.recvLeafPrincipal = MigratedRecvLeafPrincipal(
			clientID: originalID, signingKey: freshN.signingKey.data,
			signatureKey: freshN.signatureKey.data,
			pqSigningKey: oldPQSigningKey.data, pqSignatureKey: oldPQSignatureKey.data)

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let mintedBody = try minted.decode(SessionArchive.self)
		XCTAssertEqual(
			mintedBody.leafKeys.sendPQ?.current?.signatureKey, oldPQSignatureKey.data)
		XCTAssertNotEqual(
			mintedBody.leafKeys.sendPQ?.current?.signatureKey,
			freshN.pqSignatureKey.data)

		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		// The choke point IS the live proof: it independently re-derives
		// the tree's ACTUAL presented key and compares it against
		// `leafKeys.sendPQ.current` — the exact slot `sendPQSigningKey()`
		// (and so `owePQBind`) reads with no other logic in between. A
		// pass here means any future `owePQBind` call is GUARANTEED to
		// sign with the key the tree really presents.
		try restored.assertLeafKeysPresented()
		XCTAssertEqual(
			restored.leafKeys.sendPQ.current?.signingKey.data, oldPQSigningKey.data,
			"owePQBind reads exactly this slot, so this IS the old-key proof")
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

	// MARK: - Migration inputs on stored per-group signing keys

	/// Converts a LIVE `leafKeys` value 1:1 to `MigratedLeafKeys` — used
	/// only by tests that hand-stage a key `convertDeployedKeys` could
	/// never discover on its own (a window offer's target, never framed
	/// into `stagedUpdates`), so they supply it directly instead of relying
	/// on the temporary owner-keyed conversion.
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
							signatureKey: key.signatureKey.data)
					)
				})
		}
		return MigratedLeafKeys(
			sendClassical: convert(leafKeys.sendClassical),
			recvClassical: convert(leafKeys.recvClassical),
			sendPQ: convert(leafKeys.sendPQ), recvPQ: convert(leafKeys.recvPQ))
	}

	/// Hand-builds one genuinely-signed, unframed own-Update offer against
	/// `session.recvGroup.classical` (mirrors `RotationTests.
	/// authorRotatingUpd`) — a fresh keypair, so the offer's identity is
	/// fully known to the test, and NOT appended to `session.stagedUpdates`
	/// (a migrated session's framed store may not carry every offer the
	/// window does). Returns everything a `MigratedOwnOffer`/window record
	/// needs.
	private func handBuiltOwnOffer(in session: inout TwoMLSSession) throws -> (
		ref: Data, bareProposal: Data, epoch: UInt64, groupID: Data, senderLeafIndex: UInt32
	) {
		var mirror = try XCTUnwrap(session.recvGroup)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.classical.proposeUpdate(
			SessionTestSupport.classicalProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.classicalProvider,
				current: try session.recvClassicalSigningKey(), new: freshSigningKey
			),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: session.identity.clientID),
				signatureKey: freshSignatureKey))
		session.recvGroup = mirror
		// This hand-built Update bypasses `prepareToEncrypt`, which never
		// stages the fresh key itself — stage it so a later fold's
		// `promoted()` can find it.
		try session.leafKeys.recvClassical.stage(
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey),
			for: session.identity.clientID)
		guard case .publicMessage(let updatePub) = message else {
			XCTFail("expected a publicMessage-framed Update")
			throw TwoMLSError.malformedSideBandMessage
		}
		var scratchStore = MLS.RFC9420.ProposalStore()
		let verified = try mirror.classical.verifying(
			SessionTestSupport.classicalProvider, proposal: updatePub)
		let ref = try scratchStore.insert(verified, SessionTestSupport.classicalProvider)
		guard case .proposal(let bareProposal) = updatePub.content.content else {
			XCTFail("expected a proposal-carrying PublicMessage")
			throw TwoMLSError.malformedSideBandMessage
		}
		return (
			ref: ref.data, bareProposal: try bareProposal.mlsEncoded(),
			epoch: mirror.classical.context.epoch,
			groupID: mirror.classical.context.groupID,
			senderLeafIndex: mirror.classical.myLeafIndex.value
		)
	}

	/// Rule 10: `mintArchive(deployedState:)` and `mintOwnOfferWindow`
	/// must agree on the window id given the SAME window array, unchanged —
	/// they share the one `OwnOfferWindow.id` function.
	func testMintArchiveAndMintOwnOfferWindowAgreeOnTheWindowID() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let built = try handBuiltOwnOffer(in: &bob)
		let offer = MigratedOwnOffer(
			ref: built.ref, proposal: built.bareProposal,
			leafSecret: SecretBytes(randomByteCount: 32))
		let window = MigratedOwnOfferWindow(
			epoch: built.epoch, groupID: built.groupID,
			senderLeafIndex: built.senderLeafIndex, offers: [offer])

		var parts = try migratedParts(bob)
		// The hand-built offer's target lives ONLY in `bob.leafKeys`
		// (staged directly, not through any staged/pending Update
		// `convertDeployedKeys` would notice) — supply it explicitly, as a
		// real migrator would.
		parts.leafKeys = migratedLeafKeys(from: bob.leafKeys)
		let mintedArchive = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider,
			deployedState: MigratedDeployedState(ownOffers: window))
		let archiveBody = try mintedArchive.decode(SessionArchive.self)
		let recordID = try XCTUnwrap(archiveBody.deployedCarry?.ownOfferWindow?.id)
		XCTAssertEqual(recordID.count, 32)

		let mintedWindow = try SessionMigration.mintOwnOfferWindow(
			window, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider)
		XCTAssertEqual(mintedWindow.id, recordID)
	}

	/// An empty `offers` array is `.archiveInvalid` in both mints (A.2's
	/// "an empty window ⇒ .archiveInvalid in both mints").
	func testEmptyOwnOfferWindowIsRejectedByBothMints() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let recv = try XCTUnwrap(bob.recvGroup)
		let window = MigratedOwnOfferWindow(
			epoch: recv.classical.context.epoch,
			groupID: recv.classical.context.groupID,
			senderLeafIndex: recv.classical.myLeafIndex.value, offers: [])
		let parts = try migratedParts(bob)

		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider,
				deployedState: MigratedDeployedState(ownOffers: window))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
		XCTAssertThrowsError(
			try SessionMigration.mintOwnOfferWindow(
				window, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// The id function's own coverage, directly: two windows differing only
	/// in one offer's proposal bytes (same ref, epoch, group, sender leaf
	/// index) must hash to different ids. What this pins down is "the id
	/// function drops the proposal bytes or the sort" — dropping the
	/// proposal bytes from the hash is exactly what
	/// would make this assertion fail while leaving every mint-level test
	/// (which also rejects the tampered proposal on STRUCTURAL grounds,
	/// independent of the id) still passing.
	func testTheIDFunctionCoversTheProposalBytes() throws {
		let ref = Data(repeating: 0x11, count: 32)
		let groupID = Data("group".utf8)
		let offerA = OwnOfferWindow.SortedOffer(
			ref: ref, proposal: Data("proposal-a".utf8),
			leafSecret: SecretBytes(randomByteCount: 32))
		let offerB = OwnOfferWindow.SortedOffer(
			ref: ref, proposal: Data("proposal-b".utf8),
			leafSecret: SecretBytes(randomByteCount: 32))
		let idA = OwnOfferWindow.id(
			epoch: 1, groupID: groupID, senderLeafIndex: 0, sorted: [offerA])
		let idB = OwnOfferWindow.id(
			epoch: 1, groupID: groupID, senderLeafIndex: 0, sorted: [offerB])
		XCTAssertNotEqual(idA, idB)
	}

	/// A single flipped proposal byte changes the id (so a load elsewhere
	/// fails `.archiveInvalid` on the recompute-and-compare) — the direct
	/// negative for the id function actually covering the proposal bytes.
	func testFlippingAProposalByteChangesTheWindowID() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let built = try handBuiltOwnOffer(in: &bob)
		var tamperedProposal = built.bareProposal
		tamperedProposal[tamperedProposal.index(before: tamperedProposal.endIndex)] ^= 0xFF
		let genuine = MigratedOwnOfferWindow(
			epoch: built.epoch, groupID: built.groupID,
			senderLeafIndex: built.senderLeafIndex,
			offers: [
				MigratedOwnOffer(
					ref: built.ref, proposal: built.bareProposal,
					leafSecret: SecretBytes(randomByteCount: 32))
			])
		let tampered = MigratedOwnOfferWindow(
			epoch: built.epoch, groupID: built.groupID,
			senderLeafIndex: built.senderLeafIndex,
			offers: [
				MigratedOwnOffer(
					ref: built.ref, proposal: tamperedProposal,
					leafSecret: SecretBytes(randomByteCount: 32))
			])
		let parts = try migratedParts(bob)
		// The tampered proposal no longer decodes to a genuine `.update`
		// leaf-signature (flipping its trailing byte breaks the LeafNode's
		// own self-signature), so rule 10's shape check rejects it before
		// the id ever matters here — proves the tamper is real, not a
		// silent id-only difference an attacker could route around.
		XCTAssertThrowsError(
			try SessionMigration.mintOwnOfferWindow(
				tampered, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
		XCTAssertNoThrow(
			try SessionMigration.mintOwnOfferWindow(
				genuine, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider))
	}

	/// The other half of the id function's coverage: `canonicalOrder`'s own
	/// sort. Minting the SAME set of offers in two different input orders
	/// must produce the same window id and a byte-identical archive — the
	/// id (and the wire shape) depends only on the offer SET, never on the
	/// order a migrator happened to enumerate them in.
	func testMintingTheSameOffersInDifferentInputOrdersProducesIdenticalWindows() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let g = try knownSecretOffers(3, in: bob)
		let parts = try migratedParts(bob)
		func mint(_ offers: [MigratedOwnOffer]) throws -> MintedOwnOfferWindow {
			try SessionMigration.mintOwnOfferWindow(
				MigratedOwnOfferWindow(
					epoch: g.epoch, groupID: g.groupID, senderLeafIndex: g.leaf,
					offers: offers),
				parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider)
		}
		let forward = try mint(g.offers)
		let reordered = [g.offers[2], g.offers[0], g.offers[1]]
		let shuffled = try mint(reordered)

		XCTAssertEqual(forward.id, shuffled.id)
		let forwardBody = try forward.archive.decode(OwnOfferWindowArchive.self)
		let shuffledBody = try shuffled.archive.decode(OwnOfferWindowArchive.self)
		XCTAssertEqual(forwardBody.refs, shuffledBody.refs)
		XCTAssertEqual(forwardBody.proposalLengths, shuffledBody.proposalLengths)
		XCTAssertEqual(forwardBody.proposals, shuffledBody.proposals)
		XCTAssertEqual(
			forwardBody.leafSecrets.withUnsafeBytes { Data($0) },
			shuffledBody.leafSecrets.withUnsafeBytes { Data($0) })
	}

	/// Generalized catch-up, `.mintSupplied`: every existing own leaf
	/// whose credential lags `auth.mine.current` — classical AND PQ alike —
	/// needs `pending[mine.current]` in that group, and a caller that
	/// supplies it is accepted (subsuming the prior rotation/born-
	/// dedicated-only cases).
	func testMintSuppliedLeafKeysSatisfyTheGeneralizedCatchUpRuleAcrossAllFourGroups() throws {
		// Needs both PQ halves genuinely established (not the reservation
		// shape from before A.3, which requires an EMPTY pending) so a
		// non-empty PQ `pending` is check 3's "existing group" arm, not
		// rule 4's reservation arm.
		let (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		var parts = try migratedParts(bob)
		let newID = Data("bob-caught-up-to".utf8)
		parts.auth.mine.history.append(newID)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let pendingKey = MigratedLeafKey(
			signingKey: freshSigningKey.data, signatureKey: freshSignatureKey.data)

		func withCatchUp(_ current: MigratedLeafKey) -> MigratedGroupKeys {
			MigratedGroupKeys(
				current: current,
				pending: [MigratedPendingLeafKey(target: newID, key: pendingKey)])
		}
		let identityClassicalKey = MigratedLeafKey(
			signingKey: bob.identity.signingKey.data,
			signatureKey: bob.identity.signatureKey.data)
		let identityPQKey = MigratedLeafKey(
			signingKey: bob.identity.pqSigningKey.data,
			signatureKey: bob.identity.pqSignatureKey.data)
		parts.leafKeys = MigratedLeafKeys(
			sendClassical: withCatchUp(identityClassicalKey),
			recvClassical: withCatchUp(identityClassicalKey),
			sendPQ: withCatchUp(identityPQKey),
			recvPQ: withCatchUp(identityPQKey))

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(
			restored.leafKeys.sendClassical.pending[newID]?.signatureKey.data,
			freshSignatureKey.data)
		XCTAssertEqual(
			restored.leafKeys.recvClassical.pending[newID]?.signatureKey.data,
			freshSignatureKey.data)
		XCTAssertEqual(
			restored.leafKeys.sendPQ.pending[newID]?.signatureKey.data,
			freshSignatureKey.data)
		XCTAssertEqual(
			restored.leafKeys.recvPQ.pending[newID]?.signatureKey.data,
			freshSignatureKey.data)
	}

	/// "A rotation Rust won" — `mine.current` moved to `c` but
	/// BOTH classical own leaves still present the old id, `pending[c]`
	/// staged on both, no `rotationCandidate`, no `recvLeafPrincipal` — the
	/// shape a Rust-side rotation's export leaves for a migrated session.
	/// Built through the MINT (the production path), reusing this suite's
	/// own generalized-catch-up fixture, rather than poking a live
	/// session's fields directly. Kills the revert to the old
	/// candidate-based send-catch-up predicate (half 1b) and, together with
	/// `BornDedicatedTests.testGeneralizedCatchUpWithoutRecvLeafPrincipal`,
	/// the recv-side revert (half 1a) in this non-born-dedicated shape too.
	func testRustWonRotationCatchesUpBothClassicalLeaves() throws {
		OracleCheck.allow([.sendClassical, .recvClassical])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		var parts = try migratedParts(bob)
		let c = Data("bob-rust-rotated".utf8)
		parts.auth.mine.history.append(c)

		let (classicalSigningKey, classicalSignatureKey) =
			try TwoMLSIdentity
			.mintSignatureKeypair()
		let classicalPendingKey = MigratedLeafKey(
			signingKey: classicalSigningKey.data,
			signatureKey: classicalSignatureKey.data)
		let identityClassicalKey = MigratedLeafKey(
			signingKey: bob.identity.signingKey.data,
			signatureKey: bob.identity.signatureKey.data)
		let identityPQKey = MigratedLeafKey(
			signingKey: bob.identity.pqSigningKey.data,
			signatureKey: bob.identity.pqSignatureKey.data)
		func classicalWithCatchUp() -> MigratedGroupKeys {
			MigratedGroupKeys(
				current: identityClassicalKey,
				pending: [
					MigratedPendingLeafKey(target: c, key: classicalPendingKey)
				])
		}
		// Rule 7's PQ arm is ALSO enforced in `.mintSupplied` (leafKeys
		// supplied) once `mine.current` moves — reuse the identity PQ key
		// as its own "catch-up" so minting succeeds; this test's own
		// assertions are about the classical leaves only.
		func pqWithCatchUp() -> MigratedGroupKeys {
			MigratedGroupKeys(
				current: identityPQKey,
				pending: [MigratedPendingLeafKey(target: c, key: identityPQKey)])
		}
		parts.leafKeys = MigratedLeafKeys(
			sendClassical: classicalWithCatchUp(),
			recvClassical: classicalWithCatchUp(),
			sendPQ: pqWithCatchUp(), recvPQ: pqWithCatchUp())

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertNil(restoredBob.recvLeafPrincipal)
		XCTAssertNil(restoredBob.rotationCandidate)

		// `alice` is a live, un-migrated session: the send-catch-up commit
		// below lands as a fold, not a queued-and-authorized offer, so her
		// own AS needs `c` already reachable in her tracked view of bob —
		// exactly what a real peer would already hold, having seen the
		// Rust-side rotation for real before bob ever migrated.
		alice.auth.theirs.history.append(c)

		let prepared = try restoredBob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit, "the licensed send-classical catch-up (1b)")
		XCTAssertEqual(
			restoredBob.pendingProposal?.proposing, c,
			"the staged recv-classical catch-up offer (1a)")
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(
					of: XCTUnwrap(restoredBob.sendGroup?.classical)
				)
				.credential), c)

		let frame = try restoredBob.encrypt(Data("bob-catchup".utf8)).frame
		let aliceSaw = try alice.processIncomingDecrypted(frame)
		XCTAssertTrue(aliceSaw.didApplyRemoteCommit, "1b, mirrored at alice")
		XCTAssertEqual(aliceSaw.queuedProposal.proposing, c, "1a's offer, surfaced")

		try alice.queueProposal(digest: aliceSaw.queuedProposal.digest)
		let aliceFolded = try alice.prepareToEncrypt()
		XCTAssertTrue(aliceFolded.didCommit)
		let foldFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		let bobApplied = try restoredBob.processIncomingDecrypted(foldFrame)
		XCTAssertTrue(bobApplied.didApplyRemoteCommit, "1a lands at bob")
		XCTAssertEqual(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(
					of: XCTUnwrap(restoredBob.recvGroup?.classical)
				)
				.credential), c)
	}

	/// The generalized catch-up's `.mintSupplied`-only PQ enforcement: a born-dedicated bob
	/// before A.3 has `recvGroup.pq` (Group_A is the standard pair, so it
	/// exists from birth) still presenting the INVITATION identity's PQ
	/// key while `auth.mine.current` is already D — a PQ lag
	/// `.mintConverted` tolerates (native sessions mint no PQ catch-up key
	/// until a later step; `testMintedBornDedicatedAcceptorRestoresWithCustodyIntact`
	/// pins exactly this) but `.mintSupplied` must enforce once the caller
	/// is on the hook for rule 7's PQ arm.
	func testMintSuppliedModeRequiresThePQCatchUpKeyThatMintConvertedTolerates() throws {
		let established = try SessionTestSupport.establishedDedicated(bob: "bob-d")
		let bob = established.bob
		let invitationCustody = try XCTUnwrap(bob.recvLeafPrincipal)
		let parts = try migratedParts(bob)

		// `.mintConverted` (parts.leafKeys == nil): tolerated.
		XCTAssertNoThrow(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider))

		// `.mintSupplied`, mirroring conversion's own shape everywhere
		// EXCEPT the recv-PQ catch-up key: rejected.
		let dClassicalKey = MigratedLeafKey(
			signingKey: bob.identity.signingKey.data,
			signatureKey: bob.identity.signatureKey.data)
		let dPQKey = MigratedLeafKey(
			signingKey: bob.identity.pqSigningKey.data,
			signatureKey: bob.identity.pqSignatureKey.data)
		let invitationClassicalKey = MigratedLeafKey(
			signingKey: invitationCustody.signingKey.data,
			signatureKey: invitationCustody.signatureKey.data)
		let invitationPQKey = MigratedLeafKey(
			signingKey: invitationCustody.pqSigningKey.data,
			signatureKey: invitationCustody.pqSignatureKey.data)
		var suppliedParts = parts
		suppliedParts.leafKeys = MigratedLeafKeys(
			sendClassical: MigratedGroupKeys(current: dClassicalKey),
			recvClassical: MigratedGroupKeys(
				current: invitationClassicalKey,
				pending: [
					MigratedPendingLeafKey(
						target: bob.identity.clientID, key: dClassicalKey)
				]),
			sendPQ: MigratedGroupKeys(current: dPQKey),
			// No `pending[D]` here — the missing catch-up key.
			recvPQ: MigratedGroupKeys(current: invitationPQKey))
		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: suppliedParts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// Archive keys 44/45 round-trip a no-custody classical role and a PQ
	/// wedge through restore, and the three read-only queries
	/// read them back correctly.
	func testDeployedCarryRoundTripsNoCustodyAndWedgeThroughRestore() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		var parts = try migratedParts(bob)
		let identityClassicalKey = MigratedLeafKey(
			signingKey: bob.identity.signingKey.data,
			signatureKey: bob.identity.signatureKey.data)
		let identityPQKey = MigratedLeafKey(
			signingKey: bob.identity.pqSigningKey.data,
			signatureKey: bob.identity.pqSignatureKey.data)
		parts.leafKeys = MigratedLeafKeys(
			sendClassical: MigratedGroupKeys(current: nil),
			recvClassical: MigratedGroupKeys(current: identityClassicalKey),
			sendPQ: MigratedGroupKeys(current: identityPQKey),
			recvPQ: MigratedGroupKeys(current: identityPQKey))

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider,
			deployedState: MigratedDeployedState(
				pqWedged: .bootstrap, noCustody: [.sendClassical]))

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(restored.noCustody, [.sendClassical])
		XCTAssertTrue(restored.pqSideBandWedged)
		XCTAssertFalse(restored.canSend, "no-custody on a classical role blocks canSend")
		XCTAssertThrowsError(try restored.sendClassicalSigningKey()) { error in
			XCTAssertEqual(error as? TwoMLSError, .leafCustodyUnavailable)
		}
	}
}

// MARK: - Own-offer window sampling and cap edges

@available(iOS 26, macOS 26, *)
extension SessionMigrationTests {
	private func knownSecretOffers(_ n: Int, in bob: TwoMLSSession) throws -> (
		offers: [MigratedOwnOffer], epoch: UInt64, groupID: Data, leaf: UInt32
	) {
		var result: [MigratedOwnOffer] = []
		var meta: (UInt64, Data, UInt32) = (0, Data(), 0)
		for _ in 0..<n {
			let o = try SessionTestSupport.knownSecretOwnOffer(in: bob)
			// A fresh random ref per offer, not derived from the leaf: the
			// SPI trial (`insertMigratedOwnUpdate`) never checks that a ref
			// pairs with any particular leaf, so an arbitrary unique ref is
			// as good as a genuine one for exercising sampling coverage.
			result.append(
				MigratedOwnOffer(
					ref: SessionTestSupport.classicalProvider.randomBytes(32),
					proposal: o.bareProposal, leafSecret: o.leafSecret))
			meta = (o.epoch, o.groupID, o.senderLeafIndex)
		}
		return (result, meta.0, meta.1, meta.2)
	}

	private func withBadSecret(_ offer: MigratedOwnOffer) -> MigratedOwnOffer {
		MigratedOwnOffer(
			ref: offer.ref, proposal: offer.proposal,
			leafSecret: try! SessionTestSupport.classicalProvider.hpkeGenerateKeyPair()
				.0.data)
	}

	/// Items 6a/6b: the validator trials the first 64 offers PLUS 64 more
	/// drawn by the seeded sample — never fewer, and never an unsampled
	/// offer past the first 64. N = 200, all known-secret (the
	/// caller-supplied branch, not group-written-back).
	func testSamplingCoversSeededExtras() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let g = try knownSecretOffers(200, in: bob)
		let sorted = try OwnOfferWindow.canonicalOrder(g.offers)
		let id = OwnOfferWindow.id(
			epoch: g.epoch, groupID: g.groupID, senderLeafIndex: g.leaf, sorted: sorted)
		let sample = OwnOfferWindow.sampledOfferIndices(count: 200, idSeed: id)
		XCTAssertEqual(sample.count, 128)
		XCTAssertEqual(
			Array(sample.prefix(64)), Array(0..<64), "the first 64 always sampled")
		let extra = try XCTUnwrap(sample.dropFirst(64).first)
		let unsampled = try XCTUnwrap((64..<200).first { !sample.contains($0) })

		let parts = try migratedParts(bob)
		func mint(_ offers: [MigratedOwnOffer]) throws -> MintedOwnOfferWindow {
			try SessionMigration.mintOwnOfferWindow(
				MigratedOwnOfferWindow(
					epoch: g.epoch, groupID: g.groupID, senderLeafIndex: g.leaf,
					offers: offers),
				parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider)
		}
		XCTAssertEqual(try mint(g.offers).id, id, "control: the genuine window mints")

		var badExtra = g.offers
		badExtra[extra] = withBadSecret(badExtra[extra])
		XCTAssertThrowsError(
			try mint(badExtra), "a seeded extra (index \(extra)) must be trialed"
		) {
			XCTAssertEqual($0 as? TwoMLSError, .archiveInvalid)
		}
		var badFirst = g.offers
		badFirst[10] = withBadSecret(badFirst[10])
		XCTAssertThrowsError(try mint(badFirst), "an offer in the first 64 must be trialed")
		{
			XCTAssertEqual($0 as? TwoMLSError, .archiveInvalid)
		}
		var badUnsampled = g.offers
		badUnsampled[unsampled] = withBadSecret(badUnsampled[unsampled])
		XCTAssertNoThrow(
			try mint(badUnsampled),
			"the bounded sample never trials an unsampled offer (index \(unsampled))")
	}

	/// Items 7a/7b: `validate(cap:)`'s edge — the count equal to the cap is
	/// accepted, one more than the cap is rejected.
	func testWindowCapEdge() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let g = try knownSecretOffers(5, in: bob)
		let group = try XCTUnwrap(bob.recvGroup).classical
		func validate(_ n: Int, cap: Int) throws {
			_ = try OwnOfferWindow.validate(
				MigratedOwnOfferWindow(
					epoch: g.epoch, groupID: g.groupID, senderLeafIndex: g.leaf,
					offers: Array(g.offers.prefix(n))),
				recvClassical: group, myLeafIndex: group.myLeafIndex, cap: cap,
				provider: SessionTestSupport.classicalProvider)
		}
		XCTAssertNoThrow(try validate(4, cap: 4), "count == cap accepted")
		XCTAssertThrowsError(try validate(5, cap: 4), "count == cap + 1 rejected") {
			XCTAssertEqual($0 as? TwoMLSError, .archiveInvalid)
		}
	}

	private func mintedWithWindow() throws -> (bob: TwoMLSSession, archive: SecretArchive) {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let g = try knownSecretOffers(1, in: bob)
		let parts = try migratedParts(bob)
		let archive = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider,
			deployedState: MigratedDeployedState(
				ownOffers: MigratedOwnOfferWindow(
					epoch: g.epoch, groupID: g.groupID, senderLeafIndex: g.leaf,
					offers: g.offers)))
		return (bob, archive)
	}

	private func restorePatched(
		_ archive: SecretArchive, _ patch: (inout OwnOfferWindowRecord) -> Void
	) throws -> TwoMLSSession {
		var body = try archive.decode(SessionArchive.self)
		var record = try XCTUnwrap(body.deployedCarry?.ownOfferWindow)
		patch(&record)
		body.deployedCarry?.ownOfferWindow = record
		return try TwoMLSSession.restore(
			core: nil, checkpoint: try SecretArchive(encoding: body),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	/// Items 7c/7d/8: restore's own window-record checks — the epoch must
	/// match the rebuilt recv-classical group's own epoch exactly (neither
	/// direction), and the count must be `<= maximumOfferCount`, not
	/// `< maximumOfferCount` and not `<= maximumOfferCount + 1`.
	func testRestoreRejectsBadWindowRecord() throws {
		let m = try mintedWithWindow()
		XCTAssertNotNil(try restorePatched(m.archive) { _ in }.ownOfferWindow, "control")
		XCTAssertThrowsError(try restorePatched(m.archive) { $0.epoch += 1 }) {
			XCTAssertEqual($0 as? TwoMLSError, .archiveInvalid)
		}
		XCTAssertThrowsError(try restorePatched(m.archive) { $0.epoch -= 1 }) {
			XCTAssertEqual($0 as? TwoMLSError, .archiveInvalid)
		}
		XCTAssertNoThrow(
			try restorePatched(m.archive) {
				$0.count = UInt32(MigratedOwnOfferWindow.maximumOfferCount)
			})
		XCTAssertThrowsError(
			try restorePatched(m.archive) {
				$0.count = UInt32(MigratedOwnOfferWindow.maximumOfferCount) + 1
			}
		) {
			XCTAssertEqual($0 as? TwoMLSError, .archiveInvalid)
		}
	}
}

// MARK: - Drop at import

@available(iOS 26, macOS 26, *)
extension SessionMigrationTests {
	private func rekeyInitiatedBob() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, upd: Data
	) {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try bob.pqRekeyBegin()
		guard case .rekeyInitiated(let upd) = bob.pqInflight else {
			XCTFail("expected .rekeyInitiated")
			throw TwoMLSError.sessionNotReady
		}
		return (alice, bob, upd)
	}

	private func restoreMinted(_ parts: MigratedSession) throws -> TwoMLSSession {
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		return try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	/// `pendingSideBand` is asserted here too: a parked
	/// `Upd′` that DOES verify against the restored recv-PQ group is kept
	/// whole, `pendingSideBand` intact, and the round still completes.
	func testValidParkedUpdIsKeptAtImport() throws {
		var (alice, bob, upd) = try rekeyInitiatedBob()
		let parts = try migratedParts(bob)
		var restored = try restoreMinted(parts)
		guard case .rekeyInitiated(let kept) = restored.pqInflight else {
			return XCTFail("dropped a valid Upd′")
		}
		XCTAssertEqual(kept, upd)
		XCTAssertEqual(restored.pendingSideBand, bob.pendingSideBand)
		let updFrame = try restored.pqRekeyBegin().frame
		let commit = try alice.pqRekeyRespond(updFrame).frame
		XCTAssertNoThrow(try restored.pqRekeyApply(commit))
		bob = restored
	}

	/// `pendingSideBand` is asserted here too: a parked
	/// `Upd′` that fails to verify against the restored recv-PQ group is
	/// dropped — `pqInflight` and `pendingSideBand` both cleared,
	/// `pqTurnMine` left as supplied — and self-drive then opens a plain
	/// A.4 rather than silently stalling.
	func testUnverifiableParkedUpdIsDroppedAtImport() throws {
		let (_, bob, upd) = try rekeyInitiatedBob()
		var tampered = upd
		tampered[tampered.index(before: tampered.endIndex)] ^= 0xFF
		var parts = try migratedParts(bob)
		parts.pqInflight = .rekeyInitiated(updMessage: tampered)
		parts.pendingSideBand = Frames.encodePQRekeyUpd(tampered)
		var restored = try restoreMinted(parts)
		XCTAssertNil(restored.pqInflight)
		XCTAssertNil(restored.pendingSideBand)
		XCTAssertTrue(restored.myPQTurn, "pqTurnMine left as supplied")

		_ = try restored.prepareToEncrypt()
		_ = try restored.encrypt(Data("x".utf8))
		XCTAssertNotNil(restored.pendingSideBand)
		XCTAssertEqual(restored.pendingSideBand?.first, Frames.pqEKTag)

		// A present but nil sideband is fine; a mismatched one is
		// `.archiveInvalid` (never silently repaired).
		var partsNil = parts
		partsNil.pendingSideBand = nil
		XCTAssertNil(try restoreMinted(partsNil).pqInflight)
		var partsBad = parts
		partsBad.pendingSideBand = Frames.encodePQRekeyUpd(upd)
		XCTAssertThrowsError(try restoreMinted(partsBad)) {
			XCTAssertEqual($0 as? TwoMLSError, .archiveInvalid)
		}
	}

	/// Supplied `leafKeys` still carries the dropped round's
	/// orphaned recv-PQ `pending` entry — it must be removed too, not just
	/// `pqInflight`/`pendingSideBand`.
	func testDroppedRoundPendingEntryIsRemoved() throws {
		let (_, bob, upd) = try rekeyInitiatedBob()
		var tampered = upd
		tampered[tampered.index(before: tampered.endIndex)] ^= 0xFF
		var parts = try migratedParts(bob)
		parts.pqInflight = .rekeyInitiated(updMessage: tampered)
		parts.pendingSideBand = nil
		var lk = migratedLeafKeys(from: bob.leafKeys)
		let (sk, pk) = try TwoMLSIdentity.mintSignatureKeypair()
		lk.recvPQ = MigratedGroupKeys(
			current: lk.recvPQ.current,
			pending: [
				MigratedPendingLeafKey(
					target: bob.identity.clientID,
					key: MigratedLeafKey(
						signingKey: sk.data, signatureKey: pk.data))
			])
		parts.leafKeys = lk
		let restored = try restoreMinted(parts)
		XCTAssertNil(restored.leafKeys.recvPQ.pending[bob.identity.clientID])
	}

	/// The rule-7 exception — a dropped round's target that IS
	/// `mine.current` of a still-lagging recv-PQ leaf must be KEPT, not
	/// removed by the same pruning that discards 4d's orphan.
	func testDroppedRoundKeepsTheRuleSevenKey() throws {
		let (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let c = Data("bob-rust-rotated".utf8)
		var mirror = try XCTUnwrap(bob.recvGroup)
		let (fsk, fpk) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.pq!.proposeUpdate(
			SessionTestSupport.pqProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.pqProvider, current: try bob.recvPQSigningKey(),
				new: fsk),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: c), signatureKey: fpk))
		var upd = try message.mlsEncoded()
		upd[upd.index(before: upd.endIndex)] ^= 0xFF
		var parts = try migratedParts(bob)
		parts.auth.mine.history.append(c)
		parts.pqInflight = .rekeyInitiated(updMessage: upd)
		parts.pendingSideBand = nil
		let pendingKey = MigratedLeafKey(signingKey: fsk.data, signatureKey: fpk.data)
		let lk = migratedLeafKeys(from: bob.leafKeys)
		func plus(_ g: MigratedGroupKeys) -> MigratedGroupKeys {
			MigratedGroupKeys(
				current: g.current,
				pending: [MigratedPendingLeafKey(target: c, key: pendingKey)])
		}
		parts.leafKeys = MigratedLeafKeys(
			sendClassical: plus(lk.sendClassical),
			recvClassical: plus(lk.recvClassical),
			sendPQ: plus(lk.sendPQ), recvPQ: plus(lk.recvPQ))
		let restored = try restoreMinted(parts)
		XCTAssertNil(restored.pqInflight)
		XCTAssertEqual(restored.leafKeys.recvPQ.pending[c]?.signatureKey, fpk)
	}
}

@available(iOS 26, macOS 26, *)
extension SessionMigrationTests {
	/// A rogue initiator whose own classical leaf does not advertise 0xF0A1
	/// completes `initiate` on its own side; the mint's four-tree capability
	/// check must still refuse the resulting restored trees.
	func testMintRefusesARogueOccupiedLeafInARestoredTree() throws {
		let clientID = Data("rogue-initiator".utf8)
		let classicalProvider = SessionTestSupport.classicalProvider
		let pqProvider = SessionTestSupport.pqProvider
		let rogueCaps = MLS.RFC9420.Capabilities(
			versions: [.mls10], cipherSuites: [TwoMLSSuite.classical, TwoMLSSuite.pq],
			extensions: [], proposals: [MLS.RFC9420.ProposalType(.appDataUpdate)],
			credentials: [MLS.RFC9420.CredentialType(.basic)])
		func kp(
			suite: MLS.CipherSuite, provider: any MLS.CipherSuiteProvider,
			signingKey: MLS.SignatureSecretKey, signatureKey: MLS.SignaturePublicKey,
			leafPublicKey: MLS.HpkePublicKey, initPublicKey: MLS.HpkePublicKey,
			caps: MLS.RFC9420.Capabilities
		) throws -> MLS.RFC9420.KeyPackage {
			var leaf = MLS.RFC9420.LeafNode(
				encryptionKey: leafPublicKey, signatureKey: signatureKey,
				credential: .basic(identity: clientID), capabilities: caps,
				source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
				extensions: [], signature: Data())
			leaf.signature = try MLS.signWithLabel(
				provider, privateKey: signingKey, label: "LeafNodeTBS",
				content: try leaf.toBeSigned(placement: .keyPackage))
			var keyPackage = MLS.RFC9420.KeyPackage(
				version: .mls10, cipherSuite: suite, initKey: initPublicKey,
				leafNode: leaf, extensions: [], signature: Data())
			keyPackage.signature = try MLS.signWithLabel(
				provider, privateKey: signingKey, label: "KeyPackageTBS",
				content: try keyPackage.toBeSigned())
			return keyPackage
		}
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (pqSigningKey, pqSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (cLeafSK, cLeafPK) = try classicalProvider.hpkeGenerateKeyPair()
		let (cInitSK, cInitPK) = try classicalProvider.hpkeGenerateKeyPair()
		let (pLeafSK, pLeafPK) = try pqProvider.hpkeGenerateKeyPair()
		let (pInitSK, pInitPK) = try pqProvider.hpkeGenerateKeyPair()
		let classicalKP = try kp(
			suite: TwoMLSSuite.classical, provider: classicalProvider,
			signingKey: signingKey, signatureKey: signatureKey, leafPublicKey: cLeafPK,
			initPublicKey: cInitPK, caps: rogueCaps)
		let pqKP = try kp(
			suite: MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID),
			provider: pqProvider, signingKey: pqSigningKey,
			signatureKey: pqSignatureKey,
			leafPublicKey: pLeafPK, initPublicKey: pInitPK,
			caps: TwoMLSIdentity.leafCapabilities)
		let rogueAlice = TwoMLSIdentity(
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			pqSigningKey: pqSigningKey, pqSignatureKey: pqSignatureKey,
			classicalLeafSecretKey: cLeafSK, classicalInitSecretKey: cInitSK,
			pqLeafSecretKey: pLeafSK, pqInitSecretKey: pInitSK,
			keyPackage: CombinerKeyPackage(classical: classicalKP, pq: pqKP))
		let bob = try SessionTestSupport.identity("honest-bob-for-rogue-mint")
		let initiated = try TwoMLSSession.initiate(
			identity: rogueAlice, their: bob.keyPackage,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		let parts = try migratedParts(initiated.session)
		XCTAssertThrowsError(
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: classicalProvider, pqProvider: pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}
}
