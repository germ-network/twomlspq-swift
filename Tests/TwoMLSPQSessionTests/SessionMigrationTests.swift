import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import Testing

@testable import TwoMLSPQSession

/// The public parts-to-archive session minter. The minted
/// archive must be what `TwoMLSSession.restore` accepts and semantically
/// what `makeSessionArchive` would have produced — the cross-module migrator
/// calls this with raw parts read from a legacy Rust session, so it must
/// work without a live `TwoMLSSession` (the group halves arrive as
/// format-2 snapshot `SecretArchive`s, the value `Group.archive()` produces
/// and what a Rust exporter's bytes ingest via
/// `SecretArchive(decodingPlaintext:)`).
@Suite struct SessionMigrationTests {
	/// Decomposes a live session into the exact raw parts a migrator would
	/// read off a legacy Rust session (same byte representations the native
	/// state holds). The kind is deliberately NOT part of the parts: the
	/// migrator supplies the same parts to either mint.
	/// `identityOverride` defaults to `session.identity`, correct for every
	/// non-dedicated fixture (a deployed-shaped session founds its own
	/// leaves on exactly that identity's KP halves, so it already IS the
	/// exported identity). A born-dedicated deployed session instead
	/// exports D's own full bundle — the deployed engine has no
	/// invitation-vs-D split at all — so those call sites pass D explicitly.
	/// `recvLeafPrincipal` has no native source any more (the recv-leaf
	/// catch-up custody carries no key of its own) — a born-dedicated
	/// fixture that needs the migrator's retained-custody record supplies
	/// it explicitly.
	@available(iOS 26, macOS 26, *)
	private func migratedParts(
		_ session: TwoMLSSession, identityOverride: TwoMLSIdentity? = nil,
		recvLeafPrincipal: MigratedRecvLeafPrincipal? = nil,
		suppliedLeafKeys: Bool = false
	) throws -> MigratedSession {
		let identity = identityOverride ?? session.identity
		let send = try #require(session.sendGroup)
		let sendClassicalSnapshot = try send.classical.archive()
		let sendPQSnapshot = try send.pq?.archive()
		return try MigratedSession(
			stateSeq: session.stateSeq,
			initiated: session.initiated,
			identity: MigratedSessionIdentity(
				clientID: identity.clientID,
				signingKey: identity.signingKey.data,
				signatureKey: identity.signatureKey.data,
				pqSigningKey: identity.pqSigningKey.data,
				pqSignatureKey: identity.pqSignatureKey.data,
				classicalLeafSecretKey: identity.classicalLeafSecretKey
					.data,
				classicalInitSecretKey: identity.classicalInitSecretKey?
					.data,
				pqLeafSecretKey: identity.pqLeafSecretKey.data,
				pqInitSecretKey: identity.pqInitSecretKey?.data,
				classicalKeyPackage: try identity.keyPackage.classical
					.mlsEncoded(),
				pqKeyPackage: try identity.keyPackage.pq.mlsEncoded()),
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
			rotationCandidate: try session.rotationCandidate.map { candidate in
				// Retention keeps the record even once both classical
				// leaves have converged onto it (`GroupKeySet`'s own
				// doc) — by then the key sits in `current`, not
				// `pending`, so fall back to whichever classical set's
				// own leaf now presents this id.
				let key: LeafKey
				if let pending = session.leafKeys.sendClassical.pending[
					candidate.clientID]
					?? session.leafKeys.recvClassical.pending[
						candidate.clientID]
				{
					key = pending
				} else if try session.sendGroup.map({
					try basicIdentifier(
						TwoMLSSession.ownLeaf(of: $0.classical).credential)
				}) == candidate.clientID {
					key = try #require(session.leafKeys.sendClassical.current)
				} else {
					key = try #require(session.leafKeys.recvClassical.current)
				}
				return MigratedRotationCandidate(
					clientID: candidate.clientID,
					signingKey: key.signingKey.data,
					signatureKey: key.signatureKey.data,
					proposedAtRecvEpoch: candidate.proposedAtRecvEpoch)
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
			recvLeafPrincipal: recvLeafPrincipal,
			owesEstablishmentEnvelope: session.owesEstablishmentEnvelope,
			leafKeys: suppliedLeafKeys ? migratedLeafKeys(from: session.leafKeys) : nil)
	}

	// MARK: - Deployed-shaped fixtures
	//
	// A migrator's input is a genuine deployed Rust session: every group a
	// party founds is founded on that SAME party's one KP-bundle leaf, so
	// one `identity` key legitimately founds several groups at once
	// (`SessionMigration`'s owner-keyed `convertDeployedKeys` exists only
	// to read exactly that shape). The native path no longer produces it
	// (each founds a fresh leaf per group) — these helpers reproduce it
	// directly through the `founding:`/`catchUpKey:` test seam, so this
	// file keeps exercising the converter against the shape it must
	// actually accept. D1 (fresh, independent founding leaves) is proven
	// by the native-path tests elsewhere, never here.

	@available(iOS 26, macOS 26, *)
	private func deployedShapedFounding(
		_ half: MLS.RFC9420.KeyPackage, secret: MLS.HpkeSecretKey,
		signingKey: MLS.SignatureSecretKey,
		signatureKey: MLS.SignaturePublicKey
	) -> FoundingLeaf {
		(
			leafNode: half.leafNode, leafSecretKey: secret,
			key: LeafKey(signingKey: signingKey, signatureKey: signatureKey)
		)
	}

	/// `SessionTestSupport.established()`'s deployed-shaped analogue: Alice
	/// founds Group_A's classical+PQ halves on her own already-signed KP
	/// leaves (never a freshly minted founding leaf), and Bob founds
	/// Group_B's classical half on his.
	@available(iOS 26, macOS 26, *)
	private func deployedShapedEstablished(
		alice aliceName: String = "alice", bob bobName: String = "bob"
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, aliceIdentity: TwoMLSIdentity,
		bobIdentity: TwoMLSIdentity
	) {
		let aliceIdentity = try SessionTestSupport.identity(aliceName)
		let bobIdentity = try SessionTestSupport.identity(bobName)
		let initiated = try TwoMLSSession.initiate(
			identity: aliceIdentity, their: bobIdentity.keyPackage,
			founding: (
				classical: deployedShapedFounding(
					aliceIdentity.keyPackage.classical,
					secret: aliceIdentity.classicalLeafSecretKey,
					signingKey: aliceIdentity.signingKey,
					signatureKey: aliceIdentity.signatureKey),
				pq: deployedShapedFounding(
					aliceIdentity.keyPackage.pq,
					secret: aliceIdentity.pqLeafSecretKey,
					signingKey: aliceIdentity.pqSigningKey,
					signatureKey: aliceIdentity.pqSignatureKey)
			),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let received = try TwoMLSSession.receive(
			identity: bobIdentity, welcome: initiated.welcome,
			theirClassicalKeyPackage: aliceIdentity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			founding: deployedShapedFounding(
				bobIdentity.keyPackage.classical,
				secret: bobIdentity.classicalLeafSecretKey,
				signingKey: bobIdentity.signingKey,
				signatureKey: bobIdentity.signatureKey),
			catchUpKey: nil,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		return (
			alice: initiated.session, bob: received.session,
			aliceIdentity: aliceIdentity,
			bobIdentity: bobIdentity
		)
	}

	@available(iOS 26, macOS 26, *)
	private func deployedShapedEstablishedAndExchanged(
		alice aliceName: String = "alice", bob bobName: String = "bob"
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, aliceIdentity: TwoMLSIdentity,
		bobIdentity: TwoMLSIdentity
	) {
		var (alice, bob, aliceIdentity, bobIdentity) = try deployedShapedEstablished(
			alice: aliceName, bob: bobName)
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(frame)
		return (
			alice: alice, bob: bob, aliceIdentity: aliceIdentity,
			bobIdentity: bobIdentity
		)
	}

	/// `RatchetTests.fullyEstablishedTurnOnBob()`'s deployed-shaped
	/// analogue: Bob's A.3 founding leaf is his own already-signed PQ KP
	/// leaf too, signed with the same key his classical founding leaf uses
	/// — exactly the deployed engine's one-key-per-party shape.
	@available(iOS 26, macOS 26, *)
	private func deployedShapedFullyEstablishedTurnOnBob() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession
	) {
		var (alice, bob, _, bobIdentity) = try deployedShapedEstablishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(
			kpFrame,
			founding: deployedShapedFounding(
				bobIdentity.keyPackage.pq, secret: bobIdentity.pqLeafSecretKey,
				signingKey: bobIdentity.pqSigningKey,
				signatureKey: bobIdentity.pqSignatureKey)
		).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)

		#expect(bob.myPQTurn)
		#expect(!(alice.myPQTurn))
		return (alice, bob)
	}

	/// `SessionTestSupport.establishedDedicated()`'s deployed-shaped
	/// analogue: D is a real, full `TwoMLSIdentity` bundle (never a bare
	/// credential id) — the deployed engine has no invitation-vs-D split,
	/// so its exported `identity` for a dedicated session IS D. Both the
	/// founding leaf and the rule-4 `pending[D]` catch-up entry are the
	/// SAME key (the deployed engine mints exactly one key per party), so
	/// `catchUpKey` reuses `founding.key` rather than a second, independent
	/// mint.
	@available(iOS 26, macOS 26, *)
	private func deployedShapedEstablishedDedicated(
		bob bobName: String = "bob", dedicatedClientID: Data = Data("bob-dedicated".utf8)
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, invitationIdentity: TwoMLSIdentity,
		dIdentity: TwoMLSIdentity
	) {
		let aliceIdentity = try SessionTestSupport.identity("alice")
		let invitationIdentity = try SessionTestSupport.identity(bobName)
		// A born-dedicated principal never joins with its own KP, so both
		// init secrets are cleared immediately — mirrors the native
		// `receive`'s own "never separately read" reasoning, and matters
		// here because `migratedParts(identityOverride:)` embeds this value
		// directly (a live PQ init secret would fail the mint's own gate).
		let dIdentity = try TwoMLSIdentity.generate(
			clientID: dedicatedClientID,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider
		).clearingInitSecrets(classical: true, pq: true)
		let initiated = try TwoMLSSession.initiate(
			identity: aliceIdentity, their: invitationIdentity.keyPackage,
			founding: (
				classical: deployedShapedFounding(
					aliceIdentity.keyPackage.classical,
					secret: aliceIdentity.classicalLeafSecretKey,
					signingKey: aliceIdentity.signingKey,
					signatureKey: aliceIdentity.signatureKey),
				pq: deployedShapedFounding(
					aliceIdentity.keyPackage.pq,
					secret: aliceIdentity.pqLeafSecretKey,
					signingKey: aliceIdentity.pqSigningKey,
					signatureKey: aliceIdentity.pqSignatureKey)
			),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let dFounding = deployedShapedFounding(
			dIdentity.keyPackage.classical, secret: dIdentity.classicalLeafSecretKey,
			signingKey: dIdentity.signingKey, signatureKey: dIdentity.signatureKey)
		let received = try TwoMLSSession.receive(
			identity: invitationIdentity, welcome: initiated.welcome,
			theirClassicalKeyPackage: aliceIdentity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			founding: dFounding, catchUpKey: dFounding.key,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider, newClientID: dedicatedClientID)
		return (
			alice: initiated.session, bob: received.session,
			invitationIdentity: invitationIdentity, dIdentity: dIdentity
		)
	}

	/// A fully-established session pair — post-A.3 bootstrap plus one
	/// complete PQ round (`RatchetTests`' own flow), landing at PQ epoch 2,
	/// quiescent (no inflight/owed state), ledgers and windows populated.
	@available(iOS 26, macOS 26, *)
	private func fullyEstablishedPair() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession
	) {
		var (alice, bob) = try deployedShapedFullyEstablishedTurnOnBob()

		// The full A.4 round (mirrors
		// RatchetTests.testBobInitiatedRatchetRoundAdvancesGroupBPQAndReturnsTurn):
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try #require(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		_ = try bob.pqRatchetBind(ctFrame)
		let prepared = try bob.prepareToEncrypt()
		#expect(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8)).frame
		_ = try alice.processIncomingDecrypted(boundFrame)

		#expect(alice.myPQTurn)
		return (alice: alice, bob: bob)
	}

	/// The strongest expressible equivalence check (SecretArchive exposes no
	/// plaintext byte accessor and `seal` randomizes its nonce): every
	/// `SessionArchive` field compares equal between the minted and the
	/// native body — the group entries and `auth` via their `Equatable`
	/// conformances, the rest field by field.
	@available(iOS 26, macOS 26, *)
	private func assertMintedMatchesNative(
		_ minted: SecretArchive, _ native: SecretArchive, kind: BlobKind
	) throws {
		let mintedBody = try minted.decode(SessionArchive.self)
		let nativeBody = try native.decode(SessionArchive.self)

		#expect(mintedBody.version == nativeBody.version)
		#expect(mintedBody.classicalSuite == nativeBody.classicalSuite)
		#expect(mintedBody.pqSuite == nativeBody.pqSuite)
		#expect(mintedBody.kind == nativeBody.kind)
		#expect(mintedBody.kind == kind)
		#expect(mintedBody.stateSeq == nativeBody.stateSeq)
		#expect(mintedBody.sendPQEpoch == nativeBody.sendPQEpoch)
		#expect(mintedBody.recvPQEpoch == nativeBody.recvPQEpoch)
		#expect(mintedBody.sendClassicalGroupID == nativeBody.sendClassicalGroupID)
		#expect(mintedBody.recvClassicalGroupID == nativeBody.recvClassicalGroupID)

		let mintedIdentity = mintedBody.identity
		let nativeIdentity = nativeBody.identity
		#expect(mintedIdentity.clientID == nativeIdentity.clientID)
		#expect(mintedIdentity.signingKey == nativeIdentity.signingKey)
		#expect(mintedIdentity.signatureKey == nativeIdentity.signatureKey)
		#expect(mintedIdentity.pqSigningKey == nativeIdentity.pqSigningKey)
		#expect(mintedIdentity.pqSignatureKey == nativeIdentity.pqSignatureKey)
		#expect(mintedIdentity.classicalLeafSecretKey == nativeIdentity.classicalLeafSecretKey)
		#expect(mintedIdentity.classicalInitSecretKey == nativeIdentity.classicalInitSecretKey)
		#expect(mintedIdentity.pqLeafSecretKey == nativeIdentity.pqLeafSecretKey)
		#expect(mintedIdentity.pqInitSecretKey == nativeIdentity.pqInitSecretKey)
		#expect(mintedIdentity.classicalKeyPackage == nativeIdentity.classicalKeyPackage)
		#expect(mintedIdentity.pqKeyPackage == nativeIdentity.pqKeyPackage)

		#expect(mintedBody.auth == nativeBody.auth)
		#expect(mintedBody.sendGroup == nativeBody.sendGroup)
		#expect(mintedBody.recvGroup == nativeBody.recvGroup)

		#expect(mintedBody.currentStaple == nativeBody.currentStaple)
		#expect(mintedBody.pendingProposal == nativeBody.pendingProposal)
		#expect(mintedBody.joinedWelcomeDigest == nativeBody.joinedWelcomeDigest)
		#expect(mintedBody.initiated == nativeBody.initiated)
		#expect(mintedBody.bootstrapKPSecret?.leafSecretKey == nativeBody.bootstrapKPSecret?.leafSecretKey)
		#expect(mintedBody.bootstrapKPSecret?.initSecretKey == nativeBody.bootstrapKPSecret?.initSecretKey)
		#expect(mintedBody.bootstrapKPSecret?.keyPackage == nativeBody.bootstrapKPSecret?.keyPackage)
		#expect(mintedBody.expectedBootstrapKPCommitment == nativeBody.expectedBootstrapKPCommitment)
		#expect(mintedBody.pqTurnMine == nativeBody.pqTurnMine)
		#expect(mintedBody.owedBind?.pqCommitMessage == nativeBody.owedBind?.pqCommitMessage)
		#expect(mintedBody.owedBind?.tEpoch == nativeBody.owedBind?.tEpoch)
		#expect(mintedBody.owedBind?.pqEpoch == nativeBody.owedBind?.pqEpoch)
		#expect(mintedBody.pqInflight == nativeBody.pqInflight)
		#expect(mintedBody.pendingSideBand == nativeBody.pendingSideBand)
		#expect(mintedBody.peerAppliedSendEpoch == nativeBody.peerAppliedSendEpoch)
		#expect(mintedBody.lastCrossInjected == nativeBody.lastCrossInjected)
		#expect(mintedBody.lastCrossInjectedPQ == nativeBody.lastCrossInjectedPQ)
		#expect(mintedBody.lastSendPQExported == nativeBody.lastSendPQExported)
		#expect(mintedBody.offeredProposal == nativeBody.offeredProposal)
		#expect(mintedBody.queuedProposal == nativeBody.queuedProposal)
		#expect(mintedBody.stagedUpdates == nativeBody.stagedUpdates)
		#expect(mintedBody.sendCrossPSKLedger.entries.count == nativeBody.sendCrossPSKLedger.entries.count)
		for (epoch, mintedPsk) in mintedBody.sendCrossPSKLedger.entries {
			let nativePsk = try #require(
				nativeBody.sendCrossPSKLedger.entries[epoch])
			#expect(mintedPsk.componentID == nativePsk.componentID)
			#expect(mintedPsk.pskID == nativePsk.pskID)
			#expect(mintedPsk.psk == nativePsk.psk)
		}
		#expect(mintedBody.rotationCandidate?.clientID == nativeBody.rotationCandidate?.clientID)
		#expect(mintedBody.rotationCandidate?.proposedAtRecvEpoch == nativeBody.rotationCandidate?.proposedAtRecvEpoch)
		#expect(mintedBody.spawnToken == nativeBody.spawnToken)
		#expect(mintedBody.listenRendezvous?.entries == nativeBody.listenRendezvous?.entries)
		#expect(mintedBody.recvHeaderKeys?.entries == nativeBody.recvHeaderKeys?.entries)
		#expect(mintedBody.recvHeaderKeysPQ?.entries == nativeBody.recvHeaderKeysPQ?.entries)
		#expect(mintedBody.initialTheirKP?.classical == nativeBody.initialTheirKP?.classical)
		#expect(mintedBody.initialTheirKP?.pq == nativeBody.initialTheirKP?.pq)
		#expect(mintedBody.sendAttachmentLedger?.entries.mapValues { $0.wrappedValue } == nativeBody.sendAttachmentLedger?.entries.mapValues { $0.wrappedValue })
		#expect(mintedBody.recvAttachmentLedger?.entries.mapValues { $0.wrappedValue } == nativeBody.recvAttachmentLedger?.entries.mapValues { $0.wrappedValue })
		#expect(mintedBody.owesEstablishmentEnvelope == nativeBody.owesEstablishmentEnvelope)
		// The temporary conversion must land on exactly the same four
		// stored key sets (current + pending, by target) as the live path's
		// own seeding/staging — this is the direct parity check for "the
		// conversion crosses halves or ignores staged/parked proposals."
		#expect(mintedBody.leafKeys == nativeBody.leafKeys)
		#expect(mintedBody.sendPQKeysFingerprint == nativeBody.sendPQKeysFingerprint)
		#expect(mintedBody.recvPQKeysFingerprint == nativeBody.recvPQKeysFingerprint)
	}

	// MARK: - AC 1: equivalence with the native path

	@available(iOS 26, macOS 26, *)
	@Test func mintedCheckpointDecodesToTheNativeBody() throws {
		let (alice, _) = try fullyEstablishedPair()
		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice, suppliedLeafKeys: true),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)
	}

	@available(iOS 26, macOS 26, *)
	@Test func mintedCoreDecodesToTheNativeBody() throws {
		let (alice, _) = try fullyEstablishedPair()
		let native = try alice.makeSessionArchive(kind: .core)
		let minted = try SessionMigration.mintArchive(
			kind: .core, parts: try migratedParts(alice, suppliedLeafKeys: true),
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
	@available(iOS 26, macOS 26, *)
	@Test func mintDerivesPinsFromRestoredPQTreesAndDropsAStaleLegacyPin() throws {
		let (alice, _) = try fullyEstablishedPair()
		let aliceID = alice.identity.clientID
		var parts = try migratedParts(alice, suppliedLeafKeys: true)
		parts.auth.mine.pinned = [Data("legacy-rust-founding-pin-only".utf8)]
		parts.auth.theirs.pinned = [Data("legacy-rust-founding-pin-only".utf8)]

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let mintedBody = try minted.decode(SessionArchive.self)

		#expect(mintedBody.auth.mine.pinned == [aliceID])
		#expect(!(mintedBody.auth.mine.pinned.contains(
				Data("legacy-rust-founding-pin-only".utf8))))

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
	/// to a matching `recvClassical.pending` entry, not silently drop it:
	/// the direct parity check for "the conversion... ignores staged/
	/// parked proposals" (the classical half; PQ has no resolvable-but-
	/// new-key migrated scenario here). Send-classical never holds a
	/// pending entry — the candidate's key lives in recv-classical only.
	@available(iOS 26, macOS 26, *)
	@Test func mintedMidRotationConvertsStagedUpdateAndLeafKeysMatch() throws {
		var (alice, _, _, _) = try deployedShapedEstablishedAndExchanged()
		let newID = Data("alice-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		#expect(alice.rotationCandidate != nil)
		#expect(!(alice.stagedUpdates.isEmpty))

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)

		let mintedBody = try minted.decode(SessionArchive.self)
		#expect(!(mintedBody.leafKeys.recvClassical.pending.isEmpty), "the staged rotating Upd(self) must convert into recvClassical.pending")
		#expect(mintedBody.leafKeys.sendClassical.pending.isEmpty, "send-classical never holds a pending entry")
	}

	/// The mint's rotation-shape check: a supplied `MigratedRotationCandidate
	/// .signatureKey` that does NOT match the recv-classical `pending` entry
	/// the mint actually keeps for that candidate must be rejected —
	/// `.archiveInvalid`, not silently accepted. Kills: dropping/weakening
	/// this cross-check, or comparing against the wrong (e.g. discarded
	/// send-classical) entry.
	@available(iOS 26, macOS 26, *)
	@Test func mintRejectsRotationCandidateSignatureKeyMismatchingRecvClassical() throws {
		var (alice, _, _, _) = try deployedShapedEstablishedAndExchanged()
		let newID = Data("alice-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		// A supplied `leafKeys` is required to reach the `.mintSupplied`
		// path this check guards — without it, `parts.leafKeys` is nil and
		// the mint takes the unrelated `.mintConverted` fallback instead,
		// which has its own (different) key-consistency checks.
		var parts = try migratedParts(alice)
		parts.leafKeys = migratedLeafKeys(from: alice.leafKeys)
		let candidate = try #require(parts.rotationCandidate)
		let (wrongSigningKey, wrongSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		#expect(wrongSignatureKey.data != candidate.signatureKey)
		parts.rotationCandidate = MigratedRotationCandidate(
			clientID: candidate.clientID,
			signingKey: wrongSigningKey.data,
			signatureKey: wrongSignatureKey.data,
			proposedAtRecvEpoch: candidate.proposedAtRecvEpoch)

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
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
	@available(iOS 26, macOS 26, *)
	@Test func mintedConversionItemCPopulatesTheStagedTargetIndependentlyOfItemA() throws {
		var (alice, _, _, _) = try deployedShapedEstablishedAndExchanged()
		let c = Data("alice-c".utf8)
		_ = try alice.prepareToEncrypt(rotating: c)
		#expect(alice.rotationCandidate != nil)
		let candidateKey = try #require(alice.leafKeys.recvClassical.pending[c])
		#expect(!(alice.stagedUpdates.isEmpty))

		var parts = try migratedParts(alice)
		let cPrime = Data("alice-c-prime".utf8)
		parts.rotationCandidate?.clientID = cPrime

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let mintedBody = try minted.decode(SessionArchive.self)

		let fromItemC = try #require(
			mintedBody.leafKeys.recvClassical.pending.first { $0.target == c })
		let fromItemA = try #require(
			mintedBody.leafKeys.recvClassical.pending.first { $0.target == cPrime })
		#expect(fromItemC.key.signatureKey == candidateKey.signatureKey.data)
		#expect(fromItemA.key.signatureKey == candidateKey.signatureKey.data)
	}

	/// The miss path: with NO outstanding candidate at all (and no
	/// `recvLeafPrincipal`), the staged Upd(C) that item (c) would
	/// otherwise convert can no longer resolve under any of
	/// `lookupClassical`'s three arms — mint must fail closed rather than
	/// silently drop the entry.
	@available(iOS 26, macOS 26, *)
	@Test func mintedConversionRejectsAStagedUpdateWithNoCandidateToResolveIt() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()
		let c = Data("alice-c".utf8)
		_ = try alice.prepareToEncrypt(rotating: c)
		#expect(!(alice.stagedUpdates.isEmpty))

		var parts = try migratedParts(alice)
		parts.rotationCandidate = nil

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	/// A mid-A.4 `.responding` mint: the held `S`/parked CT map, the body
	/// matches the native one, and the restored session completes the round.
	@available(iOS 26, macOS 26, *)
	@Test func mintedMidFlightResponderRoundTripsAndCompletesRound() throws {
		var (alice, bob) = try deployedShapedFullyEstablishedTurnOnBob()
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try #require(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame).frame
		guard case .responding = alice.pqInflight else {
			Issue.record("expected alice to hold `.responding` after sealing")
			return
		}

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice, suppliedLeafKeys: true),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)

		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		_ = try bob.pqRatchetBind(ctFrame)
		let prepared = try bob.prepareToEncrypt()
		#expect(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8)).frame
		let decrypted = try restored.processIncomingDecrypted(boundFrame)
		#expect(decrypted.applicationMessage == Data("bound".utf8))
	}

	// MARK: - Mint parity across more of the rotation/A.3 lifecycle

	/// Mint parity right after the peer folds a rotation offer: recv-
	/// classical has converged (the candidate's key is now `current`), but
	/// send-classical still lags (the outstanding candidate's key is still
	/// only `pending`) — a DIFFERENT point in the lifecycle from the
	/// mid-rotation (staged-but-unfolded) test above.
	@available(iOS 26, macOS 26, *)
	@Test func mintedRotationFoldedMatchesNative() throws {
		var (alice, bob, _, _) = try deployedShapedEstablishedAndExchanged()
		let newID = Data("alice-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		let foldDecrypted = try alice.processIncomingDecrypted(foldFrame)
		#expect(foldDecrypted.ownCredentialCanonicalized)

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
	@available(iOS 26, macOS 26, *)
	@Test func mintedRotationConvergedMatchesNative() throws {
		var (alice, bob, _, _) = try deployedShapedEstablishedAndExchanged()
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
		#expect(catchUpDecrypted.newSender == newID)
		#expect(alice.myPrincipalState == .sync(newID))

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		var parts = try migratedParts(alice)
		parts.leafKeys = migratedLeafKeys(from: alice.leafKeys)
		// `.mintSupplied`'s PQ-lag check requires a `pending[mineCurrent]`
		// catch-up entry on any PQ leaf whose credential lags the rotated
		// id (a single shared identity sequence covers classical and PQ
		// alike) — real here, since alice's classical rotation moved
		// `auth.mine.current` to `newID` while her PQ leaf still presents
		// her original id. No step before the A.5 legs land mints a PQ
		// catch-up key of its own, so this synthesizes one from her
		// existing PQ key — a real migrator in the same shape would supply
		// exactly this (its actual current key, staged for the eventual
		// catch-up) since nothing has minted a distinct PQ successor yet.
		if let sendPQCurrent = alice.leafKeys.sendPQ.current {
			parts.leafKeys?.sendPQ.pending.append(
				MigratedPendingLeafKey(
					target: newID,
					key: MigratedLeafKey(
						signingKey: sendPQCurrent.signingKey.data,
						signatureKey: sendPQCurrent.signatureKey.data)))
		}
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		// Not `assertMintedMatchesNative`: the synthesized sendPQ catch-up
		// entry above has no counterpart in `native` (alice's own live
		// session never staged one — nothing mints a PQ catch-up key
		// before the A.5 legs land), so `leafKeys` genuinely diverges
		// there. Every other field, and both classical sets, still match.
		let mintedBody = try minted.decode(SessionArchive.self)
		let nativeBody = try native.decode(SessionArchive.self)
		#expect(mintedBody.auth == nativeBody.auth)
		#expect(mintedBody.sendGroup == nativeBody.sendGroup)
		#expect(mintedBody.recvGroup == nativeBody.recvGroup)
		#expect(mintedBody.leafKeys.sendClassical == nativeBody.leafKeys.sendClassical)
		#expect(mintedBody.leafKeys.recvClassical == nativeBody.leafKeys.recvClassical)
		#expect(mintedBody.leafKeys.sendPQ?.current == nativeBody.leafKeys.sendPQ?.current)
		#expect(mintedBody.leafKeys.recvPQ == nativeBody.leafKeys.recvPQ)
		#expect(mintedBody.leafKeys.sendClassical.pending.isEmpty, "a converged rotation leaves no outstanding send-classical pending entry")
	}

	/// Mint parity for the pre-A.3 initiator: fully established classically
	/// — Group_A (`sendGroup`, the initiator's own founding pair) already
	/// carries its PQ half, but Group_B (`recvGroup`, classical-only until
	/// the §A.3 bootstrap) does not yet — `recvPQ` converts to its
	/// identity-keyed reservation.
	@available(iOS 26, macOS 26, *)
	@Test func mintedPreA3InitiatorMatchesNative() throws {
		var (alice, _, _, _) = try deployedShapedEstablishedAndExchanged()
		#expect(alice.sendGroup?.pq != nil)
		#expect(alice.recvGroup?.pq == nil)

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
		#expect(restored.recvGroup?.pq == nil)
	}

	/// The mirror image on the acceptor: bob's `recvGroup` (Group_A) already
	/// carries PQ (founded at invitation-accept time), but his `sendGroup`
	/// (Group_B) is still classical-only pre-A.3 — `sendPQ` converts to the
	/// canonical present-but-empty shape: nothing is reserved ahead of A.3
	/// founding.
	@available(iOS 26, macOS 26, *)
	@Test func mintedPreA3AcceptorMatchesNative() throws {
		let (_, bob, _, _) = try deployedShapedEstablishedAndExchanged()
		#expect(bob.recvGroup?.pq != nil)
		#expect(bob.sendGroup?.pq == nil)

		let native = try bob.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(bob, suppliedLeafKeys: true),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.sendGroup?.pq == nil)
		#expect(restored.leafKeys.sendPQ.current == nil)
	}

	/// A deployed-shaped pre-A.3 acceptor's mint+restore never founds
	/// send-PQ, and a NATIVE `pqBootstrapRespond` afterward mints its own
	/// fresh founding key — never a stored or identity key. Two input
	/// shapes both land there (the CLARIFICATION's twin): a `.mintSupplied`
	/// non-nil `sendPQ.current` reservation is dropped without throwing,
	/// and the canonical present-but-empty `.mintConverted` shape is
	/// accepted as-is.
	@available(iOS 26, macOS 26, *)
	@Test func migratedPreA3AcceptorFoundsSendPQOnAFreshKey() throws {
		for suppliedReservation in [false, true] {
			var (alice, bob, aliceIdentity, bobIdentity) =
				try deployedShapedEstablishedAndExchanged(
					alice: "d6-alice-\(suppliedReservation)",
					bob: "d6-bob-\(suppliedReservation)")
			// The `false` arm mints through `convertDeployedKeys`, which
			// stays owner-keyed only — the fixture's own message exchange
			// (needed below to satisfy the non-emittable gate for
			// `pqBootstrapBegin`) leaves bob's OWN unfolded routine offer
			// holding a D3 fresh key no owner-keyed slot explains, unrelated
			// to what this test actually covers (pre-A.3 send-PQ founding).
			// Reset it directly rather than through `.stage`'s collision
			// guard, mirroring `prepareToEncrypt`'s own overwrite rule.
			bob.leafKeys.recvClassical.pending = [:]
			bob.pendingProposal = nil
			bob.stagedUpdates = []
			#expect(bob.sendGroup?.pq == nil)

			var parts = try migratedParts(bob)
			if suppliedReservation {
				func migratedKey(_ key: LeafKey) -> MigratedLeafKey {
					MigratedLeafKey(
						signingKey: key.signingKey.data,
						signatureKey: key.signatureKey.data)
				}
				parts.leafKeys = MigratedLeafKeys(
					sendClassical: MigratedGroupKeys(
						current: migratedKey(
							try #require(
								bob.leafKeys.sendClassical.current))
					),
					recvClassical: MigratedGroupKeys(
						current: migratedKey(
							try #require(
								bob.leafKeys.recvClassical.current))
					),
					// A supplied reservation — must be dropped, never thrown on.
					sendPQ: MigratedGroupKeys(
						current: migratedKey(
							LeafKey(
								signingKey: bobIdentity
									.pqSigningKey,
								signatureKey: bobIdentity
									.pqSignatureKey))),
					recvPQ: MigratedGroupKeys(
						current: migratedKey(
							try #require(bob.leafKeys.recvPQ.current)))
				)
			}
			let minted = try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			var restored = try TwoMLSSession.restore(
				core: nil, checkpoint: minted,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			#expect(restored.leafKeys.sendPQ.current == nil)
			#expect(restored.sendGroup?.pq == nil)

			let kpFrame = try alice.pqBootstrapBegin().frame
			_ = try restored.pqBootstrapRespond(kpFrame)
			let foundedKey = try #require(restored.leafKeys.sendPQ.current)
			let presentedKey = try TwoMLSSession.ownLeaf(
				of: try #require(restored.sendGroup?.pq)
			).signatureKey
			#expect(foundedKey.signatureKey == presentedKey)
			#expect(foundedKey.signatureKey != bobIdentity.pqSignatureKey)
			#expect(foundedKey.signatureKey != restored.identity.pqSignatureKey)
			#expect(foundedKey.signatureKey != aliceIdentity.pqSignatureKey)
			try restored.assertLeafKeysPresented()
		}
	}

	/// Mint parity for the A.3-stalled initiator: the founder has sent its
	/// KP′ and is waiting on the peer's Welcome′ — `bootstrapKPSecret`
	/// held, `pqInflight == .bootstrapInitiated`, `recvGroup.pq` still nil.
	@available(iOS 26, macOS 26, *)
	@Test func mintedA3StalledInitiatorMatchesNative() throws {
		var (alice, _, _, _) = try deployedShapedEstablishedAndExchanged()
		_ = try alice.pqBootstrapBegin()
		#expect(alice.bootstrapKPSecret != nil)
		guard case .bootstrapInitiated = alice.pqInflight else {
			Issue.record("expected alice to hold .bootstrapInitiated after pqBootstrapBegin")
			return
		}
		#expect(alice.recvGroup?.pq == nil)

		let native = try alice.makeSessionArchive(kind: .checkpoint)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		try assertMintedMatchesNative(minted, native, kind: .checkpoint)
	}

	// MARK: - AC 2: restore + use

	/// Book group-rules.md rule 9: the deployed engine never records a
	/// profile, so a migrated session carrying one is refused. Kills:
	/// dropping the mint check.
	@available(iOS 26, macOS 26, *)
	@Test func mintRefusesARecordedSessionProfile() throws {
		for profile in [SessionProfile.correct, .deployedCompatible] {
			let (alice, _) = try SessionTestSupport.establishedAndExchanged(
				alice: "mint-profile-a", bob: "mint-profile-b", profile: profile)
			let mint = {
				try SessionMigration.mintArchive(
					kind: .checkpoint,
					parts: try self.migratedParts(alice, suppliedLeafKeys: true),
					classicalProvider: SessionTestSupport.classicalProvider,
					pqProvider: SessionTestSupport.pqProvider)
			}
			if profile == .correct {
				#expect(throws: TwoMLSError.archiveInvalid) { try mint() }
			} else {
				#expect(throws: Never.self) { try mint() }
			}
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func mintedCheckpointRestoresAndKeepsMessaging() throws {
		var (alice, bob) = try fullyEstablishedPair()
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(alice, suppliedLeafKeys: true),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.isFullyEstablished)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("hello".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(frame)
		#expect(decrypted.applicationMessage == Data("hello".utf8))

		_ = try bob.prepareToEncrypt()
		let reply = try bob.encrypt(Data("hi".utf8)).frame
		let replyDecrypted = try restored.processIncomingDecrypted(reply)
		#expect(replyDecrypted.applicationMessage == Data("hi".utf8))
	}

	/// The responder-side mint: `initiated == false` flips restore's
	/// standard/deferred interpretation of the two halves (Bob's sendGroup is
	/// the classical-only Group_B, his recvGroup the full Group_A).
	@available(iOS 26, macOS 26, *)
	@Test func mintedResponderCheckpointRestoresAndKeepsMessaging() throws {
		var (alice, bob) = try fullyEstablishedPair()
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: try migratedParts(bob, suppliedLeafKeys: true),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.isFullyEstablished)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("from-restored-bob".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(frame)
		#expect(decrypted.applicationMessage == Data("from-restored-bob".utf8))
	}

	/// A supplied send-classical `pending` entry is dropped at mint —
	/// `.core` and `.checkpoint` alike — never carried through into the
	/// minted body. Kills: the mint forwarding a supplied send-classical
	/// pending entry.
	@available(iOS 26, macOS 26, *)
	@Test func mintDropsSuppliedSendClassicalPending() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice, suppliedLeafKeys: true)
		let (smuggledSigningKey, smuggledSignatureKey) =
			try TwoMLSIdentity.mintSignatureKeypair()
		var leafKeys = try #require(parts.leafKeys)
		leafKeys.sendClassical.pending.append(
			MigratedPendingLeafKey(
				target: Data("smuggled".utf8),
				key: MigratedLeafKey(
					signingKey: smuggledSigningKey.data,
					signatureKey: smuggledSignatureKey.data)))
		parts.leafKeys = leafKeys

		for kind: BlobKind in [.core, .checkpoint] {
			let minted = try SessionMigration.mintArchive(
				kind: kind, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			let mintedBody = try minted.decode(SessionArchive.self)
			#expect(mintedBody.leafKeys.sendClassical.pending.isEmpty, "\(kind): a supplied send-classical pending entry must be dropped")
		}
	}

	/// A deployed-shaped party's one classical key, shared across its
	/// send- and recv-classical leaves, diverges at each leaf's own first
	/// native move — the send leaf at its first commit, the recv leaf at
	/// its first fold — never together. PQ divergence (the first A.5) is
	/// deferred to the commit that mints per-move PQ keys.
	@available(iOS 26, macOS 26, *)
	@Test func migratedSharedKeysDivergeAtEachLeafsNextMove() throws {
		var (alice, bob, aliceIdentity, _) = try deployedShapedEstablishedAndExchanged()
		let sharedKey = aliceIdentity.signatureKey
		#expect(alice.leafKeys.sendClassical.current?.signatureKey == sharedKey)
		#expect(alice.leafKeys.recvClassical.current?.signatureKey == sharedKey)

		// The first COMMIT: alice approves and folds bob's routine offer,
		// which diverges her send-classical leaf from the shared key — and,
		// in the same call, mints her own fresh recv-classical offer.
		_ = try bob.prepareToEncrypt()
		let bobOfferFrame = try bob.encrypt(Data("bob-offer".utf8)).frame
		let bobOfferDecrypted = try alice.processIncomingDecrypted(bobOfferFrame)
		_ = try alice.queueProposal(digest: bobOfferDecrypted.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		#expect(foldPrepared.didCommit)
		#expect(alice.leafKeys.sendClassical.current?.signatureKey != sharedKey)
		#expect(alice.leafKeys.recvClassical.current?.signatureKey == sharedKey, "recv-classical has not folded yet")

		// The first FOLD: bob approves and folds alice's own offer (minted
		// above), which diverges her recv-classical leaf too.
		let aliceFrame = try alice.encrypt(Data("alice-offer".utf8)).frame
		let aliceOfferDecrypted = try bob.processIncomingDecrypted(aliceFrame)
		_ = try bob.queueProposal(digest: aliceOfferDecrypted.queuedProposal.digest)
		let bobFoldPrepared = try bob.prepareToEncrypt()
		#expect(bobFoldPrepared.didCommit)
		let bobFoldFrame = try bob.encrypt(Data("bob-fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobFoldFrame)
		#expect(alice.leafKeys.recvClassical.current?.signatureKey != sharedKey)
	}

	// MARK: - AC 4: spent/edge — pre-establishment initiator

	/// A pre-establishment initiator (`recvGroup == nil`) mints with its
	/// classical init secret carried, restores, and COMPLETES establishment —
	/// the full mid-establishment restore flow a migrated session needs.
	@available(iOS 26, macOS 26, *)
	@Test func mintedPreEstablishmentInitiatorCompletesEstablishment() throws {
		// Deployed-shaped: founds Group_A on alice's own
		// already-signed KP leaves directly, rather than the public
		// `initiate(principal:their:)`'s fresh founding leaves — this test
		// exercises the converter's owner-keyed shape, matching a genuine
		// deployed session.
		let aliceIdentity = try SessionTestSupport.identity("alice")
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try #require(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			identity: aliceIdentity, their: theirKP,
			founding: (
				classical: deployedShapedFounding(
					aliceIdentity.keyPackage.classical,
					secret: aliceIdentity.classicalLeafSecretKey,
					signingKey: aliceIdentity.signingKey,
					signatureKey: aliceIdentity.signatureKey),
				pq: deployedShapedFounding(
					aliceIdentity.keyPackage.pq,
					secret: aliceIdentity.pqLeafSecretKey,
					signingKey: aliceIdentity.pqSigningKey,
					signatureKey: aliceIdentity.pqSignatureKey)
			),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let parts = try migratedParts(initiated.session)
		#expect(parts.identity.classicalInitSecretKey != nil)
		#expect(parts.identity.pqInitSecretKey == nil)
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
		#expect(!(restored.isEstablished))

		let envelope = try restored.pendingOutbound()
		guard case .establishment(let frame) = try invitation.openInitial(envelope)
		else {
			Issue.record("expected .establishment")
			return
		}
		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try #require(frame.returnKeyPackage))
		let received = try invitation.receive(
			welcome: try #require(frame.welcome),
			theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try restored.bootstrapKPCommitment(),
			spawnToken: SessionTestSupport.classicalProvider.randomBytes(16))
		var bob = received.session
		#expect(bob.isEstablished)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try restored.processIncomingDecrypted(bobFrame)
		#expect(restored.isEstablished)
		#expect(decrypted.applicationMessage == Data("bob-hello".utf8))
	}

	// MARK: - Windows: safe-to-empty vs must-carry

	/// The three re-derivable windows may mint EMPTY — restore re-captures
	/// the current epoch's entries at once (only the retained past-epoch
	/// entries are lost, the documented scope choice).
	@available(iOS 26, macOS 26, *)
	@Test func emptyDerivableWindowsMintAndRestore() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice, suppliedLeafKeys: true)
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
		#expect(restored.listenRendezvous.count == 1)
		#expect(restored.recvHeaderKeys.count == 1)
		#expect(restored.recvHeaderKeysPQ.count == 1)
	}

	/// The attachment ledgers are NOT safe to empty: the live path consumes
	/// the current epoch's `0xFF03` exporter leaf at group creation, so
	/// restore's re-capture of a ledger missing that epoch throws — the mint
	/// (whose trial restore runs the same capture) must reject it loudly.
	@available(iOS 26, macOS 26, *)
	@Test func emptyAttachmentLedgerIsRejectedAtMint() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice, suppliedLeafKeys: true)
		parts.sendAttachmentLedger = [:]

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	// MARK: - AC 3: mutation-verify

	/// Book `wire-format.md`: every occupied leaf of the restored trees —
	/// and either half of a retained `initialTheirKP` — must advertise the
	/// `APQInfo` extension and the `AppDataUpdate` proposal, or mint
	/// refuses with `.archiveInvalid`.
	@available(iOS 26, macOS 26, *)
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

	/// Computed, not stored: `TwoMLSSuite` is gated to iOS/macOS 26, so it
	/// cannot back a stored `static let` in this ungated suite — see
	/// `CombinerKeyPackageWireTests.makeIdentity()`'s stored-property
	/// workaround for the same restriction.
	@available(iOS 26, macOS 26, *)
	private static var rogueCapabilities: MLS.RFC9420.Capabilities {
		MLS.RFC9420.Capabilities(
			versions: [.mls10], cipherSuites: [TwoMLSSuite.classical, TwoMLSSuite.pq],
			extensions: [], proposals: [], credentials: [MLS.RFC9420.CredentialType(.basic)])
	}

	/// Each half checked independently: a rogue CLASSICAL half with a
	/// well-capable PQ one still throws, and vice versa.
	@available(iOS 26, macOS 26, *)
	@Test func capabilityLessInitialTheirKPIsRejectedAtMint() throws {
		let (alice, _) = try fullyEstablishedPair()
		let wellCapableKP = try rogueKeyPackage(
			named: "well-capable-their-kp",
			capabilities: TwoMLSIdentity.leafCapabilities)
		let rogueKP = try rogueKeyPackage(
			named: "rogue-their-kp", capabilities: Self.rogueCapabilities)

		var classicalRogueParts = try migratedParts(alice, suppliedLeafKeys: true)
		classicalRogueParts.initialTheirKP = (
			classical: try rogueKP.mlsEncoded(), pq: try wellCapableKP.mlsEncoded()
		)
		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: classicalRogueParts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }

		var pqRogueParts = try migratedParts(alice, suppliedLeafKeys: true)
		pqRogueParts.initialTheirKP = (
			classical: try wellCapableKP.mlsEncoded(), pq: try rogueKP.mlsEncoded()
		)
		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: pqRogueParts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	@available(iOS 26, macOS 26, *)
	@Test func corruptedClassicalSigningKeyIsRejectedAtMint() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice, suppliedLeafKeys: true)
		parts.identity.signingKey = SecretBytes(randomByteCount: 32)

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	/// A VALID but different ML-KEM leaf secret — one that passes the 96-B
	/// integrity check — is rejected by the derived-public vs KeyPackage
	/// comparison, which is the check that actually catches a mis-mapped key.
	@available(iOS 26, macOS 26, *)
	@Test func validButWrongPqLeafSecretIsRejectedAtMint() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice, suppliedLeafKeys: true)
		let (wrongSecret, _) = try SessionTestSupport.pqProvider.hpkeGenerateKeyPair()
		parts.identity.pqLeafSecretKey = wrongSecret.data

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	/// Swapping the classical leaf and init secrets (two VALID X25519 keys)
	/// is rejected — the half-swap mis-mapping this minter exists to catch.
	/// Needs the pre-establishment fixture (the only state where an init
	/// secret is supplied at all).
	@available(iOS 26, macOS 26, *)
	@Test func swappedClassicalLeafAndInitSecretsAreRejectedAtMint() throws {
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
			their: try #require(invitation.combinerKeyPackage))
		var parts = try migratedParts(initiated.session)
		let leaf = parts.identity.classicalLeafSecretKey
		parts.identity.classicalLeafSecretKey =
			try #require(parts.identity.classicalInitSecretKey)
		parts.identity.classicalInitSecretKey = leaf

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	/// An init secret supplied for an ESTABLISHED session — the native path
	/// can never produce one (`includeInitSecrets: recvGroup == nil`) — is
	/// rejected at mint.
	@available(iOS 26, macOS 26, *)
	@Test func initSecretSuppliedForEstablishedSessionIsRejected() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice, suppliedLeafKeys: true)
		parts.identity.classicalInitSecretKey = SecretBytes(randomByteCount: 32)

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	/// A PQ init secret is rejected even for a pre-establishment initiator —
	/// the native path clears it at `initiate` before any archive can exist.
	/// The gate fires BEFORE the identity cross-checks (which a correctly
	/// mapped legacy PQ init secret would otherwise pass), so the rejection
	/// is the gate's regardless of the supplied value's validity — hence a
	/// freshly generated key suffices here.
	@available(iOS 26, macOS 26, *)
	@Test func pqInitSecretIsAlwaysRejected() throws {
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
			their: try #require(invitation.combinerKeyPackage))
		var parts = try migratedParts(initiated.session)
		let (pqInitSecret, _) = try SessionTestSupport.pqProvider.hpkeGenerateKeyPair()
		parts.identity.pqInitSecretKey = pqInitSecret.data

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	/// A topology violation — no recv group with `initiated == false` — is
	/// rejected at mint (no native path produces it: the responder's
	/// `receive` always sets its recv group). NOTE the mirror mis-mapping —
	/// swapping the two halves' snapshots on an ESTABLISHED session — is
	/// deliberately NOT tested as a rejection: both topologies are internally
	/// self-consistent (the pair-identity checks are per-pair, custody is
	/// symmetric), so no mint-time signal distinguishes them. The migrator's
	/// own send/recv mapping discipline is what prevents that one.
	@available(iOS 26, macOS 26, *)
	@Test func responderTopologyWithoutRecvGroupIsRejected() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice, suppliedLeafKeys: true)
		parts.initiated = false
		parts.recvGroup = nil

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	/// The standard (full-combiner) pair's PQ snapshot is mandatory —
	/// `restoreStandardPair` fail-closes on its absence.
	@available(iOS 26, macOS 26, *)
	@Test func standardHalfWithoutPQSnapshotIsRejected() throws {
		let (alice, _) = try fullyEstablishedPair()
		var parts = try migratedParts(alice, suppliedLeafKeys: true)
		parts.sendGroup.pq = nil

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	/// A provider that doesn't back its suite is `.cipherSuiteMismatch`
	/// (the `TwoMLSIdentity.generate` precedent), not a profile-internal
	/// snapshot error.
	@available(iOS 26, macOS 26, *)
	@Test func wrongSuiteProviderIsRejected() throws {
		let (alice, _) = try fullyEstablishedPair()
		let wrongProvider = SwiftCryptoProvider().cipherSuiteProvider(for: .p256Aes128)!

		#expect(throws: TwoMLSError.cipherSuiteMismatch) { try SessionMigration.mintArchive(
				kind: .checkpoint,
				parts: try migratedParts(alice, suppliedLeafKeys: true),
				classicalProvider: wrongProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	// MARK: - Reconcile: a minted Core + Checkpoint pair restores as one

	/// Both kinds mint from ONE parts set (the migrator's actual usage) and
	/// the pair reconciles: the newer Core wins the stateSeq comparison and
	/// splices the Checkpoint's PQ halves in — the minted core's only
	/// consumer path, since a Core alone is never restorable.
	@available(iOS 26, macOS 26, *)
	@Test func mintedCoreAndCheckpointPairReconcilesAndMessages() throws {
		var (alice, bob) = try fullyEstablishedPair()
		let parts = try migratedParts(alice, suppliedLeafKeys: true)

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
		#expect(restored.isFullyEstablished)
		#expect(restored.stateSeq == 6)

		_ = try restored.prepareToEncrypt()
		let frame = try restored.encrypt(Data("paired".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(frame)
		#expect(decrypted.applicationMessage == Data("paired".utf8))
	}

	// MARK: - Custody arms: born-dedicated recvLeafPrincipal

	/// The born-dedicated acceptor (`SessionTestSupport.establishedDedicated`):
	/// Bob's session identity is the dedicated principal D while his
	/// Group_A leaves still present the INVITATION identity — custody
	/// resolves through `recvLeafPrincipal`, so the parts must carry it, and
	/// the minted archive must restore with that custody intact. No messaging
	/// leg here: Bob cannot send until the signed handoff envelope is
	/// installed and approved, and Alice isn't established until his first
	/// frame — that full flow is BornDedicatedTests' territory; the custody
	/// arms (and their negative, next test) are what this file must prove.
	/// Also the conversion case where Group_A.pq (bob's `recvGroup.pq`) is a
	/// full pair from construction — no A.3 bootstrap needed for THIS half
	/// — so it already EXISTS at mint time, and its own leaf still presents
	/// the INVITATION identity's PQ key (nothing catches PQ up to D at mint time). `lookupPQ` must resolve it via `recvLeafPrincipal`'s PQ
	/// slot, not `identity`'s (which is D) — the explicit `recvPQ.current`
	/// check below, against both the minted archive directly and the
	/// restored session, is the direct proof: it fails if that resolution
	/// is wrong.
	@available(iOS 26, macOS 26, *)
	@Test func mintedBornDedicatedAcceptorRestoresWithCustodyIntact() throws {
		let established = try deployedShapedEstablishedDedicated(bob: "bob-d")
		let bob = established.bob
		#expect(bob.owesEstablishmentEnvelope)
		// `bob.identity` stays the invitation bundle throughout (never
		// replaced with D's), so it IS the retained recv-leaf custody the
		// migrator must supply explicitly.
		let invitationCustody = bob.identity
		#expect(established.dIdentity.clientID != invitationCustody.clientID)
		#expect(bob.recvGroup?.pq != nil, "Group_A.pq already exists at mint time")
		#expect(bob.leafKeys.recvPQ.current?.signatureKey == invitationCustody.pqSignatureKey, "recv-PQ still presents the invitation identity's key, not D's")

		let migratedCustody = MigratedRecvLeafPrincipal(
			clientID: invitationCustody.clientID,
			signingKey: invitationCustody.signingKey.data,
			signatureKey: invitationCustody.signatureKey.data,
			pqSigningKey: invitationCustody.pqSigningKey.data,
			pqSignatureKey: invitationCustody.pqSignatureKey.data)
		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint,
			parts: try migratedParts(
				bob, identityOverride: established.dIdentity,
				recvLeafPrincipal: migratedCustody),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let mintedBody = try minted.decode(SessionArchive.self)
		#expect(mintedBody.leafKeys.recvPQ?.current?.signatureKey == invitationCustody.pqSignatureKey.data, "minted recvPQ.current must resolve via the retained custody's PQ slot, not identity's (D's)")

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.leafKeys.recvPQ.current?.signatureKey == invitationCustody.pqSignatureKey, "restored recvPQ.current must still present the invitation identity's PQ key")
		#expect(restored.identity.clientID == established.dIdentity.clientID)
		#expect(restored.owesEstablishmentEnvelope)
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
	@available(iOS 26, macOS 26, *)
	@Test func mintedOneSidedRotationResolvesSendPQToTheOriginalKey() throws {
		// Both PQ halves already exist, idle, turn on bob — reusing this
		// fixture (rather than hand-driving §A.3) starts past the PQ
		// bootstrap/ratchet entirely, so the classical rotation driven below
		// is the only PQ-adjacent thing this test needs to reason about.
		var (alice, bob) = try deployedShapedFullyEstablishedTurnOnBob()

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
		#expect(catchUpDecrypted.newSender == newID)
		#expect(alice.myPrincipalState == .sync(newID))
		#expect(alice.rotationCandidate != nil, "convergence doesn't clear the candidate")
		#expect(try TwoMLSSession.ownLeaf(of: alice.sendGroup!.pq!).signatureKey == alice.identity.pqSignatureKey, "send-PQ never moved off alice's original PQ key")

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
		// D3: alice's rotate+catch-up round above (same shape as
		// `testMintedRotationConvergedMatchesNative`) leaves a dangling
		// recv-classical routine-offer key `convertDeployedKeys`'s
		// owner-keyed lookup cannot explain — supply real `leafKeys`
		// directly instead (still proves the PQ claim below: it reads
		// alice's own live, never-moved send-PQ key, identity/
		// recvLeafPrincipal overrides notwithstanding).
		parts.leafKeys = migratedLeafKeys(from: alice.leafKeys)
		// `.mintSupplied`'s PQ-lag check needs a `pending[mineCurrent]`
		// catch-up entry on the send-PQ leaf, which still presents alice's
		// original id — see the identical note in
		// `testMintedRotationConvergedMatchesNative`.
		if let sendPQCurrent = alice.leafKeys.sendPQ.current {
			parts.leafKeys?.sendPQ.pending.append(
				MigratedPendingLeafKey(
					target: newID,
					key: MigratedLeafKey(
						signingKey: sendPQCurrent.signingKey.data,
						signatureKey: sendPQCurrent.signatureKey.data)))
		}
		// This fixture also founds recv-PQ (unlike the other test), so it
		// lags the rotated id too — same synthetic catch-up entry.
		if let recvPQCurrent = alice.leafKeys.recvPQ.current {
			parts.leafKeys?.recvPQ.pending.append(
				MigratedPendingLeafKey(
					target: newID,
					key: MigratedLeafKey(
						signingKey: recvPQCurrent.signingKey.data,
						signatureKey: recvPQCurrent.signatureKey.data)))
		}

		let minted = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let mintedBody = try minted.decode(SessionArchive.self)
		#expect(mintedBody.leafKeys.sendPQ?.current?.signatureKey == oldPQSignatureKey.data)
		#expect(mintedBody.leafKeys.sendPQ?.current?.signatureKey != freshN.pqSignatureKey.data)

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
		#expect(restored.leafKeys.sendPQ.current?.signingKey.data == oldPQSigningKey.data, "owePQBind reads exactly this slot, so this IS the old-key proof")
	}

	/// The negative arm: dropping `recvLeafPrincipal` from a born-dedicated
	/// acceptor's parts leaves the invitation-keyed leaves unresolvable —
	/// the custody check (not the trial restore) must catch it at mint.
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedPartsMissingRecvLeafPrincipalIsRejected() throws {
		let established = try SessionTestSupport.establishedDedicated(bob: "bob-d")
		var parts = try migratedParts(established.bob)
		parts.recvLeafPrincipal = nil

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	// MARK: - Migration inputs on stored per-group signing keys

	/// Converts a LIVE `leafKeys` value 1:1 to `MigratedLeafKeys` — used
	/// only by tests that hand-stage a key `convertDeployedKeys` could
	/// never discover on its own (a window offer's target, never framed
	/// into `stagedUpdates`), so they supply it directly instead of relying
	/// on the temporary owner-keyed conversion.
	@available(iOS 26, macOS 26, *)
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
	@available(iOS 26, macOS 26, *)
	private func handBuiltOwnOffer(in session: inout TwoMLSSession) throws -> (
		ref: Data, bareProposal: Data, epoch: UInt64, groupID: Data, senderLeafIndex: UInt32
	) {
		var mirror = try #require(session.recvGroup)
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
		// `promoted()` can find it. Assigned directly, not via `stage`: a
		// routine offer now mints fresh too (D3), so an earlier real offer
		// (from the fixture's own establishment exchange) may already hold
		// a DIFFERENT key at this same target. Its `stagedUpdates`/
		// `pendingProposal` entry is stale the moment `pending` is
		// overwritten here — cleared too, so check 6 has nothing orphaned
		// to explain; this offer is deliberately NOT re-appended there (see
		// the doc above).
		session.leafKeys.recvClassical.pending[session.identity.clientID] =
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey)
		session.stagedUpdates = []
		session.pendingProposal = nil
		guard case .publicMessage(let updatePub) = message else {
			Issue.record("expected a publicMessage-framed Update")
			throw TwoMLSError.malformedSideBandMessage
		}
		var scratchStore = MLS.RFC9420.ProposalStore()
		let verified = try mirror.classical.verifying(
			SessionTestSupport.classicalProvider, proposal: updatePub)
		let ref = try scratchStore.insert(verified, SessionTestSupport.classicalProvider)
		guard case .proposal(let bareProposal) = updatePub.content.content else {
			Issue.record("expected a proposal-carrying PublicMessage")
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
	@available(iOS 26, macOS 26, *)
	@Test func mintArchiveAndMintOwnOfferWindowAgreeOnTheWindowID() throws {
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
		let recordID = try #require(archiveBody.deployedCarry?.ownOfferWindow?.id)
		#expect(recordID.count == 32)

		let mintedWindow = try SessionMigration.mintOwnOfferWindow(
			window, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider)
		#expect(mintedWindow.id == recordID)
	}

	/// An empty `offers` array is `.archiveInvalid` in both mints (A.2's
	/// "an empty window ⇒ .archiveInvalid in both mints").
	@available(iOS 26, macOS 26, *)
	@Test func emptyOwnOfferWindowIsRejectedByBothMints() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let recv = try #require(bob.recvGroup)
		let window = MigratedOwnOfferWindow(
			epoch: recv.classical.context.epoch,
			groupID: recv.classical.context.groupID,
			senderLeafIndex: recv.classical.myLeafIndex.value, offers: [])
		let parts = try migratedParts(bob)

		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider,
				deployedState: MigratedDeployedState(ownOffers: window)) }
		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintOwnOfferWindow(
				window, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider) }
	}

	/// The id function's own coverage, directly: two windows differing only
	/// in one offer's proposal bytes (same ref, epoch, group, sender leaf
	/// index) must hash to different ids. What this pins down is "the id
	/// function drops the proposal bytes or the sort" — dropping the
	/// proposal bytes from the hash is exactly what
	/// would make this assertion fail while leaving every mint-level test
	/// (which also rejects the tampered proposal on STRUCTURAL grounds,
	/// independent of the id) still passing.
	@available(iOS 26, macOS 26, *)
	@Test func theIDFunctionCoversTheProposalBytes() throws {
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
		#expect(idA != idB)
	}

	/// A single flipped proposal byte changes the id (so a load elsewhere
	/// fails `.archiveInvalid` on the recompute-and-compare) — the direct
	/// negative for the id function actually covering the proposal bytes.
	@available(iOS 26, macOS 26, *)
	@Test func flippingAProposalByteChangesTheWindowID() throws {
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
		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintOwnOfferWindow(
				tampered, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider) }
		#expect(throws: Never.self) { try SessionMigration.mintOwnOfferWindow(
				genuine, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider) }
	}

	/// The other half of the id function's coverage: `canonicalOrder`'s own
	/// sort. Minting the SAME set of offers in two different input orders
	/// must produce the same window id and a byte-identical archive — the
	/// id (and the wire shape) depends only on the offer SET, never on the
	/// order a migrator happened to enumerate them in.
	@available(iOS 26, macOS 26, *)
	@Test func mintingTheSameOffersInDifferentInputOrdersProducesIdenticalWindows() throws {
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

		#expect(forward.id == shuffled.id)
		let forwardBody = try forward.archive.decode(OwnOfferWindowArchive.self)
		let shuffledBody = try shuffled.archive.decode(OwnOfferWindowArchive.self)
		#expect(forwardBody.refs == shuffledBody.refs)
		#expect(forwardBody.proposalLengths == shuffledBody.proposalLengths)
		#expect(forwardBody.proposals == shuffledBody.proposals)
		#expect(forwardBody.leafSecrets.withUnsafeBytes { Data($0) } == shuffledBody.leafSecrets.withUnsafeBytes { Data($0) })
	}

	/// Generalized catch-up, `.mintSupplied`: every existing own leaf whose
	/// credential lags `auth.mine.current` needs `pending[mine.current]` in
	/// that group, and a caller that supplies it is accepted (subsuming the
	/// prior rotation/born-dedicated-only cases) — recv-classical and both
	/// PQ groups. Send-classical is the one exception — it never holds
	/// a `pending` entry, so a supplied one there is silently dropped at
	/// mint rather than carried through to restore.
	@available(iOS 26, macOS 26, *)
	@Test func mintSuppliedLeafKeysSatisfyTheGeneralizedCatchUpRuleAcrossAllFourGroups() throws {
		// Needs both PQ halves genuinely established (not the reservation
		// shape from before A.3, which requires an EMPTY pending) so a
		// non-empty PQ `pending` is check 3's "existing group" arm, not
		// rule 4's reservation arm.
		let (_, bob) = try deployedShapedFullyEstablishedTurnOnBob()
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
			// Supplied anyway, to prove the mint drops it rather than
			// throwing or carrying it through.
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
		#expect(restored.leafKeys.sendClassical.pending.isEmpty)
		#expect(restored.leafKeys.recvClassical.pending[newID]?.signatureKey.data == freshSignatureKey.data)
		#expect(restored.leafKeys.sendPQ.pending[newID]?.signatureKey.data == freshSignatureKey.data)
		#expect(restored.leafKeys.recvPQ.pending[newID]?.signatureKey.data == freshSignatureKey.data)
	}

	/// "A rotation Rust won" — `mine.current` moved to `c` but
	/// BOTH classical own leaves still present the old id, `pending[c]`
	/// staged on both, no `rotationCandidate` — the shape a Rust-side
	/// rotation's export leaves for a migrated session. Built through the
	/// MINT (the production path), reusing this suite's own generalized-
	/// catch-up fixture, rather than poking a live session's fields
	/// directly. Kills the revert to the old candidate-based send-catch-up
	/// predicate (half 1b) and, together with
	/// `BornDedicatedTests.testGeneralizedCatchUpReadsOnlyLeafKeys`, the
	/// recv-side revert (half 1a) in this non-born-dedicated shape too.
	@available(iOS 26, macOS 26, *)
	@Test func rustWonRotationCatchesUpBothClassicalLeaves() throws {
		var (alice, bob) = try deployedShapedFullyEstablishedTurnOnBob()
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
		#expect(restoredBob.rotationCandidate == nil)

		// `alice` is a live, un-migrated session: the send-catch-up commit
		// below lands as a fold, not a queued-and-authorized offer, so her
		// own AS needs `c` already reachable in her tracked view of bob —
		// exactly what a real peer would already hold, having seen the
		// Rust-side rotation for real before bob ever migrated.
		alice.auth.theirs.history.append(c)

		let prepared = try restoredBob.prepareToEncrypt()
		#expect(prepared.didCommit, "the licensed send-classical catch-up (1b)")
		#expect(restoredBob.pendingProposal?.proposing == c, "the staged recv-classical catch-up offer (1a)")
		#expect(try basicIdentifier(
				TwoMLSSession.ownLeaf(
					of: #require(restoredBob.sendGroup?.classical)
				)
				.credential) == c)

		let frame = try restoredBob.encrypt(Data("bob-catchup".utf8)).frame
		let aliceSaw = try alice.processIncomingDecrypted(frame)
		#expect(aliceSaw.didApplyRemoteCommit, "1b, mirrored at alice")
		#expect(aliceSaw.queuedProposal.proposing == c, "1a's offer, surfaced")

		try alice.queueProposal(digest: aliceSaw.queuedProposal.digest)
		let aliceFolded = try alice.prepareToEncrypt()
		#expect(aliceFolded.didCommit)
		let foldFrame = try alice.encrypt(Data("alice-fold".utf8)).frame
		let bobApplied = try restoredBob.processIncomingDecrypted(foldFrame)
		#expect(bobApplied.didApplyRemoteCommit, "1a lands at bob")
		#expect(try basicIdentifier(
				TwoMLSSession.ownLeaf(
					of: #require(restoredBob.recvGroup?.classical)
				)
				.credential) == c)
	}

	/// The generalized catch-up's `.mintSupplied`-only PQ enforcement: a born-dedicated bob
	/// before A.3 has `recvGroup.pq` (Group_A is the standard pair, so it
	/// exists from birth) still presenting the INVITATION identity's PQ
	/// key while `auth.mine.current` is already D — a PQ lag
	/// `.mintConverted` tolerates (native sessions mint no PQ catch-up key
	/// until a later step; `testMintedBornDedicatedAcceptorRestoresWithCustodyIntact`
	/// pins exactly this) but `.mintSupplied` must enforce once the caller
	/// is on the hook for rule 7's PQ arm.
	@available(iOS 26, macOS 26, *)
	@Test func mintSuppliedModeRequiresThePQCatchUpKeyThatMintConvertedTolerates() throws {
		let established = try deployedShapedEstablishedDedicated(bob: "bob-d")
		let bob = established.bob
		let dIdentity = established.dIdentity
		// `bob.identity` stays the invitation bundle throughout — see
		// `testMintedBornDedicatedAcceptorRestoresWithCustodyIntact`.
		let invitationCustody = bob.identity
		let migratedCustody = MigratedRecvLeafPrincipal(
			clientID: invitationCustody.clientID,
			signingKey: invitationCustody.signingKey.data,
			signatureKey: invitationCustody.signatureKey.data,
			pqSigningKey: invitationCustody.pqSigningKey.data,
			pqSignatureKey: invitationCustody.pqSignatureKey.data)
		let parts = try migratedParts(
			bob, identityOverride: dIdentity, recvLeafPrincipal: migratedCustody)

		// `.mintConverted` (parts.leafKeys == nil): tolerated.
		#expect(throws: Never.self) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }

		// `.mintSupplied`, mirroring conversion's own shape everywhere
		// EXCEPT the recv-PQ catch-up key: rejected.
		let dClassicalKey = MigratedLeafKey(
			signingKey: dIdentity.signingKey.data,
			signatureKey: dIdentity.signatureKey.data)
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
						target: dIdentity.clientID, key: dClassicalKey)
				]),
			// The canonical pre-A.3 empty shape.
			sendPQ: MigratedGroupKeys(current: nil),
			// No `pending[D]` here — the missing catch-up key.
			recvPQ: MigratedGroupKeys(current: invitationPQKey))
		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: suppliedParts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider) }
	}

	/// Archive keys 44/45 round-trip a no-custody classical role and a PQ
	/// wedge through restore, and the three read-only queries
	/// read them back correctly.
	@available(iOS 26, macOS 26, *)
	@Test func deployedCarryRoundTripsNoCustodyAndWedgeThroughRestore() throws {
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
		// `establishedAndExchanged`'s own routine offer (D3: a fresh,
		// untracked key) is irrelevant noise for this synthetic
		// deployed-carry shape, and check 6 can't explain it against the
		// identity-only `leafKeys` above — drop it.
		parts.pendingProposal = nil
		parts.stagedUpdates = []

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
		#expect(restored.noCustody == [.sendClassical])
		#expect(restored.pqSideBandWedged)
		#expect(!(restored.canSend), "no-custody on a classical role blocks canSend")
		#expect(throws: TwoMLSError.leafCustodyUnavailable) { try restored.sendClassicalSigningKey() }
	}
}

// MARK: - Own-offer window sampling and cap edges

extension SessionMigrationTests {
	@available(iOS 26, macOS 26, *)
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

	@available(iOS 26, macOS 26, *)
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
	@available(iOS 26, macOS 26, *)
	@Test func samplingCoversSeededExtras() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let g = try knownSecretOffers(200, in: bob)
		let sorted = try OwnOfferWindow.canonicalOrder(g.offers)
		let id = OwnOfferWindow.id(
			epoch: g.epoch, groupID: g.groupID, senderLeafIndex: g.leaf, sorted: sorted)
		let sample = OwnOfferWindow.sampledOfferIndices(count: 200, idSeed: id)
		#expect(sample.count == 128)
		#expect(Array(sample.prefix(64)) == Array(0..<64), "the first 64 always sampled")
		let extra = try #require(sample.dropFirst(64).first)
		let unsampled = try #require((64..<200).first { !sample.contains($0) })

		let parts = try migratedParts(bob)
		func mint(_ offers: [MigratedOwnOffer]) throws -> MintedOwnOfferWindow {
			try SessionMigration.mintOwnOfferWindow(
				MigratedOwnOfferWindow(
					epoch: g.epoch, groupID: g.groupID, senderLeafIndex: g.leaf,
					offers: offers),
				parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider)
		}
		#expect(try mint(g.offers).id == id, "control: the genuine window mints")

		var badExtra = g.offers
		badExtra[extra] = withBadSecret(badExtra[extra])
		#expect(throws: TwoMLSError.archiveInvalid, "a seeded extra (index \(extra)) must be trialed") { try mint(badExtra) }
		var badFirst = g.offers
		badFirst[10] = withBadSecret(badFirst[10])
		#expect(throws: TwoMLSError.archiveInvalid, "an offer in the first 64 must be trialed") { try mint(badFirst) }
		var badUnsampled = g.offers
		badUnsampled[unsampled] = withBadSecret(badUnsampled[unsampled])
		#expect(throws: Never.self, "the bounded sample never trials an unsampled offer (index \(unsampled))") { try mint(badUnsampled) }
	}

	/// Items 7a/7b: `validate(cap:)`'s edge — the count equal to the cap is
	/// accepted, one more than the cap is rejected.
	@available(iOS 26, macOS 26, *)
	@Test func windowCapEdge() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let g = try knownSecretOffers(5, in: bob)
		let group = try #require(bob.recvGroup).classical
		func validate(_ n: Int, cap: Int) throws {
			_ = try OwnOfferWindow.validate(
				MigratedOwnOfferWindow(
					epoch: g.epoch, groupID: g.groupID, senderLeafIndex: g.leaf,
					offers: Array(g.offers.prefix(n))),
				recvClassical: group, myLeafIndex: group.myLeafIndex, cap: cap,
				provider: SessionTestSupport.classicalProvider)
		}
		#expect(throws: Never.self, "count == cap accepted") { try validate(4, cap: 4) }
		#expect(throws: TwoMLSError.archiveInvalid, "count == cap + 1 rejected") { try validate(5, cap: 4) }
	}

	@available(iOS 26, macOS 26, *)
	private func mintedWithWindow() throws -> (bob: TwoMLSSession, archive: SecretArchive) {
		let (_, bob, _, _) = try deployedShapedEstablishedAndExchanged()
		let g = try knownSecretOffers(1, in: bob)
		let parts = try migratedParts(bob, suppliedLeafKeys: true)
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

	@available(iOS 26, macOS 26, *)
	private func restorePatched(
		_ archive: SecretArchive, _ patch: (inout OwnOfferWindowRecord) -> Void
	) throws -> TwoMLSSession {
		var body = try archive.decode(SessionArchive.self)
		var record = try #require(body.deployedCarry?.ownOfferWindow)
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
	@available(iOS 26, macOS 26, *)
	@Test func restoreRejectsBadWindowRecord() throws {
		let m = try mintedWithWindow()
		#expect(try restorePatched(m.archive) { _ in }.ownOfferWindow != nil, "control")
		#expect(throws: TwoMLSError.archiveInvalid) { try restorePatched(m.archive) { $0.epoch += 1 } }
		#expect(throws: TwoMLSError.archiveInvalid) { try restorePatched(m.archive) { $0.epoch -= 1 } }
		#expect(throws: Never.self) { try restorePatched(m.archive) {
				$0.count = UInt32(MigratedOwnOfferWindow.maximumOfferCount)
			} }
		#expect(throws: TwoMLSError.archiveInvalid) { try restorePatched(m.archive) {
				$0.count = UInt32(MigratedOwnOfferWindow.maximumOfferCount) + 1
			} }
	}
}

// MARK: - Drop at import

extension SessionMigrationTests {
	@available(iOS 26, macOS 26, *)
	private func rekeyInitiatedBob() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, upd: Data
	) {
		var (alice, bob) = try deployedShapedFullyEstablishedTurnOnBob()
		_ = try bob.pqRekeyBegin()
		guard case .rekeyInitiated(let upd) = bob.pqInflight else {
			Issue.record("expected .rekeyInitiated")
			throw TwoMLSError.sessionNotReady
		}
		return (alice, bob, upd)
	}

	@available(iOS 26, macOS 26, *)
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
	@available(iOS 26, macOS 26, *)
	@Test func validParkedUpdIsKeptAtImport() throws {
		var (alice, bob, upd) = try rekeyInitiatedBob()
		let parts = try migratedParts(bob, suppliedLeafKeys: true)
		var restored = try restoreMinted(parts)
		guard case .rekeyInitiated(let kept) = restored.pqInflight else {
			Issue.record("dropped a valid Upd′")
			return
		}
		#expect(kept == upd)
		#expect(restored.pendingSideBand == bob.pendingSideBand)
		let updFrame = try restored.pqRekeyBegin().frame
		let commit = try alice.pqRekeyRespond(updFrame).frame
		#expect(throws: Never.self) { try restored.pqRekeyApply(commit) }
		bob = restored
	}

	/// `pendingSideBand` is asserted here too: a parked
	/// `Upd′` that fails to verify against the restored recv-PQ group is
	/// dropped — `pqInflight` and `pendingSideBand` both cleared,
	/// `pqTurnMine` left as supplied — and self-drive then opens a plain
	/// A.4 rather than silently stalling.
	@available(iOS 26, macOS 26, *)
	@Test func unverifiableParkedUpdIsDroppedAtImport() throws {
		let (_, bob, upd) = try rekeyInitiatedBob()
		var tampered = upd
		tampered[tampered.index(before: tampered.endIndex)] ^= 0xFF
		var parts = try migratedParts(bob)
		parts.pqInflight = .rekeyInitiated(updMessage: tampered)
		parts.pendingSideBand = Frames.encodePQRekeyUpd(tampered)
		var restored = try restoreMinted(parts)
		#expect(restored.pqInflight == nil)
		#expect(restored.pendingSideBand == nil)
		#expect(restored.myPQTurn, "pqTurnMine left as supplied")

		_ = try restored.prepareToEncrypt()
		_ = try restored.encrypt(Data("x".utf8))
		#expect(restored.pendingSideBand != nil)
		#expect(restored.pendingSideBand?.first == Frames.pqEKTag)

		// A present but nil sideband is fine; a mismatched one is
		// `.archiveInvalid` (never silently repaired).
		var partsNil = parts
		partsNil.pendingSideBand = nil
		#expect(try restoreMinted(partsNil).pqInflight == nil)
		var partsBad = parts
		partsBad.pendingSideBand = Frames.encodePQRekeyUpd(upd)
		#expect(throws: TwoMLSError.archiveInvalid) { try restoreMinted(partsBad) }
	}

	/// Supplied `leafKeys` still carries the dropped round's
	/// orphaned recv-PQ `pending` entry — it must be removed too, not just
	/// `pqInflight`/`pendingSideBand`.
	@available(iOS 26, macOS 26, *)
	@Test func droppedRoundPendingEntryIsRemoved() throws {
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
		#expect(restored.leafKeys.recvPQ.pending[bob.identity.clientID] == nil)
	}

	/// The rule-7 exception — a dropped round's target that IS
	/// `mine.current` of a still-lagging recv-PQ leaf must be KEPT, not
	/// removed by the same pruning that discards 4d's orphan.
	@available(iOS 26, macOS 26, *)
	@Test func droppedRoundKeepsTheRuleSevenKey() throws {
		let (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let c = Data("bob-rust-rotated".utf8)
		var mirror = try #require(bob.recvGroup)
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
		#expect(restored.pqInflight == nil)
		#expect(restored.leafKeys.recvPQ.pending[c]?.signatureKey == fpk)
	}

	// MARK: - Wrong-signer heal (anomaly #5's own field shape)

	/// A pair with `bob` holding the PQ turn, `alice` having deferred her
	/// own fold to a plain A.4 under C2 (bob's own A.5 hasn't landed
	/// anywhere yet), and bob's recv-PQ leaf still presenting his
	/// pre-rotation id.
	@available(iOS 26, macOS 26, *)
	private func bobHoldingTurnAfterDeferredFold() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, bobOldID: Data, bobNewID: Data
	) {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try SessionTestSupport.drivePQRound(initiator: &bob, responder: &alice)
		#expect(alice.myPQTurn)
		let bobOldID = bob.identity.clientID
		let bobNewID = Data("bob-wrong-signer-heal".utf8)

		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try alice.processIncomingDecrypted(offerFrame)
		try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)

		// C2: bob's leaf hasn't moved in either PQ group, so his own A.5
		// hasn't landed anywhere — alice's fold defers to a plain A.4.
		let foldPrepared = try alice.prepareToEncrypt()
		#expect(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		guard case .initiating = alice.pqInflight else {
			Issue.record("expected alice's fold to defer to a plain A.4 under C2")
			throw TwoMLSError.sessionNotReady
		}
		let ekFrame = try #require(alice.pqPendingOutbound())
		_ = try bob.processIncomingDecrypted(foldFrame)
		#expect(bob.myPrincipalState == .sync(bobNewID))

		let ctFrame = try bob.pqRatchetRespond(ekFrame).frame
		_ = try alice.pqRatchetBind(ctFrame)

		// Fresh evidence for alice's discharge below — her own fold above
		// spent the earlier rotation-offer evidence.
		_ = try bob.prepareToEncrypt()
		let bobAckFrame = try bob.encrypt(Data("bob-ack".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobAckFrame)

		let dischargePrepared = try alice.prepareToEncrypt()
		#expect(dischargePrepared.didCommit)
		let boundFrame = try alice.encrypt(Data("discharge".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)
		#expect(bob.myPQTurn)

		let bobRecvPQ = try TwoMLSSession.ownLeaf(of: try #require(bob.recvGroup?.pq))
		#expect(try basicIdentifier(bobRecvPQ.credential) == bobOldID)
		return (alice, bob, bobOldID, bobNewID)
	}

	/// Hand-builds a well-formed §A.5 `Upd′` moving `session`'s own
	/// recv-PQ occupant leaf to `newID` under a fresh key, but frames it
	/// with a THIRD key — distinct from both the leaf's own fresh key and
	/// the key the leaf currently presents — matching anomaly #5's own
	/// field shape (the deployed engine's A.3 join signs with its CURRENT
	/// client PQ key rather than the KP′ key the leaf actually presents).
	/// swift-mls 0.1.6's `proposeUpdate` self-verifies its own envelope
	/// against the leaf key it mints, so the wrong signer can't be
	/// produced through that API directly — this builds the
	/// `FramedContent` by hand instead, the same way
	/// `SessionTestSupport.knownSecretOwnOffer` does for a classical own
	/// offer.
	@available(iOS 26, macOS 26, *)
	private func wrongSignerParkedUpd(
		forRecvPQOf session: TwoMLSSession, newID: Data
	) throws -> (updBytes: Data, freshLeafKey: LeafKey) {
		let provider = SessionTestSupport.pqProvider
		var group = try #require(session.recvGroup?.pq)
		let current = try TwoMLSSession.ownLeaf(of: group)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (wrongSigningKey, _) = try TwoMLSIdentity.mintSignatureKeypair()
		let (_, hpkePublic) = try provider.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: hpkePublic, signatureKey: freshSignatureKey,
			credential: .basic(identity: newID), capabilities: current.capabilities,
			source: .update, extensions: current.extensions, signature: Data())
		let tbs = try leaf.toBeSigned(
			placement: .inGroup(
				groupID: group.context.groupID, leafIndex: group.myLeafIndex))
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: freshSigningKey, label: "LeafNodeTBS", content: tbs)
		// A throwaway `proposeUpdate` call, only to get a correctly-shaped
		// sender for the hand-built `FramedContent` below — its own Update
		// leaf/keys are discarded.
		let (template, _) = try group.proposeUpdate(
			provider,
			sign: MLS.RFC9420.signingClosure(provider, try session.recvPQSigningKey()),
			framing: .publicMessage)
		guard case .publicMessage(let templatePub) = template else {
			throw TwoMLSError.malformedSideBandMessage
		}
		let content = MLS.RFC9420.FramedContent(
			groupID: group.context.groupID, epoch: group.context.epoch,
			sender: templatePub.content.sender, authenticatedData: newID,
			content: .proposal(.update(leaf)))
		let pub = try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: group.context,
			confirmationTag: nil, signingKey: wrongSigningKey,
			membershipKey: group.epoch.membershipKey)
		let updBytes = try MLS.RFC9420.Message.publicMessage(pub).mlsEncoded()
		return (
			updBytes,
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey)
		)
	}

	/// A migrated session carrying a parked `Upd′` framed by a wrong (third)
	/// key is dropped at import — its field shape, not the byte flip
	/// `testUnverifiableParkedUpdIsDroppedAtImport` already covers. The
	/// staged key survives as the rule-7 catch-up entry (the leaf still
	/// lags `mine.current`), but the parked round itself does not, and the
	/// next send re-proposes fresh under the key the leaf actually
	/// presents. Kills: a re-propose that consumes the held key rather
	/// than minting fresh (swift-mls's self-verify would then throw, and
	/// nothing would be staged); a drop keyed on decode success alone (the
	/// byte-flip test already catches that).
	@available(iOS 26, macOS 26, *)
	@Test func wrongSignerParkedUpdIsDroppedAndReProposedUnderTheStoredKey() throws {
		let (alice, bob, bobOldID, bobNewID) = try bobHoldingTurnAfterDeferredFold()
		let (wrongUpd, freshLeafKey) = try wrongSignerParkedUpd(
			forRecvPQOf: bob, newID: bobNewID)

		var parts = try migratedParts(bob, suppliedLeafKeys: true)
		parts.pqInflight = .rekeyInitiated(updMessage: wrongUpd)
		parts.pendingSideBand = Frames.encodePQRekeyUpd(wrongUpd)
		var lk = migratedLeafKeys(from: bob.leafKeys)
		let (sendPQSigningKey, sendPQSignatureKey) =
			try TwoMLSIdentity.mintSignatureKeypair()
		lk.recvPQ = MigratedGroupKeys(
			current: lk.recvPQ.current,
			pending: [
				MigratedPendingLeafKey(
					target: bobNewID,
					key: MigratedLeafKey(
						signingKey: freshLeafKey.signingKey.data,
						signatureKey: freshLeafKey.signatureKey.data))
			])
		lk.sendPQ = MigratedGroupKeys(
			current: lk.sendPQ.current,
			pending: [
				MigratedPendingLeafKey(
					target: bobNewID,
					key: MigratedLeafKey(
						signingKey: sendPQSigningKey.data,
						signatureKey: sendPQSignatureKey.data))
			])
		parts.leafKeys = lk

		var restored = try restoreMinted(parts)
		#expect(restored.pqInflight == nil, "dropped at import")
		#expect(restored.pendingSideBand == nil, "dropped at import")
		#expect(restored.myPQTurn, "pqTurnMine left as supplied")
		#expect(restored.leafKeys.recvPQ.pending[bobNewID]?.signatureKey == freshLeafKey.signatureKey, "the rule-7 catch-up key survives — the leaf still lags mine.current")

		// The next send re-proposes fresh, signed under the key the leaf
		// actually presents (bobOldID's), not the wrong one dropped above.
		_ = try restored.prepareToEncrypt()
		let selfDriven = try restored.encrypt(Data("heal".utf8))
		#expect(selfDriven.update.kind == .checkpoint)
		guard case .rekeyInitiated(let newUpdBytes) = restored.pqInflight else {
			Issue.record("expected the self-drive to re-propose the catch-up")
			return
		}
		#expect(newUpdBytes != wrongUpd)
		let newFreshKey = try #require(restored.leafKeys.recvPQ.pending[bobNewID])
		#expect(newFreshKey.signatureKey != freshLeafKey.signatureKey)

		guard
			case .publicMessage(let newUpdPub) = try MLS.RFC9420.Message(
				mlsEncoded: newUpdBytes)
		else {
			Issue.record("expected a publicMessage-framed Upd′")
			return
		}
		#expect(newUpdPub.content.authenticatedData == bobNewID)

		// It verifies against alice's send-PQ for real — signed under the
		// key bob's leaf there actually presents (bobOldID's), which the
		// dropped wrong-signer round never was.
		let pending = try #require(restored.pqPendingOutbound())
		var aliceMutable = alice
		#expect(throws: Never.self) { try aliceMutable.pqRekeyRespond(pending) }
		_ = bobOldID
	}

	/// The dropped wrong-signer round's own heal, driven end to end: bob's
	/// re-proposed A.5 catch-up lands, then alice's reciprocal (her own
	/// leaf in bob's recv-PQ still lags), then an ordinary A.4 — never
	/// wedged throughout. Kills: dropping C2 or reading it from the wrong
	/// group; the own-arm-only trigger; "lags" read as history membership
	/// rather than a head compare; a re-propose that consumes the held key
	/// rather than minting fresh.
	@available(iOS 26, macOS 26, *)
	@Test func droppedWrongSignerUpdHealsThroughTheSelfDrivenCatchUp() throws {
		let (alice, bob, _, bobNewID) = try bobHoldingTurnAfterDeferredFold()
		let (wrongUpd, freshLeafKey) = try wrongSignerParkedUpd(
			forRecvPQOf: bob, newID: bobNewID)

		var parts = try migratedParts(bob, suppliedLeafKeys: true)
		parts.pqInflight = .rekeyInitiated(updMessage: wrongUpd)
		parts.pendingSideBand = Frames.encodePQRekeyUpd(wrongUpd)
		var lk = migratedLeafKeys(from: bob.leafKeys)
		let (sendPQSigningKey, sendPQSignatureKey) =
			try TwoMLSIdentity.mintSignatureKeypair()
		lk.recvPQ = MigratedGroupKeys(
			current: lk.recvPQ.current,
			pending: [
				MigratedPendingLeafKey(
					target: bobNewID,
					key: MigratedLeafKey(
						signingKey: freshLeafKey.signingKey.data,
						signatureKey: freshLeafKey.signatureKey.data))
			])
		lk.sendPQ = MigratedGroupKeys(
			current: lk.sendPQ.current,
			pending: [
				MigratedPendingLeafKey(
					target: bobNewID,
					key: MigratedLeafKey(
						signingKey: sendPQSigningKey.data,
						signatureKey: sendPQSignatureKey.data))
			])
		parts.leafKeys = lk

		var restoredBob = try restoreMinted(parts)
		#expect(restoredBob.pqInflight == nil)
		var mutableAlice = alice

		// bob's re-proposed A.5 catch-up (0x1B), landing his recv-PQ leaf
		// on bobNewID.
		let bobTag = try SessionTestSupport.drivePQRound(
			initiator: &restoredBob, responder: &mutableAlice)
		#expect(bobTag == Frames.pqRekeyUpdTag)
		#expect(!(restoredBob.pqSideBandWedged))
		let bobRecvPQAfter = try TwoMLSSession.ownLeaf(
			of: try #require(restoredBob.recvGroup?.pq))
		#expect(try basicIdentifier(bobRecvPQAfter.credential) == bobNewID)
		#expect(restoredBob.leafKeys.recvPQ.pending.isEmpty)

		// alice's reciprocal (0x1B) — her own leaf in bob's recv-PQ mirror
		// still lags, and C2 is now satisfied.
		let aliceTag = try SessionTestSupport.drivePQRound(
			initiator: &mutableAlice, responder: &restoredBob)
		#expect(aliceTag == Frames.pqRekeyUpdTag)
		#expect(!(restoredBob.pqSideBandWedged))

		// Neither trigger has anything left to fire — the following round
		// is ordinary A.4.
		let finalTag = try SessionTestSupport.drivePQRound(
			initiator: &restoredBob, responder: &mutableAlice)
		#expect(finalTag == Frames.pqEKTag)
		#expect(!(restoredBob.pqSideBandWedged))
	}

	// MARK: - The one-way lag drop (mint-time admissibility)

	/// A parked `Upd′` that verifies but whose target has already left
	/// `mine.history` — the mint-time admissibility drop: a rollback
	/// to any credential no longer in history is refused by the same
	/// successor rule everywhere else, and a parked target is no
	/// exception. Kills: a missing admissibility check.
	@available(iOS 26, macOS 26, *)
	@Test func parkedUpdWhoseTargetLeftOurHistoryIsDroppedAtImport() throws {
		let (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let target = Data("bob-evicted-target".utf8)

		// A genuinely-signed Upd′ targeting `target`, built off a scratch
		// copy so `bob`'s own state is untouched.
		var mirror = try #require(bob.recvGroup)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.pq!.proposeUpdate(
			SessionTestSupport.pqProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.pqProvider, current: try bob.recvPQSigningKey(),
				new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: target),
				signatureKey: freshSignatureKey))
		let updBytes = try message.mlsEncoded()

		var parts = try migratedParts(bob, suppliedLeafKeys: true)
		parts.pqInflight = .rekeyInitiated(updMessage: updBytes)
		parts.pendingSideBand = Frames.encodePQRekeyUpd(updBytes)
		// `target` was never part of bob's own canonical history — the
		// round is stale, and no live leaf lags anything else, so no
		// further catch-up entry is needed.
		var lk = migratedLeafKeys(from: bob.leafKeys)
		lk.recvPQ = MigratedGroupKeys(
			current: lk.recvPQ.current,
			pending: [
				MigratedPendingLeafKey(
					target: target,
					key: MigratedLeafKey(
						signingKey: freshSigningKey.data,
						signatureKey: freshSignatureKey.data))
			])
		parts.leafKeys = lk

		let restored = try restoreMinted(parts)
		#expect(restored.pqInflight == nil, "the target has left history — dropped at mint")
		#expect(restored.pendingSideBand == nil)
		#expect(restored.leafKeys.recvPQ.pending[target] == nil, "not the rule-7 key — target isn't mine.current")
	}

	/// The control: a parked `Upd′` targeting an id that predates
	/// `mine.current` but is STILL within the history window is kept, not
	/// dropped — the admissibility check must not drop every non-current
	/// target, only an evicted one. (The same-id refresh case is a
	/// separate arm — see the pinned/evicted test below.)
	@available(iOS 26, macOS 26, *)
	@Test func parkedUpdToAHistoryIDIsKeptAtImport() throws {
		let (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let target = Data("bob-history-target".utf8)

		var mirror = try #require(bob.recvGroup)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.pq!.proposeUpdate(
			SessionTestSupport.pqProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.pqProvider, current: try bob.recvPQSigningKey(),
				new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: target),
				signatureKey: freshSignatureKey))
		let updBytes = try message.mlsEncoded()

		var parts = try migratedParts(bob, suppliedLeafKeys: true)
		parts.pqInflight = .rekeyInitiated(updMessage: updBytes)
		parts.pendingSideBand = Frames.encodePQRekeyUpd(updBytes)
		// `target` predates `mine.current` but is still within the history
		// window — admissible, if stale, unlike the evicted case above.
		parts.auth.mine.history.insert(target, at: 0)
		var lk = migratedLeafKeys(from: bob.leafKeys)
		lk.recvPQ = MigratedGroupKeys(
			current: lk.recvPQ.current,
			pending: [
				MigratedPendingLeafKey(
					target: target,
					key: MigratedLeafKey(
						signingKey: freshSigningKey.data,
						signatureKey: freshSignatureKey.data))
			])
		parts.leafKeys = lk

		let restored = try restoreMinted(parts)
		guard case .rekeyInitiated(let kept) = restored.pqInflight else {
			Issue.record("a target still within history must be kept")
			return
		}
		#expect(kept == updBytes)
		#expect(restored.pendingSideBand != nil)
	}

	/// A parked SAME-ID `Upd′` — a key refresh, not a move: its target
	/// equals the recv-PQ leaf's own currently-presented credential — must
	/// be kept even once that id has left `mine.history` (a full rotation
	/// cycle evicted it) and is pinned. The `target == presentedRecvPQID`
	/// admissibility arm is not a history lookup: a pinned id is never a
	/// valid *successor*, but this Upd′ never claims to be one. Kills:
	/// `admissible = mine.history.contains(target)` alone (dropping the
	/// same-id arm), which would wrongly drop this refresh.
	@available(iOS 26, macOS 26, *)
	@Test func parkedSameIDUpdWhoseTargetIsEvictedAndPinnedIsKeptAtImport() throws {
		let (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let presentedID = bob.identity.clientID

		// A same-id key refresh: the Upd′ credential equals the leaf's own
		// presented id, not a move to a new one.
		var mirror = try #require(bob.recvGroup)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.pq!.proposeUpdate(
			SessionTestSupport.pqProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.pqProvider, current: try bob.recvPQSigningKey(),
				new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: presentedID),
				signatureKey: freshSignatureKey))
		let updBytes = try message.mlsEncoded()

		var parts = try migratedParts(bob, suppliedLeafKeys: true)
		parts.pqInflight = .rekeyInitiated(updMessage: updBytes)
		parts.pendingSideBand = Frames.encodePQRekeyUpd(updBytes)
		// The leaf's own id has since left the history window — a further
		// classical rotation landed, elsewhere, moving `mine.current` on —
		// and, evicted, `presentedID` is pinned: exactly the state a
		// rollback would be refused in, but this Upd′ isn't one.
		let laterCurrent = Data("bob-vN".utf8)
		parts.auth.mine.history.removeAll { $0 == presentedID }
		parts.auth.mine.history.append(laterCurrent)
		parts.auth.mine.pinned.append(presentedID)
		// Every other own leaf now lags the new `mine.current` (none of
		// them moved with the classical rotation), so check 7 requires a
		// `pending[laterCurrent]` catch-up placeholder in each — unrelated
		// to the same-id arm this test targets, but required for the parts
		// to mint at all.
		let (laterSigningKey, laterSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let laterKey = MigratedLeafKey(
			signingKey: laterSigningKey.data, signatureKey: laterSignatureKey.data)
		var lk = migratedLeafKeys(from: bob.leafKeys)
		lk.recvClassical = MigratedGroupKeys(
			current: lk.recvClassical.current,
			pending: [MigratedPendingLeafKey(target: laterCurrent, key: laterKey)])
		lk.recvPQ = MigratedGroupKeys(
			current: lk.recvPQ.current,
			pending: [
				MigratedPendingLeafKey(
					target: presentedID,
					key: MigratedLeafKey(
						signingKey: freshSigningKey.data,
						signatureKey: freshSignatureKey.data)),
				MigratedPendingLeafKey(target: laterCurrent, key: laterKey),
			])
		lk.sendPQ = MigratedGroupKeys(
			current: lk.sendPQ.current,
			pending: [MigratedPendingLeafKey(target: laterCurrent, key: laterKey)])
		parts.leafKeys = lk

		let restored = try restoreMinted(parts)
		guard case .rekeyInitiated(let kept) = restored.pqInflight else {
			Issue.record("a same-id refresh must be kept even once its id is evicted and pinned")
			return
		}
		#expect(kept == updBytes)
		#expect(restored.pendingSideBand != nil)
	}
}

extension SessionMigrationTests {
	/// A rogue initiator whose own classical leaf does not advertise 0xF0A1
	/// completes `initiate` on its own side; the mint's four-tree capability
	/// check must still refuse the resulting restored trees.
	@available(iOS 26, macOS 26, *)
	@Test func mintRefusesARogueOccupiedLeafInARestoredTree() throws {
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
		#expect(throws: TwoMLSError.archiveInvalid) { try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: classicalProvider, pqProvider: pqProvider) }
	}
}
