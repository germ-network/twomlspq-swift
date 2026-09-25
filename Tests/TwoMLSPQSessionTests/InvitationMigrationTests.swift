import Foundation
import MLSCodec
import MLSProfileRFC9420
import SecretBytes
import Testing

@testable import TwoMLSPQSession

/// The public parts-to-archive invitation minter. The minted
/// archive must be what `Invitation.restore` accepts and semantically what
/// `makeInvitationArchive` would have produced — the cross-module migrator
/// calls this with raw parts read from a legacy Rust invitation, so it must
/// work without a live `Invitation`/`TwoMLSIdentity` or any provider.
@Suite struct InvitationMigrationTests {
	@available(iOS 26, macOS 26, *)
	private func makePrincipal(_ name: String) throws -> Principal {
		try Principal.generate(
			clientID: Data(name.utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	/// Decomposes a live invitation into the exact raw parts a migrator would
	/// read off a legacy Rust invitation (same byte representations the
	/// native identity holds).
	@available(iOS 26, macOS 26, *)
	private func migratedParts(
		_ invitation: Invitation
	) throws -> (clientID: Data, stateSeq: UInt64, identity: MigratedIdentity) {
		let identity = try #require(invitation.identity)
		return (
			clientID: invitation.clientID,
			stateSeq: invitation.stateSeq,
			identity: MigratedIdentity(
				clientID: identity.clientID,
				signingKey: identity.signingKey.data,
				signatureKey: identity.signatureKey.data,
				pqSigningKey: identity.pqSigningKey.data,
				pqSignatureKey: identity.pqSignatureKey.data,
				classicalLeafSecretKey: identity.classicalLeafSecretKey.data,
				classicalInitSecretKey: try #require(
					identity.classicalInitSecretKey
				).data,
				pqLeafSecretKey: identity.pqLeafSecretKey.data,
				pqInitSecretKey: try #require(identity.pqInitSecretKey).data,
				classicalKeyPackage: try identity.keyPackage.classical.mlsEncoded(),
				pqKeyPackage: try identity.keyPackage.pq.mlsEncoded())
		)
	}

	// MARK: - AC 1: equivalence with the native path

	/// The minted archive decodes to the same `InvitationArchive` body the
	/// native `makeInvitationArchive` one does, field by field — including
	/// post-PR-#40's two DISTINCT per-half signing keys. (SecretArchive
	/// exposes no plaintext byte accessor and `seal` uses a random nonce, so
	/// raw-byte equality is unobservable by design; the decoded bodies are
	/// the strongest expressible comparison. Table arrays are sorted by the
	/// minter for reproducibility, which restore is insensitive to.)
	@available(iOS 26, macOS 26, *)
	@Test func mintedArchiveDecodesToTheNativeBody() throws {
		// last-resort so the identity survives `receive` (a single-use
		// invitation nils it on consume).
		var (invitation, nativeArchive) = try makePrincipal("bob").generateInvitation(
			lastResort: true)
		let other = try makePrincipal("alice")
		let round = try TwoMLSSession.initiate(
			principal: other,
			their: try #require(invitation.combinerKeyPackage))
		_ = try invitation.receive(
			welcome: round.welcome,
			theirClassicalKeyPackage: round.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try round.session.bootstrapKPCommitment(),
			spawnToken: SessionTestSupport.classicalProvider.randomBytes(16))
		// Re-archive the now-mutated invitation so both paths carry the same
		// non-empty tables.
		nativeArchive = try invitation.makeInvitationArchive()

		let parts = try migratedParts(invitation)
		let minted = try InvitationMigration.mintArchive(
			clientID: parts.clientID, lastResort: true, stateSeq: invitation.stateSeq,
			identity: parts.identity, forwardTable: invitation.forwardTable,
			processedWelcomes: invitation.processedWelcomes,
			bootstrapRouting: invitation.bootstrapRouting,
			consumedRemotes: invitation.consumedRemotes)

		let nativeBody = try nativeArchive.decode(InvitationArchive.self)
		let mintedBody = try minted.decode(InvitationArchive.self)
		#expect(mintedBody.version == nativeBody.version)
		#expect(mintedBody.classicalSuite == nativeBody.classicalSuite)
		#expect(mintedBody.pqSuite == nativeBody.pqSuite)
		#expect(mintedBody.stateSeq == nativeBody.stateSeq)
		#expect(mintedBody.lastResort == nativeBody.lastResort)
		#expect(mintedBody.clientID == nativeBody.clientID)
		#expect(mintedBody.consumedRemotes == nativeBody.consumedRemotes)
		for table in [
			(minted: mintedBody.forwardTable, native: nativeBody.forwardTable),
			(
				minted: mintedBody.processedWelcomes,
				native: nativeBody.processedWelcomes
			),
			(minted: mintedBody.bootstrapRouting, native: nativeBody.bootstrapRouting),
		] {
			#expect(
				Dictionary(
					uniqueKeysWithValues: table.minted.map {
						($0.key, $0.classicalGroupID)
					})
					== Dictionary(
						uniqueKeysWithValues: table.native.map {
							($0.key, $0.classicalGroupID)
						}))
		}
		guard let mintedIdentity = mintedBody.identity,
			let nativeIdentity = nativeBody.identity
		else {
			Issue.record("expected both identities present")
			return
		}
		#expect(mintedIdentity.clientID == nativeIdentity.clientID)
		#expect(mintedIdentity.signatureKey == nativeIdentity.signatureKey)
		#expect(mintedIdentity.pqSignatureKey == nativeIdentity.pqSignatureKey)
		#expect(
			mintedIdentity.classicalKeyPackage == nativeIdentity.classicalKeyPackage)
		#expect(mintedIdentity.pqKeyPackage == nativeIdentity.pqKeyPackage)
		#expect(mintedIdentity.signingKey == nativeIdentity.signingKey)
		#expect(mintedIdentity.pqSigningKey == nativeIdentity.pqSigningKey)
		#expect(
			mintedIdentity.classicalLeafSecretKey
				== nativeIdentity.classicalLeafSecretKey
		)
		#expect(
			mintedIdentity.classicalInitSecretKey
				== nativeIdentity.classicalInitSecretKey
		)
		#expect(mintedIdentity.pqLeafSecretKey == nativeIdentity.pqLeafSecretKey)
		#expect(mintedIdentity.pqInitSecretKey == nativeIdentity.pqInitSecretKey)
		// Post-PR-#40: the two halves carry DISTINCT signing keys, and both
		// survive the mint.
		#expect(mintedIdentity.signingKey != mintedIdentity.pqSigningKey)
	}

	// MARK: - AC 2: restore + use (the migrated KEM/HPKE keys are live)

	/// A minted archive restores to an invitation that opens a §A.1 envelope
	/// sealed to its published KP — the migrated PQ init secret actually
	/// decapsulates — and then receives the welcome that envelope carried.
	@available(iOS 26, macOS 26, *)
	@Test func mintedArchiveRestoresAndOpenInitialsARealEnvelope() throws {
		let bobPrincipal = try makePrincipal("bob")
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let parts = try migratedParts(invitation)
		let minted = try InvitationMigration.mintArchive(
			clientID: parts.clientID, lastResort: true, stateSeq: invitation.stateSeq,
			identity: parts.identity, forwardTable: [:], processedWelcomes: [:],
			bootstrapRouting: [:], consumedRemotes: [])

		var restored = try Invitation.restore(
			archive: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let alicePrincipal = try makePrincipal("alice")
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal,
			their: try #require(invitation.combinerKeyPackage))
		let envelope = try initiated.session.pendingOutbound()
		guard case .establishment(let frame) = try restored.openInitial(envelope) else {
			Issue.record("expected .establishment")
			return
		}
		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try #require(frame.returnKeyPackage))
		let received = try restored.receive(
			welcome: try #require(frame.welcome), theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: SessionTestSupport.classicalProvider.randomBytes(16))
		#expect(received.session.isEstablished)
	}

	// MARK: - AC 3: spent single-use

	/// `identity: nil` mints a spent single-use invitation's archive, which
	/// restores (identity nil, still routable) and `openInitial` fails
	/// cleanly with `.invitationSpent`.
	@available(iOS 26, macOS 26, *)
	@Test func spentSingleUseMintRestoresAndFailsOpenInitialCleanly() throws {
		let minted = try InvitationMigration.mintArchive(
			clientID: Data("bob".utf8), lastResort: false, stateSeq: 7, identity: nil,
			forwardTable: [Data("tok".utf8): Data("gid".utf8)], processedWelcomes: [:],
			bootstrapRouting: [:], consumedRemotes: [Data("alice".utf8)])
		let restored = try Invitation.restore(
			archive: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.identity == nil)
		#expect(restored.combinerKeyPackage == nil)
		#expect(restored.stateSeq == 7)
		#expect(
			restored.forwardGroupID(spawnToken: Data("tok".utf8)) == Data("gid".utf8))
		#expect(throws: TwoMLSError.invitationSpent) {
			try restored.openInitial(Data("x".utf8))
		}
	}

	// MARK: - AC 4: mutation-verify

	/// Corrupting ONE migrated secret (the PQ leaf secret) must fail — at
	/// mint time (here inside the 96-B integrity check), proving the mint
	/// detects a bad part rather than just a decode.
	@available(iOS 26, macOS 26, *)
	@Test func corruptedPqLeafSecretIsRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		var parts = try #require(try migratedParts(invitation).identity)
		var corrupted = [UInt8](repeating: 0, count: 96)
		for (i, byte) in corrupted.enumerated() { corrupted[i] = byte &+ UInt8(i) }
		parts.pqLeafSecretKey = try SecretBytes(bytes: Data(corrupted))

		#expect(throws: TwoMLSError.archiveInvalid) {
			try InvitationMigration.mintArchive(
				clientID: invitation.clientID, lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts, forwardTable: [:],
				processedWelcomes: [:], bootstrapRouting: [:], consumedRemotes: [])
		}
	}

	/// A VALID but different ML-KEM leaf secret — one that passes the 96-B
	/// integrity check — is rejected by the derived-public vs KeyPackage
	/// comparison, which is the check that actually catches a mis-mapped
	/// (not merely corrupted) key.
	@available(iOS 26, macOS 26, *)
	@Test func validButWrongPqLeafSecretIsRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		var parts = try #require(try migratedParts(invitation).identity)
		let (wrongSecret, _) = try SessionTestSupport.pqProvider.hpkeGenerateKeyPair()
		parts.pqLeafSecretKey = wrongSecret.data

		#expect(throws: TwoMLSError.archiveInvalid) {
			try InvitationMigration.mintArchive(
				clientID: invitation.clientID, lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts, forwardTable: [:],
				processedWelcomes: [:], bootstrapRouting: [:], consumedRemotes: [])
		}
	}

	/// Swapping the classical leaf and init secrets (two VALID X25519 keys,
	/// so no integrity check fires) is rejected — exactly the half-swap
	/// mis-mapping this minter exists to catch.
	@available(iOS 26, macOS 26, *)
	@Test func swappedClassicalLeafAndInitSecretsAreRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		var parts = try #require(try migratedParts(invitation).identity)
		let leaf = parts.classicalLeafSecretKey
		parts.classicalLeafSecretKey = parts.classicalInitSecretKey
		parts.classicalInitSecretKey = leaf

		#expect(throws: TwoMLSError.archiveInvalid) {
			try InvitationMigration.mintArchive(
				clientID: invitation.clientID, lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts, forwardTable: [:],
				processedWelcomes: [:], bootstrapRouting: [:], consumedRemotes: [])
		}
	}

	/// Corrupting the classical signing key fails the same way.
	@available(iOS 26, macOS 26, *)
	@Test func corruptedClassicalSigningKeyIsRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		var parts = try #require(try migratedParts(invitation).identity)
		parts.signingKey = try SecretBytes(
			bytes: Data(repeating: 0x42, count: 32))

		#expect(throws: TwoMLSError.archiveInvalid) {
			try InvitationMigration.mintArchive(
				clientID: invitation.clientID, lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts, forwardTable: [:],
				processedWelcomes: [:], bootstrapRouting: [:], consumedRemotes: [])
		}
	}

	/// A wrong `clientID` (not matching the KP credential) is rejected at
	/// mint — otherwise `openInitial` would fail downstream with nothing to
	/// explain why.
	@available(iOS 26, macOS 26, *)
	@Test func mismatchedClientIDIsRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		let parts = try migratedParts(invitation)

		#expect(throws: TwoMLSError.archiveInvalid) {
			try InvitationMigration.mintArchive(
				clientID: Data("mallory".utf8), lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts.identity,
				forwardTable: [:], processedWelcomes: [:], bootstrapRouting: [:],
				consumedRemotes: [])
		}
	}
}
