import Foundation
import MLSCodec
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// The public parts-to-archive invitation minter. The minted
/// archive must be what `Invitation.restore` accepts and semantically what
/// `makeInvitationArchive` would have produced — the cross-module migrator
/// calls this with raw parts read from a legacy Rust invitation, so it must
/// work without a live `Invitation`/`TwoMLSIdentity` or any provider.
@available(iOS 26, macOS 26, *)
final class InvitationMigrationTests: XCTestCase {
	private func makePrincipal(_ name: String) throws -> Principal {
		try Principal.generate(
			clientID: Data(name.utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	/// Decomposes a live invitation into the exact raw parts a migrator would
	/// read off a legacy Rust invitation (same byte representations the
	/// native identity holds).
	private func migratedParts(
		_ invitation: Invitation
	) throws -> (clientID: Data, stateSeq: UInt64, identity: MigratedIdentity) {
		let identity = try XCTUnwrap(invitation.identity)
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
				classicalInitSecretKey: try XCTUnwrap(
					identity.classicalInitSecretKey
				).data,
				pqLeafSecretKey: identity.pqLeafSecretKey.data,
				pqInitSecretKey: try XCTUnwrap(identity.pqInitSecretKey).data,
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
	func testMintedArchiveDecodesToTheNativeBody() throws {
		// last-resort so the identity survives `receive` (a single-use
		// invitation nils it on consume).
		var (invitation, nativeArchive) = try makePrincipal("bob").generateInvitation(
			lastResort: true)
		let other = try makePrincipal("alice")
		let round = try TwoMLSSession.initiate(
			principal: other,
			their: try XCTUnwrap(invitation.combinerKeyPackage))
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
		XCTAssertEqual(mintedBody.version, nativeBody.version)
		XCTAssertEqual(mintedBody.classicalSuite, nativeBody.classicalSuite)
		XCTAssertEqual(mintedBody.pqSuite, nativeBody.pqSuite)
		XCTAssertEqual(mintedBody.stateSeq, nativeBody.stateSeq)
		XCTAssertEqual(mintedBody.lastResort, nativeBody.lastResort)
		XCTAssertEqual(mintedBody.clientID, nativeBody.clientID)
		XCTAssertEqual(mintedBody.consumedRemotes, nativeBody.consumedRemotes)
		for table in [
			(minted: mintedBody.forwardTable, native: nativeBody.forwardTable),
			(
				minted: mintedBody.processedWelcomes,
				native: nativeBody.processedWelcomes
			),
			(minted: mintedBody.bootstrapRouting, native: nativeBody.bootstrapRouting),
		] {
			XCTAssertEqual(
				Dictionary(
					uniqueKeysWithValues: table.minted.map {
						($0.key, $0.classicalGroupID)
					}),
				Dictionary(
					uniqueKeysWithValues: table.native.map {
						($0.key, $0.classicalGroupID)
					}))
		}
		guard let mintedIdentity = mintedBody.identity,
			let nativeIdentity = nativeBody.identity
		else { return XCTFail("expected both identities present") }
		XCTAssertEqual(mintedIdentity.clientID, nativeIdentity.clientID)
		XCTAssertEqual(mintedIdentity.signatureKey, nativeIdentity.signatureKey)
		XCTAssertEqual(mintedIdentity.pqSignatureKey, nativeIdentity.pqSignatureKey)
		XCTAssertEqual(
			mintedIdentity.classicalKeyPackage, nativeIdentity.classicalKeyPackage)
		XCTAssertEqual(mintedIdentity.pqKeyPackage, nativeIdentity.pqKeyPackage)
		XCTAssertEqual(mintedIdentity.signingKey, nativeIdentity.signingKey)
		XCTAssertEqual(mintedIdentity.pqSigningKey, nativeIdentity.pqSigningKey)
		XCTAssertEqual(
			mintedIdentity.classicalLeafSecretKey, nativeIdentity.classicalLeafSecretKey
		)
		XCTAssertEqual(
			mintedIdentity.classicalInitSecretKey, nativeIdentity.classicalInitSecretKey
		)
		XCTAssertEqual(mintedIdentity.pqLeafSecretKey, nativeIdentity.pqLeafSecretKey)
		XCTAssertEqual(mintedIdentity.pqInitSecretKey, nativeIdentity.pqInitSecretKey)
		// Post-PR-#40: the two halves carry DISTINCT signing keys, and both
		// survive the mint.
		XCTAssertNotEqual(mintedIdentity.signingKey, mintedIdentity.pqSigningKey)
	}

	// MARK: - AC 2: restore + use (the migrated KEM/HPKE keys are live)

	/// A minted archive restores to an invitation that opens a §A.1 envelope
	/// sealed to its published KP — the migrated PQ init secret actually
	/// decapsulates — and then receives the welcome that envelope carried.
	func testMintedArchiveRestoresAndOpenInitialsARealEnvelope() throws {
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
			their: try XCTUnwrap(invitation.combinerKeyPackage))
		let envelope = try initiated.session.pendingOutbound()
		guard case .establishment(let frame) = try restored.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		let returnKP = try EstablishmentMessages.decodeKeyPackage(
			try XCTUnwrap(frame.returnKeyPackage))
		let received = try restored.receive(
			welcome: try XCTUnwrap(frame.welcome), theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: SessionTestSupport.classicalProvider.randomBytes(16))
		XCTAssertTrue(received.session.isEstablished)
	}

	// MARK: - AC 3: spent single-use

	/// `identity: nil` mints a spent single-use invitation's archive, which
	/// restores (identity nil, still routable) and `openInitial` fails
	/// cleanly with `.invitationSpent`.
	func testSpentSingleUseMintRestoresAndFailsOpenInitialCleanly() throws {
		let minted = try InvitationMigration.mintArchive(
			clientID: Data("bob".utf8), lastResort: false, stateSeq: 7, identity: nil,
			forwardTable: [Data("tok".utf8): Data("gid".utf8)], processedWelcomes: [:],
			bootstrapRouting: [:], consumedRemotes: [Data("alice".utf8)])
		let restored = try Invitation.restore(
			archive: minted,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertNil(restored.identity)
		XCTAssertNil(restored.combinerKeyPackage)
		XCTAssertEqual(restored.stateSeq, 7)
		XCTAssertEqual(
			restored.forwardGroupID(spawnToken: Data("tok".utf8)), Data("gid".utf8))
		XCTAssertThrowsError(
			try restored.openInitial(Data("x".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .invitationSpent)
		}
	}

	// MARK: - AC 4: mutation-verify

	/// Corrupting ONE migrated secret (the PQ leaf secret) must fail — at
	/// mint time (here inside the 96-B integrity check), proving the mint
	/// detects a bad part rather than just a decode.
	func testCorruptedPqLeafSecretIsRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		var parts = try XCTUnwrap(try migratedParts(invitation).identity)
		var corrupted = [UInt8](repeating: 0, count: 96)
		for (i, byte) in corrupted.enumerated() { corrupted[i] = byte &+ UInt8(i) }
		parts.pqLeafSecretKey = try SecretBytes(bytes: Data(corrupted))

		XCTAssertThrowsError(
			try InvitationMigration.mintArchive(
				clientID: invitation.clientID, lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts, forwardTable: [:],
				processedWelcomes: [:], bootstrapRouting: [:], consumedRemotes: [])
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A VALID but different ML-KEM leaf secret — one that passes the 96-B
	/// integrity check — is rejected by the derived-public vs KeyPackage
	/// comparison, which is the check that actually catches a mis-mapped
	/// (not merely corrupted) key.
	func testValidButWrongPqLeafSecretIsRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		var parts = try XCTUnwrap(try migratedParts(invitation).identity)
		let (wrongSecret, _) = try SessionTestSupport.pqProvider.hpkeGenerateKeyPair()
		parts.pqLeafSecretKey = wrongSecret.data

		XCTAssertThrowsError(
			try InvitationMigration.mintArchive(
				clientID: invitation.clientID, lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts, forwardTable: [:],
				processedWelcomes: [:], bootstrapRouting: [:], consumedRemotes: [])
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// Swapping the classical leaf and init secrets (two VALID X25519 keys,
	/// so no integrity check fires) is rejected — exactly the half-swap
	/// mis-mapping this minter exists to catch.
	func testSwappedClassicalLeafAndInitSecretsAreRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		var parts = try XCTUnwrap(try migratedParts(invitation).identity)
		let leaf = parts.classicalLeafSecretKey
		parts.classicalLeafSecretKey = parts.classicalInitSecretKey
		parts.classicalInitSecretKey = leaf

		XCTAssertThrowsError(
			try InvitationMigration.mintArchive(
				clientID: invitation.clientID, lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts, forwardTable: [:],
				processedWelcomes: [:], bootstrapRouting: [:], consumedRemotes: [])
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// Corrupting the classical signing key fails the same way.
	func testCorruptedClassicalSigningKeyIsRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		var parts = try XCTUnwrap(try migratedParts(invitation).identity)
		parts.signingKey = try SecretBytes(
			bytes: Data(repeating: 0x42, count: 32))

		XCTAssertThrowsError(
			try InvitationMigration.mintArchive(
				clientID: invitation.clientID, lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts, forwardTable: [:],
				processedWelcomes: [:], bootstrapRouting: [:], consumedRemotes: [])
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	/// A wrong `clientID` (not matching the KP credential) is rejected at
	/// mint — otherwise `openInitial` would fail downstream with nothing to
	/// explain why.
	func testMismatchedClientIDIsRejectedAtMint() throws {
		let (invitation, _) = try makePrincipal("bob").generateInvitation(lastResort: true)
		let parts = try migratedParts(invitation)

		XCTAssertThrowsError(
			try InvitationMigration.mintArchive(
				clientID: Data("mallory".utf8), lastResort: true,
				stateSeq: invitation.stateSeq, identity: parts.identity,
				forwardTable: [:], processedWelcomes: [:], bootstrapRouting: [:],
				consumedRemotes: [])
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}
}
