import Crypto
import Foundation
import MLSCodec
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto

// MARK: - Invitation migration minter (GER-2372 R1)
//
// The cross-module invitation migrator's parts-to-archive entry: mint the
// Swift-native v1 `InvitationArchive` body directly from raw parts a legacy
// Rust invitation supplies over UniFFI — no live `Invitation`, no
// `TwoMLSIdentity`, and no `CipherSuiteProvider` (encoding is provider-free;
// `SecretArchive(encoding:)` never touches crypto). "Mint the archive, not a
// live object": the migrator dual-reads the legacy side, single-writes this
// one.

/// Raw migrated identity parts, mirroring `IdentityArchive`'s field types
/// exactly, plus the one field the plan-review's caller could have dropped:
/// the identity's own `clientID`, which must equal both `KeyPackage`s' Basic
/// credential identities (and the invitation-level `clientID` — `mintArchive`
/// checks) or `openInitial`/`receive` fail downstream with nothing to explain
/// why.
///
/// Secret-key byte representations — the migrator must supply what the native
/// providers consume, both archived verbatim by the native path:
///  - The two Ed25519 signing keys: `rawRepresentation` (32 B each). The
///    halves may carry the SAME keypair (a legacy one-key principal) or
///    distinct ones — both restore: `IdentityArchive.restore` validates each
///    half's pair independently and never requires the halves to differ.
///  - The classical HPKE secrets: X25519 `rawRepresentation` (32 B).
///  - The PQ HPKE secrets: `MLKEM768.PrivateKey.integrityCheckedRepresentation`
///    (96 B — seed‖SHA3-256(ek), CryptoKit/swift-crypto's archival convention,
///    NOT a raw decapsulation key or bare seed).
///  - `classicalKeyPackage`/`pqKeyPackage`: BARE `KeyPackage` wire bytes (the
///    migrator unwraps the Rust MLSMessage frame); stored verbatim, never
///    re-encoded or re-signed.
///
/// `mintArchive` cross-checks every secret against its `KeyPackage` public
/// (`initKey`, `leafNode.encryptionKey`, both `leafNode.signatureKey`s) and
/// the clientID binding, so a mis-mapped part fails loudly at mint time as
/// `.archiveInvalid` instead of restoring cleanly and failing opaquely at
/// first use.
@available(iOS 26, macOS 26, *)
public struct MigratedIdentity: Sendable {
	/// Must equal both `KeyPackage`s' Basic credential identities.
	public var clientID: Data
	/// Ed25519 `rawRepresentation` (32 B).
	public var signingKey: SecretBytes
	public var signatureKey: Data
	/// Ed25519 `rawRepresentation` (32 B) — may equal `signingKey` for a
	/// legacy one-key principal; per-half keys are the native model.
	public var pqSigningKey: SecretBytes
	public var pqSignatureKey: Data
	/// X25519 `rawRepresentation` (32 B).
	public var classicalLeafSecretKey: SecretBytes
	/// X25519 `rawRepresentation` (32 B). Non-optional: the native path can
	/// never produce a mintable invitation without it (a single-use consume
	/// nils the whole identity instead), and without it a restored invitation
	/// could neither `openInitial` nor `receive`.
	public var classicalInitSecretKey: SecretBytes
	/// ML-KEM-768 `integrityCheckedRepresentation` (96 B).
	public var pqLeafSecretKey: SecretBytes
	/// ML-KEM-768 `integrityCheckedRepresentation` (96 B). Non-optional,
	/// like its classical counterpart.
	public var pqInitSecretKey: SecretBytes
	/// BARE classical `KeyPackage` wire bytes.
	public var classicalKeyPackage: Data
	/// BARE PQ `KeyPackage` wire bytes.
	public var pqKeyPackage: Data

	public init(
		clientID: Data,
		signingKey: SecretBytes,
		signatureKey: Data,
		pqSigningKey: SecretBytes,
		pqSignatureKey: Data,
		classicalLeafSecretKey: SecretBytes,
		classicalInitSecretKey: SecretBytes,
		pqLeafSecretKey: SecretBytes,
		pqInitSecretKey: SecretBytes,
		classicalKeyPackage: Data,
		pqKeyPackage: Data
	) {
		self.clientID = clientID
		self.signingKey = signingKey
		self.signatureKey = signatureKey
		self.pqSigningKey = pqSigningKey
		self.pqSignatureKey = pqSignatureKey
		self.classicalLeafSecretKey = classicalLeafSecretKey
		self.classicalInitSecretKey = classicalInitSecretKey
		self.pqLeafSecretKey = pqLeafSecretKey
		self.pqInitSecretKey = pqInitSecretKey
		self.classicalKeyPackage = classicalKeyPackage
		self.pqKeyPackage = pqKeyPackage
	}
}

@available(iOS 26, macOS 26, *)
public enum InvitationMigration {
	/// Mint a native, unsealed, zeroizing invitation `SecretArchive` from raw
	/// migrated parts — byte-shape-identical to what `makeInvitationArchive()`
	/// would have produced for the same state (modulo the table-array ordering
	/// caveat: this path sorts the table arrays and `consumedRemotes` bytewise
	/// so repeated mints of the same parts are reproducible; restore is
	/// order-insensitive). Encoding needs no provider — the parts ARE the
	/// native representations.
	///
	/// `identity: nil` mints a spent single-use invitation's archive. With an
	/// identity, init secrets ride verbatim from the parts (the native
	/// invitation path's `includeInitSecrets: true`).
	///
	/// - Throws: `TwoMLSError.archiveInvalid` if any migrated part fails its
	///   cross-check: a signing keypair that doesn't derive to its public, a
	///   secret whose derived public doesn't match its `KeyPackage`'s
	///   `initKey`/`encryptionKey`, a Basic credential identity that isn't
	///   `clientID` (both the identity's own id and the invitation-level one),
	///   a `KeyPackage` that doesn't MLS-decode or isn't the port's
	///   mls10/classical-or-PQ suite, or a secret that isn't in its provider's
	///   native representation.
	///
	/// `lastResort` is TRUSTED, not verified — the port's key packages carry
	/// no last-resort extension to check it against; the migrator must read it
	/// from the legacy side's own state.
	public static func mintArchive(
		clientID: Data,
		lastResort: Bool,
		stateSeq: UInt64,
		identity: MigratedIdentity?,
		forwardTable: [Data: Data],
		processedWelcomes: [Data: Data],
		bootstrapRouting: [Data: Data],
		consumedRemotes: Set<Data>
	) throws -> SecretArchive {
		let identityArchive = try identity.map {
			try Self.archiveIdentity($0, clientID: clientID)
		}
		let body = InvitationArchive(
			version: invitationArchiveVersion,
			classicalSuite: TwoMLSSuite.classical.id,
			pqSuite: TwoMLSSuite.pq.id,
			stateSeq: stateSeq,
			lastResort: lastResort,
			clientID: clientID,
			identity: identityArchive,
			forwardTable: sortedEntries(forwardTable),
			processedWelcomes: sortedEntries(processedWelcomes),
			bootstrapRouting: sortedEntries(bootstrapRouting),
			consumedRemotes: consumedRemotes.sorted { $0.lexicographicallyPrecedes($1) }
		)
		return try SecretArchive(encoding: body)
	}

	/// Maps the raw parts into `IdentityArchive` — mirroring the native
	/// `IdentityArchive(_:includeInitSecrets: true)` invitation path (init
	/// secrets always carried when present) — then runs the SAME checks
	/// `restore` would, plus the HPKE/KP checks restore never does, so a bad
	/// migration mapping is a loud mint-time failure.
	private static func archiveIdentity(
		_ identity: MigratedIdentity, clientID: Data
	) throws -> IdentityArchive {
		guard try derivedEd25519Public(from: identity.signingKey) == identity.signatureKey,
			try derivedEd25519Public(from: identity.pqSigningKey)
				== identity.pqSignatureKey
		else {
			throw TwoMLSError.archiveInvalid
		}
		// Keyed decodes folded to fail-closed `archiveInvalid` — an
		// MLSMessage-FRAMED KeyPackage (the migrator's likeliest mistake)
		// otherwise escapes as a raw `CodecError`.
		let classicalKP: MLS.RFC9420.KeyPackage
		let pqKP: MLS.RFC9420.KeyPackage
		do {
			classicalKP = try MLS.RFC9420.KeyPackage(
				mlsEncoded: identity.classicalKeyPackage)
			pqKP = try MLS.RFC9420.KeyPackage(mlsEncoded: identity.pqKeyPackage)
		} catch is MLS.CodecError {
			throw TwoMLSError.archiveInvalid
		}
		guard classicalKP.version == .mls10, pqKP.version == .mls10,
			classicalKP.cipherSuite == TwoMLSSuite.classical,
			pqKP.cipherSuite == TwoMLSSuite.pq,
			try basicIdentifier(classicalKP.leafNode.credential) == identity.clientID,
			try basicIdentifier(pqKP.leafNode.credential) == identity.clientID,
			identity.clientID == clientID,
			classicalKP.leafNode.signatureKey.data == identity.signatureKey,
			pqKP.leafNode.signatureKey.data == identity.pqSignatureKey,
			try classicalPublic(from: identity.classicalLeafSecretKey)
				== classicalKP.leafNode.encryptionKey.data,
			try pqPublic(from: identity.pqLeafSecretKey)
				== pqKP.leafNode.encryptionKey.data,
			try classicalPublic(from: identity.classicalInitSecretKey)
				== classicalKP.initKey.data,
			try pqPublic(from: identity.pqInitSecretKey) == pqKP.initKey.data
		else {
			throw TwoMLSError.archiveInvalid
		}
		return IdentityArchive(
			clientID: identity.clientID,
			signingKey: identity.signingKey,
			signatureKey: identity.signatureKey,
			pqSigningKey: identity.pqSigningKey,
			pqSignatureKey: identity.pqSignatureKey,
			classicalLeafSecretKey: identity.classicalLeafSecretKey,
			classicalInitSecretKey: SecretField(
				wrappedValue: identity.classicalInitSecretKey),
			pqLeafSecretKey: identity.pqLeafSecretKey,
			pqInitSecretKey: SecretField(wrappedValue: identity.pqInitSecretKey),
			classicalKeyPackage: identity.classicalKeyPackage,
			pqKeyPackage: identity.pqKeyPackage)
	}

	/// Table arrays sorted bytewise by key — restore rebuilds dictionaries, so
	/// order is wire-irrelevant, but deterministic bytes make a re-mint of the
	/// same parts reproducible.
	private static func sortedEntries(_ table: [Data: Data]) -> [InvitationTableEntry] {
		table.map(InvitationTableEntry.init).sorted {
			$0.key.lexicographicallyPrecedes($1.key)
		}
	}

	/// Same idiom as `derivedSignaturePublicKey` in SessionArchive.swift: this
	/// layer pins Ed25519 signing, so one hardcoded primitive is worth the
	/// fail-closed cross-check.
	private static func derivedEd25519Public(from signingKey: SecretBytes) throws -> Data {
		guard
			let privateKey = try? Curve25519.Signing.PrivateKey(
				rawRepresentation: signingKey)
		else { throw TwoMLSError.archiveInvalid }
		return privateKey.publicKey.rawRepresentation
	}

	/// X25519 public from a raw 32-B secret — the classical provider's own
	/// representation (any clamped 32 bytes is a valid scalar). No plaintext
	/// copy: `SecretBytes` is itself `ContiguousBytes`, exactly what the
	/// `rawRepresentation` initializer takes.
	private static func classicalPublic(from secretKey: SecretBytes) throws -> Data {
		guard secretKey.byteCount == 32 else { throw TwoMLSError.archiveInvalid }
		guard
			let key = try? Curve25519.KeyAgreement.PrivateKey(
				rawRepresentation: secretKey)
		else { throw TwoMLSError.archiveInvalid }
		return key.publicKey.rawRepresentation
	}

	/// ML-KEM-768 encapsulation key from the 96-B `integrityChecked-
	/// Representation` secret — the PQ provider's archival convention. A
	/// wrong/corrupt 96 bytes fails the integrity check (a CryptoKit error,
	/// folded here to fail-closed `archiveInvalid`).
	private static func pqPublic(from secretKey: SecretBytes) throws -> Data {
		guard
			let privateKey = try? secretKey.withUnsafeBytes({ raw in
				try MLKEM768.PrivateKey(integrityCheckedRepresentation: Data(raw))
			})
		else { throw TwoMLSError.archiveInvalid }
		return privateKey.publicKey.rawRepresentation
	}
}
