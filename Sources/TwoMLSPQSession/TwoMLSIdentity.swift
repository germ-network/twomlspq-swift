import Crypto
import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQCrypto

/// The classical and PQ halves of one party's `KeyPackage` — the unit
/// `CombinerGroup.establish`/`join` add/join per party.
public struct CombinerKeyPackage: Sendable {
	public var classical: MLS.RFC9420.KeyPackage
	public var pq: MLS.RFC9420.KeyPackage

	public init(classical: MLS.RFC9420.KeyPackage, pq: MLS.RFC9420.KeyPackage) {
		self.classical = classical
		self.pq = pq
	}
}

/// A party's principal: one Ed25519 signing keypair (both halves sign with
/// it — `0xFDEA` forwards signing to the same Ed25519 primitive, it is
/// confidentiality-only) plus a per-half HPKE leaf/init keypair, and the two
/// already-signed `KeyPackage`s built from them.
///
/// The two init secrets are join-only: each is read exactly once, to join
/// the group its own `KeyPackage` was added to (never to found one — that
/// takes only the leaf secret). A SESSION archive carries the classical one
/// only pre-establishment (`IdentityArchive`'s `includeInitSecrets: recvGroup
/// == nil` session path) — an in-flight initiator still needs it to join its
/// receive group after a restore. Once a SESSION's join has happened both are
/// `nil`ed (`clearingInitSecrets`) and the archive omits them, which is moot:
/// an invitation's identity is the SAME published key package's private
/// material across every welcome it accepts, so retaining an already-spent
/// init secret in a SESSION archive would needlessly widen one leaked
/// session archive's blast radius to the still-published key package. An
/// un-consumed INVITATION's identity is different: its init secrets are
/// still live (not yet spent by any join), and it IS archived with them
/// (`includeInitSecrets: true`) — they are exactly what lets a restored
/// invitation `receive` a welcome at all.
@available(iOS 26, macOS 26, *)
public struct TwoMLSIdentity: Sendable {
	public let clientID: Data
	public let signingKey: MLS.SignatureSecretKey
	public let signatureKey: MLS.SignaturePublicKey
	public let classicalLeafSecretKey: MLS.HpkeSecretKey
	public let classicalInitSecretKey: MLS.HpkeSecretKey?
	public let pqLeafSecretKey: MLS.HpkeSecretKey
	public let pqInitSecretKey: MLS.HpkeSecretKey?
	public let keyPackage: CombinerKeyPackage

	/// - Throws: `TwoMLSError.sessionNotReady` if the classical init secret
	///   was already cleared (this identity's classical KP was already
	///   joined with once).
	public var classicalJoinCredentials: MLS.RFC9420.Group.JoinerCredentials {
		get throws {
			guard let classicalInitSecretKey else { throw TwoMLSError.sessionNotReady }
			return .init(
				keyPackage: keyPackage.classical, initKey: classicalInitSecretKey,
				encryptionKey: classicalLeafSecretKey)
		}
	}

	/// - Throws: `TwoMLSError.sessionNotReady` if the PQ init secret was
	///   already cleared (this identity's PQ KP was already joined with
	///   once).
	public var pqJoinCredentials: MLS.RFC9420.Group.JoinerCredentials {
		get throws {
			guard let pqInitSecretKey else { throw TwoMLSError.sessionNotReady }
			return .init(
				keyPackage: keyPackage.pq, initKey: pqInitSecretKey,
				encryptionKey: pqLeafSecretKey)
		}
	}

	/// A copy with the named init secrets dropped — call once each is
	/// provably done being read (its own `KeyPackage` has been joined
	/// with), so a later archive of this identity never carries it.
	func clearingInitSecrets(classical: Bool, pq: Bool) -> TwoMLSIdentity {
		TwoMLSIdentity(
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			classicalLeafSecretKey: classicalLeafSecretKey,
			classicalInitSecretKey: classical ? nil : classicalInitSecretKey,
			pqLeafSecretKey: pqLeafSecretKey,
			pqInitSecretKey: pq ? nil : pqInitSecretKey, keyPackage: keyPackage)
	}

	/// The leaf capabilities every occupied leaf this module creates
	/// advertises: both suites (so either half's `KeyPackage` validates), the
	/// `APQInfo` GCE and the `AppDataUpdate` proposal — every occupied leaf
	/// must support both (book wire-format.md: "Every occupied leaf must
	/// advertise the `APQInfo` extension (`0xF0A1`) and the `AppDataUpdate`
	/// proposal (`0x0008`) types; a leaf that cannot support them is rejected
	/// rather than silently degraded") — and the `AppBinding` GCE (`0xF0A2`,
	/// book group-rules.md rule 8: "Leaves advertise the extension type, so a
	/// binding-carrying group can only ever contain capability-bearing
	/// leaves"). Advertising a superset is always valid against the profile's
	/// `validatePolicy`.
	static var leafCapabilities: MLS.RFC9420.Capabilities {
		MLS.RFC9420.Capabilities(
			versions: [.mls10],
			cipherSuites: [TwoMLSSuite.classical, TwoMLSSuite.pq],
			extensions: [
				MLS.Combiner.Codepoints.deployed.apqInfoExtensionType,
				AppBinding.extensionType,
			],
			proposals: [MLS.RFC9420.ProposalType(.appDataUpdate)],
			credentials: [MLS.RFC9420.CredentialType(.basic)])
	}

	/// Sign and build one half's `LeafNode` + `KeyPackage` — the
	/// `CombinerTestSupport.member(...)` recipe, ported into real code.
	private static func signedKeyPackage(
		cipherSuite: MLS.CipherSuite,
		provider: any MLS.CipherSuiteProvider,
		clientID: Data,
		signingKey: MLS.SignatureSecretKey,
		signatureKey: MLS.SignaturePublicKey,
		leafPublicKey: MLS.HpkePublicKey,
		initPublicKey: MLS.HpkePublicKey
	) throws -> MLS.RFC9420.KeyPackage {
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublicKey, signatureKey: signatureKey,
			credential: .basic(identity: clientID),
			capabilities: leafCapabilities,
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: cipherSuite, initKey: initPublicKey,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return keyPackage
	}

	/// Mint a fresh Ed25519 signing keypair — exactly `generate`'s signing
	/// half, factored out for a classical principal rotation (slice 6): a
	/// signature-key rotation needs only this, never a full `TwoMLSIdentity`
	/// (no `KeyPackage`, no HPKE leaf/init keys — swift-mls mints the rotated
	/// leaf's own encryption key inside `proposeUpdate`/`committing`).
	static func mintSignatureKeypair() throws -> (
		signingKey: MLS.SignatureSecretKey, signatureKey: MLS.SignaturePublicKey
	) {
		let signingPrivateKey = Curve25519.Signing.PrivateKey()
		let signingKey = try MLS.SignatureSecretKey(signingPrivateKey.rawRepresentation)
		let signatureKey = MLS.SignaturePublicKey(
			signingPrivateKey.publicKey.rawRepresentation)
		return (signingKey, signatureKey)
	}

	/// Mint a fresh combiner key-package bundle — fresh leaf/init HPKE
	/// secrets, fresh classical+PQ `KeyPackage`s — signed under an ALREADY
	/// existing signing identity. This is the shape `Principal` needs (book
	/// concepts.md: "credential-scoped signer"): every KP or session leaf it
	/// mints shares its one signing key, rather than each getting its own.
	public static func generate(
		clientID: Data,
		signingKey: MLS.SignatureSecretKey,
		signatureKey: MLS.SignaturePublicKey,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> TwoMLSIdentity {
		guard classicalProvider.cipherSuite == TwoMLSSuite.classical,
			pqProvider.cipherSuite == TwoMLSSuite.pq
		else { throw TwoMLSError.cipherSuiteMismatch }

		let (classicalLeafSecretKey, classicalLeafPublicKey) =
			try classicalProvider.hpkeGenerateKeyPair()
		let (classicalInitSecretKey, classicalInitPublicKey) =
			try classicalProvider.hpkeGenerateKeyPair()
		let (pqLeafSecretKey, pqLeafPublicKey) = try pqProvider.hpkeGenerateKeyPair()
		let (pqInitSecretKey, pqInitPublicKey) = try pqProvider.hpkeGenerateKeyPair()

		let classicalKeyPackage = try signedKeyPackage(
			cipherSuite: TwoMLSSuite.classical, provider: classicalProvider,
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			leafPublicKey: classicalLeafPublicKey, initPublicKey: classicalInitPublicKey
		)
		let pqKeyPackage = try signedKeyPackage(
			cipherSuite: MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID),
			provider: pqProvider, clientID: clientID, signingKey: signingKey,
			signatureKey: signatureKey, leafPublicKey: pqLeafPublicKey,
			initPublicKey: pqInitPublicKey)

		return TwoMLSIdentity(
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			classicalLeafSecretKey: classicalLeafSecretKey,
			classicalInitSecretKey: classicalInitSecretKey,
			pqLeafSecretKey: pqLeafSecretKey, pqInitSecretKey: pqInitSecretKey,
			keyPackage: CombinerKeyPackage(
				classical: classicalKeyPackage, pq: pqKeyPackage))
	}

	/// Generate a fresh, standalone principal identity: a fresh signing
	/// keypair plus the signing-key-scoped `generate` above's fresh KP
	/// bundle. Used directly by tests/internals that need no enclosing
	/// `Principal`; `Principal` itself always goes through the overload
	/// above, so every KP/leaf it mints shares its one signing key.
	public static func generate(
		clientID: Data,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> TwoMLSIdentity {
		let (signingKey, signatureKey) = try mintSignatureKeypair()
		return try generate(
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
	}

	/// Mint a fresh PQ `KeyPackage` KP′ — a brand-new leaf+init HPKE keypair
	/// (suite `0xFDEA`), signed with `self.signingKey`/`signatureKey` and
	/// `leafCapabilities` — distinct from `keyPackage.pq` (this identity's own
	/// leaf IN Group_A). KP′ is what the peer Adds into the new Group_B.pq at
	/// §A.3 bootstrap.
	public func freshPQKeyPackage(pqProvider: any MLS.CipherSuiteProvider) throws -> (
		keyPackage: MLS.RFC9420.KeyPackage, leafSecretKey: MLS.HpkeSecretKey,
		initSecretKey: MLS.HpkeSecretKey
	) {
		let (leafSecretKey, leafPublicKey) = try pqProvider.hpkeGenerateKeyPair()
		let (initSecretKey, initPublicKey) = try pqProvider.hpkeGenerateKeyPair()
		let keyPackage = try Self.signedKeyPackage(
			cipherSuite: MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID),
			provider: pqProvider, clientID: clientID, signingKey: signingKey,
			signatureKey: signatureKey, leafPublicKey: leafPublicKey,
			initPublicKey: initPublicKey)
		return (keyPackage, leafSecretKey, initSecretKey)
	}
}
