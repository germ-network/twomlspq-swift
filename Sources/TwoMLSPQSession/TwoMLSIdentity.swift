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
@available(iOS 26, macOS 26, *)
public struct TwoMLSIdentity: Sendable {
	public let clientID: Data
	public let signingKey: MLS.SignatureSecretKey
	public let signatureKey: MLS.SignaturePublicKey
	public let classicalLeafSecretKey: MLS.HpkeSecretKey
	public let classicalInitSecretKey: MLS.HpkeSecretKey
	public let pqLeafSecretKey: MLS.HpkeSecretKey
	public let pqInitSecretKey: MLS.HpkeSecretKey
	public let keyPackage: CombinerKeyPackage

	public var classicalJoinCredentials: MLS.RFC9420.Group.JoinerCredentials {
		.init(
			keyPackage: keyPackage.classical, initKey: classicalInitSecretKey,
			encryptionKey: classicalLeafSecretKey)
	}

	public var pqJoinCredentials: MLS.RFC9420.Group.JoinerCredentials {
		.init(
			keyPackage: keyPackage.pq, initKey: pqInitSecretKey,
			encryptionKey: pqLeafSecretKey)
	}

	/// The leaf capabilities every occupied leaf this module creates
	/// advertises: both suites (so either half's `KeyPackage` validates), the
	/// `APQInfo` GCE, and the `AppDataUpdate` proposal — group-rules rule 8
	/// ("every occupied leaf must advertise APQInfo + AppDataUpdate").
	/// Advertising a superset is always valid against the profile's
	/// `validatePolicy`.
	static var leafCapabilities: MLS.RFC9420.Capabilities {
		MLS.RFC9420.Capabilities(
			versions: [.mls10],
			cipherSuites: [
				.curve25519Aes128,
				MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID),
			],
			extensions: [MLS.Combiner.Codepoints.deployed.apqInfoExtensionType],
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

	/// Generate a fresh principal: one signing keypair, a leaf/init HPKE
	/// keypair per half, and both halves' signed `KeyPackage`s.
	public static func generate(
		clientID: Data,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> TwoMLSIdentity {
		let signingPrivateKey = Curve25519.Signing.PrivateKey()
		let signingKey = MLS.SignatureSecretKey(signingPrivateKey.rawRepresentation)
		let signatureKey = MLS.SignaturePublicKey(
			signingPrivateKey.publicKey.rawRepresentation)

		let (classicalLeafSecretKey, classicalLeafPublicKey) =
			try classicalProvider.hpkeGenerateKeyPair()
		let (classicalInitSecretKey, classicalInitPublicKey) =
			try classicalProvider.hpkeGenerateKeyPair()
		let (pqLeafSecretKey, pqLeafPublicKey) = try pqProvider.hpkeGenerateKeyPair()
		let (pqInitSecretKey, pqInitPublicKey) = try pqProvider.hpkeGenerateKeyPair()

		let classicalKeyPackage = try signedKeyPackage(
			cipherSuite: .curve25519Aes128, provider: classicalProvider,
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
