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

/// A freshly minted founding leaf: `mintFoundingLeaf`'s return shape, named
/// so `Establishment.swift`/`Bootstrap.swift`'s `founding:` test seams can
/// state it as a parameter type.
typealias FoundingLeaf = (
	leafNode: MLS.RFC9420.LeafNode, leafSecretKey: MLS.HpkeSecretKey, key: LeafKey
)

/// One combiner KeyPackage's private material: TWO independent Ed25519
/// signing keypairs, one per half (`signingKey`/`signatureKey` for the
/// classical half, `pqSigningKey`/`pqSignatureKey` for the PQ half; `0xFDEA`
/// forwards signing to the same Ed25519 primitive, it is
/// confidentiality-only, but the two halves never share a key) — plus a
/// per-half HPKE leaf/init keypair, and the two already-signed `KeyPackage`s
/// built from them. Each key is minted fresh for THIS bundle and lands only
/// in the one group that half joins: the classical half's key seeds
/// recv-classical (its return KP), the PQ half's seeds recv-PQ (as KP′) —
/// no group is FOUNDED on either (`TwoMLSIdentity.mintFoundingLeaf` mints
/// those separately). `Principal` holds no signing key of its own: every
/// `TwoMLSIdentity` it mints gets its own two fresh per-half keys, mirroring
/// a deployed Rust `CombinerClient`'s own per-`KeyPackage` signing pairs.
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
///
/// KP′ is `keyPackage.pq` itself, not a separate mint: `initiate` reads
/// `pqLeafSecretKey`/`pqInitSecretKey` straight off this bundle into
/// `bootstrapKPSecret`, so — until the §A.3 join spends it —
/// `bootstrapKPSecret.leafSecretKey` and `pqLeafSecretKey` are the SAME
/// secret (harmless: both name the one leaf KP′ actually is).
@available(iOS 26, macOS 26, *)
public struct TwoMLSIdentity: Sendable {
	public let clientID: Data
	public let signingKey: MLS.SignatureSecretKey
	public let signatureKey: MLS.SignaturePublicKey
	public let pqSigningKey: MLS.SignatureSecretKey
	public let pqSignatureKey: MLS.SignaturePublicKey
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
			pqSigningKey: pqSigningKey, pqSignatureKey: pqSignatureKey,
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
		leafCapabilities(advertising: [])
	}

	/// `leafCapabilities` plus the extension type of each profile in
	/// `profiles` — a classical leaf's capabilities (book group-rules.md
	/// rule 9: the classical key package's leaf carries the profile
	/// signal; PQ leaves stay on the base `leafCapabilities`).
	static func leafCapabilities(
		advertising profiles: [SessionProfile]
	) -> MLS.RFC9420.Capabilities {
		var capabilities = MLS.RFC9420.Capabilities(
			versions: [.mls10],
			cipherSuites: [TwoMLSSuite.classical, TwoMLSSuite.pq],
			extensions: [
				MLS.Combiner.Codepoints.deployed.apqInfoExtensionType,
				AppBinding.extensionType,
			],
			proposals: [MLS.RFC9420.ProposalType(.appDataUpdate)],
			credentials: [MLS.RFC9420.CredentialType(.basic)])
		capabilities.extensions += profiles.compactMap(\.extensionType)
		return capabilities
	}

	/// Sign one half's `LeafNode` under `signingKey` — the shared core of a
	/// KeyPackage half (`signedKeyPackage`, below) and a founding leaf
	/// (`mintFoundingLeaf`), which needs a signed leaf but no `KeyPackage`
	/// wrapper at all (a founding leaf has no init key).
	private static func signedLeaf(
		provider: any MLS.CipherSuiteProvider,
		clientID: Data,
		signingKey: MLS.SignatureSecretKey,
		signatureKey: MLS.SignaturePublicKey,
		leafPublicKey: MLS.HpkePublicKey,
		capabilities: MLS.RFC9420.Capabilities = leafCapabilities
	) throws -> MLS.RFC9420.LeafNode {
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublicKey, signatureKey: signatureKey,
			credential: .basic(identity: clientID),
			capabilities: capabilities,
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		return leaf
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
		initPublicKey: MLS.HpkePublicKey,
		capabilities: MLS.RFC9420.Capabilities = leafCapabilities
	) throws -> MLS.RFC9420.KeyPackage {
		let leaf = try signedLeaf(
			provider: provider, clientID: clientID, signingKey: signingKey,
			signatureKey: signatureKey, leafPublicKey: leafPublicKey,
			capabilities: capabilities)
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: cipherSuite, initKey: initPublicKey,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return keyPackage
	}

	/// Mint a fresh founding leaf: a brand-new Ed25519 signing pair and a
	/// brand-new HPKE leaf pair, signed into a `LeafNode` under
	/// `leafCapabilities` — the leaf a group is FOUNDED on (`Group.create`),
	/// never joined with. No init key, no `KeyPackage` wrapper: those only
	/// exist for a half a peer can Add from, and a founding leaf is never
	/// Added anywhere.
	static func mintFoundingLeaf(
		clientID: Data,
		provider: any MLS.CipherSuiteProvider,
		capabilities: MLS.RFC9420.Capabilities = leafCapabilities
	) throws -> FoundingLeaf {
		let (signingKey, signatureKey) = try mintSignatureKeypair()
		let (leafSecretKey, leafPublicKey) = try provider.hpkeGenerateKeyPair()
		let leaf = try signedLeaf(
			provider: provider, clientID: clientID, signingKey: signingKey,
			signatureKey: signatureKey, leafPublicKey: leafPublicKey,
			capabilities: capabilities)
		return (
			leaf, leafSecretKey,
			LeafKey(signingKey: signingKey, signatureKey: signatureKey)
		)
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
	/// secrets, fresh classical+PQ `KeyPackage`s — signed under two ALREADY
	/// existing, independent per-half signing identities. Factored out of
	/// the public keyless `generate` below, which is the only caller: every
	/// `TwoMLSIdentity` this module mints gets its own two fresh per-half
	/// keys, never a caller-supplied pair.
	private static func generate(
		clientID: Data,
		signingKey: MLS.SignatureSecretKey,
		signatureKey: MLS.SignaturePublicKey,
		pqSigningKey: MLS.SignatureSecretKey,
		pqSignatureKey: MLS.SignaturePublicKey,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		advertising profiles: [SessionProfile]
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
			leafPublicKey: classicalLeafPublicKey, initPublicKey: classicalInitPublicKey,
			capabilities: leafCapabilities(advertising: profiles)
		)
		let pqKeyPackage = try signedKeyPackage(
			cipherSuite: MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID),
			provider: pqProvider, clientID: clientID, signingKey: pqSigningKey,
			signatureKey: pqSignatureKey, leafPublicKey: pqLeafPublicKey,
			initPublicKey: pqInitPublicKey)

		return TwoMLSIdentity(
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			pqSigningKey: pqSigningKey, pqSignatureKey: pqSignatureKey,
			classicalLeafSecretKey: classicalLeafSecretKey,
			classicalInitSecretKey: classicalInitSecretKey,
			pqLeafSecretKey: pqLeafSecretKey, pqInitSecretKey: pqInitSecretKey,
			keyPackage: CombinerKeyPackage(
				classical: classicalKeyPackage, pq: pqKeyPackage))
	}

	/// Generate a fresh, standalone principal identity: two fresh, independent
	/// signing keypairs (classical + PQ) plus the signing-key-scoped
	/// `generate` above's fresh KP bundle. This is the only mint path:
	/// `Principal.generate`/`generateInvitation` call it directly, so every
	/// `TwoMLSIdentity` — every KP/leaf it mints — gets its own two fresh
	/// per-half keys, shared with no other bundle.
	public static func generate(
		clientID: Data,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> TwoMLSIdentity {
		try generate(
			clientID: clientID, classicalProvider: classicalProvider,
			pqProvider: pqProvider, advertising: [])
	}

	/// `generate` with the profiles its classical key package advertises
	/// named explicitly — the seam `Principal`'s public opt-in and the test
	/// support thread through.
	static func generate(
		clientID: Data,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		advertising profiles: [SessionProfile]
	) throws -> TwoMLSIdentity {
		let (signingKey, signatureKey) = try mintSignatureKeypair()
		let (pqSigningKey, pqSignatureKey) = try mintSignatureKeypair()
		return try generate(
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			pqSigningKey: pqSigningKey, pqSignatureKey: pqSignatureKey,
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			advertising: profiles)
	}
}
