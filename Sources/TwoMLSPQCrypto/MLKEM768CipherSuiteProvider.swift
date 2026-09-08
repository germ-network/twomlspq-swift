import CryptoKit
import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes

/// `MLS.CipherSuiteProvider` for the private-range post-quantum suite
/// `0xFDEA` = `MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519`.
///
/// ML-KEM-768 (Apple CryptoKit) is the only KEM-specific work. The symmetric
/// half — HKDF-SHA256 / AES-128-GCM / SHA-256 / Ed25519 — is byte-for-byte
/// swift-mls suite-1's (`.curve25519Aes128`), so it is reused wholesale by
/// forwarding to that provider rather than reimplemented. RFC 9180 base-mode
/// HPKE is assembled here over the ML-KEM KEM, matching the deployed mls-rs
/// CryptoKit provider (`Hpke<MlKem768Kem, HKDF-SHA256, AES-128-GCM>`).
///
/// Uses Apple CryptoKit's ML-KEM (not swift-crypto's own): the archived secret
/// is CryptoKit's 96-byte `integrityCheckedRepresentation`, and reconstructing
/// a blob produced by the deployed provider requires the same implementation.
/// Hence `@available(iOS 26, macOS 26)`, where CryptoKit ML-KEM ships. `MLKEM768`
/// is written fully qualified as `CryptoKit.MLKEM768` so a future `import Crypto`
/// cannot silently rebind it to swift-crypto's BoringSSL type, whose integrity
/// bytes need not match Apple's — which would break cross-runtime reconstruction.
@available(iOS 26, macOS 26, *)
public struct MLKEM768CipherSuiteProvider: MLS.CipherSuiteProvider {
	/// The private-range MLS cipher-suite id for ML-KEM-768.
	public static let cipherSuiteID: UInt16 = 0xFDEA

	/// FIPS 203 ML-KEM-768 KeyGen seed (`d ‖ z`) length, the input CryptoKit's
	/// `seedRepresentation` initializer expects.
	static let mlKemSeedSize = 64

	/// RFC 9180 §5.1 HPKE `suite_id = "HPKE" ‖ kem_id ‖ kdf_id ‖ aead_id`: kem_id
	/// `0xFDEA`, kdf_id `0x0001` (HKDF-SHA256), aead_id `0x0001` (AES-128-GCM) —
	/// the 10-byte string `48 50 4B 45 FD EA 00 01 00 01`. Never transmitted; a KDF
	/// domain separator recomputed identically by both peers. Built with swift-mls's
	/// provider-authoring toolkit.
	static let hpkeSuiteID = MLS.hpkeSuiteID(
		kemID: cipherSuiteID, kdfID: 0x0001, aeadID: 0x0001)

	/// RFC 9180 §4.1 KEM `suite_id = "KEM" ‖ kem_id`, used only by DeriveKeyPair
	/// (`4B 45 4D FD EA`) — never on the seal/open path.
	static let kemSuiteID = MLS.hpkeKEMSuiteID(kemID: cipherSuiteID)

	/// swift-mls suite-1 — the symmetric stack `0xFDEA` shares byte-for-byte.
	private let symmetric: any MLS.CipherSuiteProvider

	public init() {
		// Force-unwrap is safe: `.curve25519Aes128` is always in
		// `SwiftCryptoProvider.supportedCipherSuites`.
		self.symmetric = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!
	}

	public var cipherSuite: MLS.CipherSuite { MLS.CipherSuite(id: Self.cipherSuiteID) }

	// MARK: - Symmetric primitives (reused from suite-1, verified identical)

	public var hashSize: Int { symmetric.hashSize }
	public var aeadKeySize: Int { symmetric.aeadKeySize }
	public var aeadNonceSize: Int { symmetric.aeadNonceSize }

	public func randomBytes(_ count: Int) -> Data { symmetric.randomBytes(count) }
	public func hash(_ data: Data) throws -> Data { try symmetric.hash(data) }

	public func kdfExtract(salt: some ContiguousBytes, ikm: some ContiguousBytes) throws -> Data
	{
		try symmetric.kdfExtract(salt: salt, ikm: ikm)
	}
	public func kdfExpand(prk: some ContiguousBytes, info: Data, length: Int) throws -> Data {
		try symmetric.kdfExpand(prk: prk, info: info, length: length)
	}
	public func kdfExtractSecret(salt: some ContiguousBytes, ikm: some ContiguousBytes) throws
		-> SecretBytes
	{
		try symmetric.kdfExtractSecret(salt: salt, ikm: ikm)
	}
	public func kdfExpandSecret(prk: some ContiguousBytes, info: Data, length: Int) throws
		-> SecretBytes
	{
		try symmetric.kdfExpandSecret(prk: prk, info: info, length: length)
	}

	public func sign(privateKey: MLS.SignatureSecretKey, content: Data) throws -> Data {
		try symmetric.sign(privateKey: privateKey, content: content)
	}
	public func verify(publicKey: MLS.SignaturePublicKey, content: Data, signature: Data) throws
		-> Bool
	{
		try symmetric.verify(publicKey: publicKey, content: content, signature: signature)
	}

	public func aeadSeal(key: Data, nonce: Data, aad: Data?, plaintext: Data) throws -> Data {
		try symmetric.aeadSeal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
	}
	public func aeadOpen(key: Data, nonce: Data, aad: Data?, ciphertext: Data) throws -> Data {
		try symmetric.aeadOpen(key: key, nonce: nonce, aad: aad, ciphertext: ciphertext)
	}

	// MARK: - KEM (ML-KEM-768, Apple CryptoKit)

	public func hpkeGenerateKeyPair() throws -> (MLS.HpkeSecretKey, MLS.HpkePublicKey) {
		let key = try CryptoKit.MLKEM768.PrivateKey()
		return (
			try MLS.HpkeSecretKey(key.integrityCheckedRepresentation),
			MLS.HpkePublicKey(key.publicKey.rawRepresentation)
		)
	}

	public func hpkeDeriveKeyPair(ikm: some ContiguousBytes) throws -> (
		MLS.HpkeSecretKey, MLS.HpkePublicKey
	) {
		// Mirrors mls-rs `Hpke::derive`: dkp_prk = LabeledExtract(KEM suite_id,
		// "dkp_prk", ikm), then ML-KEM KeyGen from a 64-byte seed. CryptoKit needs
		// `d‖z` (64 B), but dkp_prk is HKDF-SHA256's 32-byte extract, so expand it
		// to 64 with a plain HKDF-Expand (empty info) — exactly what the deployed
		// provider's `generate_deterministic` does for a non-64-byte input.
		// RFC 9180 §4 LabeledExtract concatenates `ikm` into the byte string it
		// hashes, so the seed must be materialized as `Data` for the hash input
		// regardless of custody — the same inherent copy swift-mls's own provider
		// makes, not a stray plaintext copy of a long-lived secret.
		let ikmData = ikm.withUnsafeBytes { Data($0) }
		let dkpPRK = try hpkeLabeledExtract(
			suiteID: Self.kemSuiteID, salt: Data(), label: "dkp_prk", ikm: ikmData)
		let seed = try kdfExpand(prk: dkpPRK, info: Data(), length: Self.mlKemSeedSize)
		let key = try CryptoKit.MLKEM768.PrivateKey(
			seedRepresentation: seed, publicKey: nil)
		return (
			try MLS.HpkeSecretKey(key.integrityCheckedRepresentation),
			MLS.HpkePublicKey(key.publicKey.rawRepresentation)
		)
	}

	// MARK: - HPKE (RFC 9180 base mode over ML-KEM)

	public func hpkeSeal(publicKey: MLS.HpkePublicKey, info: Data, aad: Data?, plaintext: Data)
		throws -> (enc: Data, ciphertext: Data)
	{
		let recipient = try CryptoKit.MLKEM768.PublicKey(rawRepresentation: publicKey.data)
		let encapsulation = try recipient.encapsulate()
		let sharedSecret = try SecretBytes(bytes: encapsulation.sharedSecret)
		let schedule = try keySchedule(sharedSecret: sharedSecret, info: info)
		let ciphertext = try aeadSeal(
			key: schedule.key, nonce: schedule.baseNonce, aad: aad, plaintext: plaintext
		)
		// `enc` = ML-KEM ciphertext (1088 B); `ciphertext` = AEAD ct‖tag.
		return (enc: encapsulation.encapsulated, ciphertext: ciphertext)
	}

	public func hpkeOpen(
		enc: Data, secretKey: MLS.HpkeSecretKey, info: Data, aad: Data?, ciphertext: Data
	) throws -> Data {
		let privateKey = try secretKey.data.withUnsafeBytes { raw in
			try CryptoKit.MLKEM768.PrivateKey(integrityCheckedRepresentation: raw)
		}
		let sharedSecret = try SecretBytes(bytes: privateKey.decapsulate(enc))
		let schedule = try keySchedule(sharedSecret: sharedSecret, info: info)
		return try aeadOpen(
			key: schedule.key, nonce: schedule.baseNonce, aad: aad,
			ciphertext: ciphertext)
	}

	// MARK: - RFC 9180 base-mode key schedule (labeled KDF from swift-mls)

	/// RFC 9180 §5.1 base-mode key schedule with an empty PSK. Returns only the
	/// AEAD `key` and `base_nonce` — single-shot seal/open uses sequence 0, so
	/// the nonce is `base_nonce` unchanged, and the seam needs no exporter secret.
	private func keySchedule(sharedSecret: SecretBytes, info: Data) throws -> (
		key: Data, baseNonce: Data
	) {
		let suiteID = Self.hpkeSuiteID
		let pskIDHash = try hpkeLabeledExtract(
			suiteID: suiteID, salt: Data(), label: "psk_id_hash", ikm: Data())
		let infoHash = try hpkeLabeledExtract(
			suiteID: suiteID, salt: Data(), label: "info_hash", ikm: info)
		let secret = try hpkeLabeledExtract(
			suiteID: suiteID, salt: sharedSecret, label: "secret", ikm: Data())
		// key_schedule_context = mode ‖ psk_id_hash ‖ info_hash, mode 0x00 = base.
		let context = Data([0x00]) + pskIDHash + infoHash
		let key = try hpkeLabeledExpand(
			suiteID: suiteID, prk: secret, label: "key", info: context,
			length: aeadKeySize)
		let baseNonce = try hpkeLabeledExpand(
			suiteID: suiteID, prk: secret, label: "base_nonce", info: context,
			length: aeadNonceSize)
		return (key, baseNonce)
	}
}
