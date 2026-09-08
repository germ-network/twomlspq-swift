import CryptoKit
import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes

/// A raw ML-KEM-768 ephemeral KEM, independent of the HPKE assembly in
/// `MLKEM768CipherSuiteProvider` — §A.4's ratchet legs exchange a bare
/// encapsulation key / ciphertext pair, not an HPKE-sealed message. Mirrors
/// that provider's `CryptoKit.MLKEM768` usage exactly (fully qualified, same
/// archival format), so it inherits the same cross-runtime reconstruction
/// guarantee and the same `@available` floor.
@available(iOS 26, macOS 26, *)
public enum MLKEM768KEM {
	/// Generate a fresh ephemeral key pair. `ek` is the 1184-byte encapsulation
	/// key; the secret key is held as `MLS.HpkeSecretKey` (SecretBytes-backed,
	/// Sendable) via CryptoKit's 96-byte `integrityCheckedRepresentation`.
	public static func generateEphemeral() throws -> (secretKey: MLS.HpkeSecretKey, ek: Data) {
		let key = try CryptoKit.MLKEM768.PrivateKey()
		let secretKey = try MLS.HpkeSecretKey(key.integrityCheckedRepresentation)
		return (secretKey, key.publicKey.rawRepresentation)
	}

	/// Encapsulate to a peer's `ek`, yielding a fresh 32-byte shared secret and
	/// the 1088-byte ciphertext to send.
	public static func encapsulate(to ek: Data) throws -> (sharedSecret: SecretBytes, enc: Data)
	{
		let recipient = try CryptoKit.MLKEM768.PublicKey(rawRepresentation: ek)
		let encapsulation = try recipient.encapsulate()
		let sharedSecret = try SecretBytes(bytes: encapsulation.sharedSecret)
		return (sharedSecret, encapsulation.encapsulated)
	}

	/// Decapsulate `enc` with `secretKey`. ML-KEM decapsulation never throws on
	/// a mismatched/garbled `enc` — it always returns *some* 32-byte value, just
	/// not the sender's shared secret. Callers relying on this as an
	/// authenticator (e.g. `CTSeal.open`'s AEAD) must not treat a return here as
	/// proof of anything.
	public static func decapsulate(_ enc: Data, secretKey: MLS.HpkeSecretKey) throws
		-> SecretBytes
	{
		let privateKey = try secretKey.data.withUnsafeBytes { raw in
			try CryptoKit.MLKEM768.PrivateKey(integrityCheckedRepresentation: Data(raw))
		}
		let sharedSecret = try privateKey.decapsulate(enc)
		return try SecretBytes(bytes: sharedSecret)
	}
}
