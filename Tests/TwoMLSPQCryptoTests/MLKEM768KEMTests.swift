import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes
import Testing

@testable import TwoMLSPQCrypto

@Suite struct MLKEM768KEMTests {
	private func rawBytes(_ secret: SecretBytes) -> Data { secret.withUnsafeBytes { Data($0) } }

	// MARK: - Round-trip

	@available(iOS 26, macOS 26, *)
	@Test func encapsulateDecapsulateRoundTrips() throws {
		let (secretKey, ek) = try MLKEM768KEM.generateEphemeral()
		let (sharedSecret, enc) = try MLKEM768KEM.encapsulate(to: ek)
		let recovered = try MLKEM768KEM.decapsulate(enc, secretKey: secretKey)
		#expect(rawBytes(sharedSecret) == rawBytes(recovered))
	}

	/// ML-KEM decapsulate does NOT throw on a mismatched key — it always
	/// returns *some* 32-byte value, just not the sender's shared secret. A
	/// wrong/independent `secretKey` must yield a DIFFERENT shared secret, not
	/// a thrown error.
	@available(iOS 26, macOS 26, *)
	@Test func decapsulateWithWrongSecretKeyYieldsDifferentSecret() throws {
		let (_, ek) = try MLKEM768KEM.generateEphemeral()
		let (otherSecretKey, _) = try MLKEM768KEM.generateEphemeral()
		let (sharedSecret, enc) = try MLKEM768KEM.encapsulate(to: ek)
		let recovered = try MLKEM768KEM.decapsulate(enc, secretKey: otherSecretKey)
		#expect(rawBytes(sharedSecret) != rawBytes(recovered))
	}

	// MARK: - Pinned sizes

	@available(iOS 26, macOS 26, *)
	@Test func pinnedSizes() throws {
		let (secretKey, ek) = try MLKEM768KEM.generateEphemeral()
		#expect(ek.count == 1184)
		let (sharedSecret, enc) = try MLKEM768KEM.encapsulate(to: ek)
		#expect(enc.count == 1088)
		#expect(rawBytes(sharedSecret).count == 32)
		let recovered = try MLKEM768KEM.decapsulate(enc, secretKey: secretKey)
		#expect(rawBytes(recovered).count == 32)
	}
}
