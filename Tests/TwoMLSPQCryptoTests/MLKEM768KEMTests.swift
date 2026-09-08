import CryptoKit
import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes
import XCTest

@testable import TwoMLSPQCrypto

// XCTest (not swift-testing): its `@Test` macro rejects `@available`-gated
// functions, and `MLKEM768KEM` is `@available(iOS 26, macOS 26)` — see
// `MLKEM768ProviderTests`'s note on the same constraint.
@available(iOS 26, macOS 26, *)
final class MLKEM768KEMTests: XCTestCase {
	private func rawBytes(_ secret: SecretBytes) -> Data { secret.withUnsafeBytes { Data($0) } }

	// MARK: - Round-trip

	func testEncapsulateDecapsulateRoundTrips() throws {
		let (secretKey, ek) = try MLKEM768KEM.generateEphemeral()
		let (sharedSecret, enc) = try MLKEM768KEM.encapsulate(to: ek)
		let recovered = try MLKEM768KEM.decapsulate(enc, secretKey: secretKey)
		XCTAssertEqual(rawBytes(sharedSecret), rawBytes(recovered))
	}

	/// ML-KEM decapsulate does NOT throw on a mismatched key — it always
	/// returns *some* 32-byte value, just not the sender's shared secret. A
	/// wrong/independent `secretKey` must yield a DIFFERENT shared secret, not
	/// a thrown error.
	func testDecapsulateWithWrongSecretKeyYieldsDifferentSecret() throws {
		let (_, ek) = try MLKEM768KEM.generateEphemeral()
		let (otherSecretKey, _) = try MLKEM768KEM.generateEphemeral()
		let (sharedSecret, enc) = try MLKEM768KEM.encapsulate(to: ek)
		let recovered = try MLKEM768KEM.decapsulate(enc, secretKey: otherSecretKey)
		XCTAssertNotEqual(rawBytes(sharedSecret), rawBytes(recovered))
	}

	// MARK: - Pinned sizes

	func testPinnedSizes() throws {
		let (secretKey, ek) = try MLKEM768KEM.generateEphemeral()
		XCTAssertEqual(ek.count, 1184)
		let (sharedSecret, enc) = try MLKEM768KEM.encapsulate(to: ek)
		XCTAssertEqual(enc.count, 1088)
		XCTAssertEqual(rawBytes(sharedSecret).count, 32)
		let recovered = try MLKEM768KEM.decapsulate(enc, secretKey: secretKey)
		XCTAssertEqual(rawBytes(recovered).count, 32)
	}
}
