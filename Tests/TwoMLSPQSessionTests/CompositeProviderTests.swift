import Foundation
import MLSCodec
import MLSCrypto
import XCTest

@testable import TwoMLSPQCrypto

// XCTest (not swift-testing): `@Test` rejects `@available`-gated functions,
// and `CompositeCryptoProvider` is `@available(iOS 26, macOS 26)`.
@available(iOS 26, macOS 26, *)
final class CompositeProviderTests: XCTestCase {
	let provider = CompositeCryptoProvider()

	func testSupportedCipherSuitesIsClassicalPlusPQ() {
		let expected =
			SwiftCryptoProvider().supportedCipherSuites
			+ [MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID)]
		XCTAssertEqual(provider.supportedCipherSuites, expected)
	}

	/// Dispatch by HPKE key size, not by type-check: `SwiftCryptoCipherSuiteProvider`
	/// is `internal` to `MLSCrypto`, unreachable from this module even
	/// `@testable`. A swapped dispatch predicate produces the wrong provider,
	/// which shows up as the wrong HPKE key size (ML-KEM-768: 1184 bytes;
	/// X25519: 32 bytes).
	func testDispatchRoutesPQSuiteToMLKEM768() throws {
		let pq = try XCTUnwrap(
			provider.cipherSuiteProvider(
				for: MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID))
		)
		let (_, publicKey) = try pq.hpkeGenerateKeyPair()
		XCTAssertEqual(publicKey.data.count, 1184)
	}

	func testDispatchRoutesClassicalSuitesToSwiftCryptoProvider() throws {
		let classical = try XCTUnwrap(provider.cipherSuiteProvider(for: .curve25519Aes128))
		let (_, publicKey) = try classical.hpkeGenerateKeyPair()
		XCTAssertEqual(publicKey.data.count, 32)
	}

	func testUnknownSuiteReturnsNil() {
		XCTAssertNil(provider.cipherSuiteProvider(for: MLS.CipherSuite(id: 0xFFFF)))
	}
}
