import Foundation
import MLSCodec
import MLSCrypto
import Testing

@testable import TwoMLSPQCrypto

@Suite struct CompositeProviderTests {
	@available(iOS 26, macOS 26, *)
	private var provider: CompositeCryptoProvider { CompositeCryptoProvider() }

	@available(iOS 26, macOS 26, *)
	@Test func supportedCipherSuitesIsClassicalPlusPQ() {
		let expected =
			SwiftCryptoProvider().supportedCipherSuites
			+ [MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID)]
		#expect(provider.supportedCipherSuites == expected)
	}

	/// Dispatch by HPKE key size, not by type-check: `SwiftCryptoCipherSuiteProvider`
	/// is `internal` to `MLSCrypto`, unreachable from this module even
	/// `@testable`. A swapped dispatch predicate produces the wrong provider,
	/// which shows up as the wrong HPKE key size (ML-KEM-768: 1184 bytes;
	/// X25519: 32 bytes).
	@available(iOS 26, macOS 26, *)
	@Test func dispatchRoutesPQSuiteToMLKEM768() throws {
		let raw = provider.cipherSuiteProvider(
			for: MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID))
		let pq = try #require(raw)
		let (_, publicKey) = try pq.hpkeGenerateKeyPair()
		#expect(publicKey.data.count == 1184)
	}

	@available(iOS 26, macOS 26, *)
	@Test func dispatchRoutesClassicalSuitesToSwiftCryptoProvider() throws {
		let raw = provider.cipherSuiteProvider(for: .curve25519ChaCha)
		let classical = try #require(raw)
		let (_, publicKey) = try classical.hpkeGenerateKeyPair()
		#expect(publicKey.data.count == 32)
	}

	@available(iOS 26, macOS 26, *)
	@Test func unknownSuiteReturnsNil() {
		#expect(provider.cipherSuiteProvider(for: MLS.CipherSuite(id: 0xFFFF)) == nil)
	}
}
