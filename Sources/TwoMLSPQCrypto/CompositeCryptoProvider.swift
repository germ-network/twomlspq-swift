import Foundation
import MLSCodec
import MLSCrypto

/// Routes classical suites to `SwiftCryptoProvider` and `0xFDEA` to
/// `MLKEM768CryptoProvider` — the single `MLS.CryptoProvider` the session
/// layer configures both combiner halves from.
@available(iOS 26, macOS 26, *)
public struct CompositeCryptoProvider: MLS.CryptoProvider {
	private let classical = SwiftCryptoProvider()
	private let pq = MLKEM768CryptoProvider()

	public init() {}

	public var supportedCipherSuites: [MLS.CipherSuite] {
		classical.supportedCipherSuites + pq.supportedCipherSuites
	}

	public func cipherSuiteProvider(for suite: MLS.CipherSuite) -> (
		any MLS.CipherSuiteProvider
	)? {
		suite.id == MLKEM768CipherSuiteProvider.cipherSuiteID
			? pq.cipherSuiteProvider(for: suite)
			: classical.cipherSuiteProvider(for: suite)
	}
}
