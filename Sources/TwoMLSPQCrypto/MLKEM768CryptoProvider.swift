import Foundation
import MLSCodec
import MLSCrypto

/// A minimal `MLS.CryptoProvider` vending only the `0xFDEA` ML-KEM-768 suite.
///
/// Compose it with `SwiftCryptoProvider` (the classical suites) to route a full
/// APQ session: classical suites → `SwiftCryptoProvider`, `0xFDEA` → this. That
/// composite is intentionally left to the consuming layer.
@available(iOS 26, macOS 26, *)
public struct MLKEM768CryptoProvider: MLS.CryptoProvider {
	public init() {}

	public var supportedCipherSuites: [MLS.CipherSuite] {
		[MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID)]
	}

	public func cipherSuiteProvider(for suite: MLS.CipherSuite) -> (
		any MLS.CipherSuiteProvider
	)? {
		suite.id == MLKEM768CipherSuiteProvider.cipherSuiteID
			? MLKEM768CipherSuiteProvider()
			: nil
	}
}
