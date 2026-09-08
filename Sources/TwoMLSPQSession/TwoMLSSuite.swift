import MLSCodec
import MLSCrypto
import TwoMLSPQCrypto

/// The two cipher suites this module ever deploys — the single source of
/// truth `TwoMLSIdentity`/`TwoMLSSession`/`APQGroup` build `KeyPackage`s,
/// leaf capabilities, and `APQInfo` checks against, instead of each holding
/// its own copy of the suite literal.
@available(iOS 26, macOS 26, *)
enum TwoMLSSuite {
	/// `0x0003` — `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`,
	/// matching the deployed Rust reference's `CURVE25519_CHACHA`.
	static let classical = MLS.CipherSuite.curve25519ChaCha
	/// `0xFDEA` — the private-range ML-KEM-768 suite.
	static let pq = MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID)
}
