import Crypto
import Foundation
import XCTest

@testable import TwoMLSPQCrypto

// XCTest (not swift-testing): its `@Test` macro rejects `@available`-gated
// functions — see `MLKEM768ProviderTests`'s note on the same constraint.
//
// `import Crypto` (not CryptoKit) so `MLKEM768` here is the impl-agnostic
// type: CryptoKit on Apple, swift-crypto's BoringSSL off-Apple. On Apple,
// `Crypto` re-exports CryptoKit, so this run only PINS the archive structure
// and REGRESSES CryptoKit against the oracle (Crypto IS CryptoKit here) — it
// is not yet a cross-impl proof on this host. The genuine cross-impl leg
// (BoringSSL == FIPS oracle == CryptoKit) executes when this same test runs
// on the Android build. Do not overclaim cross-impl coverage from a run here.
@available(iOS 26, macOS 26, *)
final class MLKEM768CrossImplKATTests: XCTestCase {
	private func hexData(_ hex: String) -> Data {
		var out = Data(capacity: hex.count / 2)
		var index = hex.startIndex
		while index < hex.endIndex {
			let next = hex.index(index, offsetBy: 2)
			out.append(UInt8(hex[index..<next], radix: 16)!)
			index = next
		}
		return out
	}

	/// Pins the archive tail's exact construction — `d‖z (64B) ‖
	/// SHA3-256(encapsulation key) (32B)` — the load-bearing cross-impl
	/// structural fact, independent of which `MLKEM768` is active.
	func testArchiveTailIsSHA3OfPublicKey() {
		let secret = hexData(RustOracleVectors.deriveSecret)
		let pub = hexData(RustOracleVectors.derivePublic)
		XCTAssertEqual(secret.count, 96)
		XCTAssertEqual(pub.count, 1184)

		let seed = secret.prefix(64)
		let tail = secret.suffix(32)
		XCTAssertEqual(tail, Data(SHA3_256.hash(data: pub)))
		XCTAssertEqual(seed.count, 64)
	}

	/// Full 96-byte KAT via the swapped, impl-agnostic `MLKEM768`: the oracle's
	/// seed reconstructs the oracle's public key and its exact archive bytes.
	func testSeedReconstructsOracleArchive() throws {
		let secret = hexData(RustOracleVectors.deriveSecret)
		let pub = hexData(RustOracleVectors.derivePublic)
		let seed = secret.prefix(64)

		let key = try MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil)
		XCTAssertEqual(key.publicKey.rawRepresentation, pub)
		XCTAssertEqual(Data(key.seedRepresentation), Data(seed))
		XCTAssertEqual(Data(key.integrityCheckedRepresentation), secret)
	}

	/// Reconstruct round-trip: the oracle's full 96-byte archive rebuilds the
	/// same public key via the swapped `MLKEM768`.
	func testIntegrityCheckedRepresentationReconstructs() throws {
		let secret = hexData(RustOracleVectors.deriveSecret)
		let pub = hexData(RustOracleVectors.derivePublic)

		let recon = try MLKEM768.PrivateKey(integrityCheckedRepresentation: secret)
		XCTAssertEqual(recon.publicKey.rawRepresentation, pub)
	}
}
