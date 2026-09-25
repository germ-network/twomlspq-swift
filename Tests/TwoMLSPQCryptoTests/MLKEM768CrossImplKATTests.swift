import Crypto
import Foundation
import Testing

@testable import TwoMLSPQCrypto

// `import Crypto` (not CryptoKit) so `MLKEM768` here is the impl-agnostic
// type: CryptoKit on Apple, swift-crypto's BoringSSL off-Apple. On Apple,
// `Crypto` re-exports CryptoKit, so this run only PINS the archive structure
// and REGRESSES CryptoKit against the oracle (Crypto IS CryptoKit here) — it
// is not yet a cross-impl proof on this host. The genuine cross-impl leg
// (BoringSSL == FIPS oracle == CryptoKit) executes when this same test runs
// on the Android build. Do not overclaim cross-impl coverage from a run here.
@Suite struct MLKEM768CrossImplKATTests {
	private func hexData(_ hex: String) throws -> Data {
		var out = Data(capacity: hex.count / 2)
		var index = hex.startIndex
		while index < hex.endIndex {
			let next = hex.index(index, offsetBy: 2)
			out.append(try #require(UInt8(hex[index..<next], radix: 16)))
			index = next
		}
		return out
	}

	/// Pins the archive tail's exact construction — `d‖z (64B) ‖
	/// SHA3-256(encapsulation key) (32B)` — the load-bearing cross-impl
	/// structural fact, independent of which `MLKEM768` is active.
	@available(iOS 26, macOS 26, *)
	@Test func archiveTailIsSHA3OfPublicKey() throws {
		let secret = try hexData(RustOracleVectors.deriveSecret)
		let pub = try hexData(RustOracleVectors.derivePublic)
		#expect(secret.count == 96)
		#expect(pub.count == 1184)

		let seed = secret.prefix(64)
		let tail = secret.suffix(32)
		#expect(tail == Data(SHA3_256.hash(data: pub)))
		#expect(seed.count == 64)
	}

	/// Full 96-byte KAT via the swapped, impl-agnostic `MLKEM768`: the oracle's
	/// seed reconstructs the oracle's public key and its exact archive bytes.
	@available(iOS 26, macOS 26, *)
	@Test func seedReconstructsOracleArchive() throws {
		let secret = try hexData(RustOracleVectors.deriveSecret)
		let pub = try hexData(RustOracleVectors.derivePublic)
		let seed = secret.prefix(64)

		let key = try MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil)
		#expect(key.publicKey.rawRepresentation == pub)
		#expect(Data(key.seedRepresentation) == Data(seed))
		#expect(Data(key.integrityCheckedRepresentation) == secret)
	}

	/// Reconstruct round-trip: the oracle's full 96-byte archive rebuilds the
	/// same public key via the swapped `MLKEM768`.
	@available(iOS 26, macOS 26, *)
	@Test func integrityCheckedRepresentationReconstructs() throws {
		let secret = try hexData(RustOracleVectors.deriveSecret)
		let pub = try hexData(RustOracleVectors.derivePublic)

		let recon = try MLKEM768.PrivateKey(integrityCheckedRepresentation: secret)
		#expect(recon.publicKey.rawRepresentation == pub)
	}
}
