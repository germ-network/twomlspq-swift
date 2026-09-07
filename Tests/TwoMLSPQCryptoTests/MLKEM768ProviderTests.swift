import CryptoKit
import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes
import XCTest

@testable import TwoMLSPQCrypto

// XCTest (not swift-testing): its `@Test` macro rejects `@available`-gated
// functions, and this provider is `@available(iOS 26, macOS 26)`.
//
// NOTE: the whole class is `@available(iOS 26, macOS 26)`, so `swift test` on a
// host below macOS 26 SILENTLY skips it and reports green with 0 tests run. CI
// pins `runs-on: macos-26`; run these locally only on macOS 26+.
@available(iOS 26, macOS 26, *)
final class MLKEM768ProviderTests: XCTestCase {
	let provider = MLKEM768CipherSuiteProvider()
	/// swift-mls suite-1 — the symmetric stack `0xFDEA` reuses.
	let suite1 = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128)!

	private func rawBytes(_ secret: SecretBytes) -> Data { secret.withUnsafeBytes { Data($0) } }

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

	// MARK: - Identity / sizes

	func testCipherSuiteAndSizes() {
		XCTAssertEqual(provider.cipherSuite.id, 0xFDEA)
		XCTAssertEqual(provider.hashSize, 32)
		XCTAssertEqual(provider.aeadKeySize, 16)
		XCTAssertEqual(provider.aeadNonceSize, 12)
	}

	/// The HPKE `suite_id` is a load-bearing, never-transmitted domain separator.
	/// Pin the exact 10 bytes `"HPKE" ‖ 0xFDEA ‖ 0x0001 ‖ 0x0001`.
	func testHPKESuiteIDBytes() {
		XCTAssertEqual(
			MLKEM768CipherSuiteProvider.hpkeSuiteID,
			Data([0x48, 0x50, 0x4B, 0x45, 0xFD, 0xEA, 0x00, 0x01, 0x00, 0x01]))
	}

	/// The KEM `suite_id` used only by DeriveKeyPair: `"KEM" ‖ 0xFDEA`.
	func testKEMSuiteIDBytes() {
		XCTAssertEqual(
			MLKEM768CipherSuiteProvider.kemSuiteID,
			Data([0x4B, 0x45, 0x4D, 0xFD, 0xEA]))
	}

	func testGeneratedKeySizes() throws {
		let (secret, publicKey) = try provider.hpkeGenerateKeyPair()
		XCTAssertEqual(publicKey.data.count, 1184)  // ML-KEM-768 encapsulation key
		XCTAssertEqual(rawBytes(secret.data).count, 96)  // integrityCheckedRepresentation
	}

	// MARK: - HPKE base-mode round-trips

	func testHPKERoundTripNoAAD() throws {
		let (secret, publicKey) = try provider.hpkeGenerateKeyPair()
		let info = Data("test-info".utf8)
		let plaintext = Data("hello post-quantum world".utf8)
		let sealed = try provider.hpkeSeal(
			publicKey: publicKey, info: info, aad: nil, plaintext: plaintext)
		XCTAssertEqual(sealed.enc.count, 1088)  // ML-KEM ciphertext
		let opened = try provider.hpkeOpen(
			enc: sealed.enc, secretKey: secret, info: info, aad: nil,
			ciphertext: sealed.ciphertext)
		XCTAssertEqual(opened, plaintext)
	}

	func testHPKERoundTripWithAAD() throws {
		let (secret, publicKey) = try provider.hpkeGenerateKeyPair()
		let info = Data("info".utf8)
		let aad = Data("authenticated".utf8)
		let plaintext = Data("payload".utf8)
		let sealed = try provider.hpkeSeal(
			publicKey: publicKey, info: info, aad: aad, plaintext: plaintext)
		let opened = try provider.hpkeOpen(
			enc: sealed.enc, secretKey: secret, info: info, aad: aad,
			ciphertext: sealed.ciphertext)
		XCTAssertEqual(opened, plaintext)
	}

	// MARK: - Mutation / negative cases (each must break the right thing)

	func testWrongAADFailsToOpen() throws {
		let (secret, publicKey) = try provider.hpkeGenerateKeyPair()
		let info = Data("info".utf8)
		let sealed = try provider.hpkeSeal(
			publicKey: publicKey, info: info, aad: Data("aad".utf8),
			plaintext: Data("m".utf8))
		XCTAssertThrowsError(
			try provider.hpkeOpen(
				enc: sealed.enc, secretKey: secret, info: info,
				aad: Data("wrong".utf8),
				ciphertext: sealed.ciphertext))
	}

	func testWrongInfoFailsToOpen() throws {
		let (secret, publicKey) = try provider.hpkeGenerateKeyPair()
		let sealed = try provider.hpkeSeal(
			publicKey: publicKey, info: Data("info-a".utf8), aad: nil,
			plaintext: Data("m".utf8))
		XCTAssertThrowsError(
			try provider.hpkeOpen(
				enc: sealed.enc, secretKey: secret, info: Data("info-b".utf8),
				aad: nil,
				ciphertext: sealed.ciphertext))
	}

	func testWrongSecretKeyFailsToOpen() throws {
		let (_, publicKey) = try provider.hpkeGenerateKeyPair()
		let (otherSecret, _) = try provider.hpkeGenerateKeyPair()
		let info = Data("info".utf8)
		let sealed = try provider.hpkeSeal(
			publicKey: publicKey, info: info, aad: nil, plaintext: Data("m".utf8))
		XCTAssertThrowsError(
			try provider.hpkeOpen(
				enc: sealed.enc, secretKey: otherSecret, info: info, aad: nil,
				ciphertext: sealed.ciphertext))
	}

	func testTamperedCiphertextFailsToOpen() throws {
		let (secret, publicKey) = try provider.hpkeGenerateKeyPair()
		let info = Data("info".utf8)
		let sealed = try provider.hpkeSeal(
			publicKey: publicKey, info: info, aad: nil, plaintext: Data("message".utf8))
		var tampered = sealed.ciphertext
		tampered[tampered.startIndex] ^= 0x01
		XCTAssertThrowsError(
			try provider.hpkeOpen(
				enc: sealed.enc, secretKey: secret, info: info, aad: nil,
				ciphertext: tampered))
	}

	// MARK: - DeriveKeyPair

	func testDeriveIsDeterministic() throws {
		let ikm = Data(repeating: 0x2A, count: 32)
		let (secretA, publicA) = try provider.hpkeDeriveKeyPair(ikm: ikm)
		let (secretB, publicB) = try provider.hpkeDeriveKeyPair(ikm: ikm)
		XCTAssertEqual(publicA.data, publicB.data)
		XCTAssertEqual(rawBytes(secretA.data), rawBytes(secretB.data))
		XCTAssertEqual(publicA.data.count, 1184)
		XCTAssertEqual(rawBytes(secretA.data).count, 96)
	}

	func testDeriveDiffersByIKM() throws {
		let (_, publicA) = try provider.hpkeDeriveKeyPair(
			ikm: Data(repeating: 0x01, count: 32))
		let (_, publicB) = try provider.hpkeDeriveKeyPair(
			ikm: Data(repeating: 0x02, count: 32))
		XCTAssertNotEqual(publicA.data, publicB.data)
	}

	func testDerivedKeyPairRoundTripsThroughHPKE() throws {
		let ikm = Data(repeating: 0x37, count: 32)
		let (secret, publicKey) = try provider.hpkeDeriveKeyPair(ikm: ikm)
		let info = Data("derive-info".utf8)
		let plaintext = Data("derived-key message".utf8)
		let sealed = try provider.hpkeSeal(
			publicKey: publicKey, info: info, aad: nil, plaintext: plaintext)
		let opened = try provider.hpkeOpen(
			enc: sealed.enc, secretKey: secret, info: info, aad: nil,
			ciphertext: sealed.ciphertext)
		XCTAssertEqual(opened, plaintext)
	}

	// MARK: - Archive format (the load-bearing migration contract)

	/// The 96-byte secret is CryptoKit's `integrityCheckedRepresentation`:
	/// seed-bearing (first 64 bytes are the `d‖z` seed) and reconstructable to
	/// the same key. This is the exact format the deployed provider archives, so
	/// a blob produced there reconstructs here — the migration guarantee.
	func testArchiveIsSeedBearingAndReconstructs() throws {
		let (secret, publicKey) = try provider.hpkeGenerateKeyPair()
		let archive = rawBytes(secret.data)
		XCTAssertEqual(archive.count, 96)

		let reconstructed = try CryptoKit.MLKEM768.PrivateKey(
			integrityCheckedRepresentation: archive)
		// Reconstructs to the same public key.
		XCTAssertEqual(reconstructed.publicKey.rawRepresentation, publicKey.data)
		// The leading 64 bytes are the FIPS 203 `d‖z` seed.
		XCTAssertEqual(Data(reconstructed.seedRepresentation), archive.prefix(64))

		// And it decapsulates: encapsulate to the public key, decapsulate with the
		// reconstructed private key, secrets match.
		let encapsulation = try CryptoKit.MLKEM768.PublicKey(
			rawRepresentation: publicKey.data
		)
		.encapsulate()
		let ss = try reconstructed.decapsulate(encapsulation.encapsulated)
		XCTAssertEqual(
			ss.withUnsafeBytes { Data($0) },
			encapsulation.sharedSecret.withUnsafeBytes { Data($0) })
	}

	// MARK: - Known-answer vectors from the Rust oracle (cross-runtime conformance)

	/// Deterministic DeriveKeyPair KAT against the deployed Rust CryptoKit provider:
	/// a fixed `ikm` must yield the exact public key and 96-byte archive the oracle
	/// produces. Catches a wrong `dkp_prk` suite_id, a labeled-vs-plain expand, a wrong
	/// seed length, or `I2OSP` endianness — none of which a self-round-trip would see.
	func testDeriveKATMatchesRustOracle() throws {
		let ikm = Data(repeating: 0x2A, count: 32)
		let (secret, publicKey) = try provider.hpkeDeriveKeyPair(ikm: ikm)
		XCTAssertEqual(publicKey.data, hexData(RustOracleVectors.derivePublic))
		XCTAssertEqual(rawBytes(secret.data), hexData(RustOracleVectors.deriveSecret))
	}

	/// Open a ciphertext SEALED BY THE RUST ORACLE: reconstruct the oracle's 96-byte
	/// archive, decapsulate its `enc`, run the key schedule over its `info`, and recover
	/// the plaintext. Exercises the whole open path (archive reconstruction, decap,
	/// LabeledExtract/Expand, AEAD) against real oracle bytes, not a Swift self-seal.
	func testOpenFromRustOracle() throws {
		let secret = try MLS.HpkeSecretKey(hexData(RustOracleVectors.deriveSecret))
		let opened = try provider.hpkeOpen(
			enc: hexData(RustOracleVectors.sealEnc),
			secretKey: secret,
			info: hexData(RustOracleVectors.info),
			aad: nil,
			ciphertext: hexData(RustOracleVectors.sealCt))
		XCTAssertEqual(opened, hexData(RustOracleVectors.plaintext))
	}

	// MARK: - Symmetric parity with suite-1 (pins the forwarding wiring)

	func testHashMatchesSuite1() throws {
		let data = Data("the quick brown fox".utf8)
		XCTAssertEqual(try provider.hash(data), try suite1.hash(data))
	}

	func testKDFMatchesSuite1() throws {
		let salt = Data("salt".utf8)
		let ikm = Data("input key material".utf8)
		let prk = try provider.kdfExtract(salt: salt, ikm: ikm)
		XCTAssertEqual(prk, try suite1.kdfExtract(salt: salt, ikm: ikm))
		let info = Data("info".utf8)
		XCTAssertEqual(
			try provider.kdfExpand(prk: prk, info: info, length: 32),
			try suite1.kdfExpand(prk: prk, info: info, length: 32))
	}

	func testAEADMatchesSuite1() throws {
		let key = Data(repeating: 0x11, count: 16)
		let nonce = Data(repeating: 0x22, count: 12)
		let aad = Data("aad".utf8)
		let plaintext = Data("secret".utf8)
		let mine = try provider.aeadSeal(
			key: key, nonce: nonce, aad: aad, plaintext: plaintext)
		XCTAssertEqual(
			mine,
			try suite1.aeadSeal(key: key, nonce: nonce, aad: aad, plaintext: plaintext))
		XCTAssertEqual(
			try provider.aeadOpen(key: key, nonce: nonce, aad: aad, ciphertext: mine),
			plaintext)
	}

	func testSignVerifyRoundTrips() throws {
		let signingKey = Curve25519.Signing.PrivateKey()
		let secret = MLS.SignatureSecretKey(signingKey.rawRepresentation)
		let publicKey = MLS.SignaturePublicKey(signingKey.publicKey.rawRepresentation)
		let content = Data("sign me".utf8)
		let signature = try provider.sign(privateKey: secret, content: content)
		XCTAssertTrue(
			try provider.verify(
				publicKey: publicKey, content: content, signature: signature))
		XCTAssertFalse(
			try provider.verify(
				publicKey: publicKey, content: Data("other".utf8),
				signature: signature))
	}
}
