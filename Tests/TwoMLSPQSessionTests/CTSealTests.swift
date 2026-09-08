import Foundation
import MLSCodec
import MLSCrypto
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

// XCTest (not swift-testing): `@Test` rejects `@available`-gated functions,
// and `CTSeal` is `@available(iOS 26, macOS 26)` — see the other session
// tests' note on the same constraint.
@available(iOS 26, macOS 26, *)
final class CTSealTests: XCTestCase {
	private func rawBytes(_ secret: SecretBytes) -> Data { secret.withUnsafeBytes { Data($0) } }

	// MARK: - `ctSealKey` KAT (regression guard, classical provider = ChaCha)

	func testCtSealKeyKAT() throws {
		let kemSS = try SecretBytes(bytes: Data(repeating: 0x01, count: 32))
		let ctSealPSK = try SecretBytes(bytes: Data(repeating: 0x02, count: 32))
		let key = try CTSeal.ctSealKey(
			kemSS: kemSS, ctSealPSK: ctSealPSK,
			aead: SessionTestSupport.classicalProvider)
		XCTAssertEqual(key.count, SessionTestSupport.classicalProvider.aeadKeySize)
		XCTAssertEqual(SessionTestSupport.classicalProvider.aeadKeySize, 32)
		// Regression pin, not a cross-impl vector: captured from this
		// implementation (HKDF-Extract(salt: kemSS, ikm: ctSealPSK) then a
		// plain HKDF-Expand(info: keyInfo, 32) over ChaCha's classical
		// provider) with fixed all-0x01/all-0x02 inputs.
		XCTAssertEqual(
			key,
			Data(
				[
					0x5c, 0x1b, 0x8f, 0x72, 0xb5, 0xb2, 0xa2, 0x21,
					0x76, 0x93, 0xef, 0xd2, 0x2e, 0x3c, 0xb4, 0x7b,
					0xcb, 0x72, 0x6e, 0x72, 0xe8, 0x91, 0xd2, 0x4e,
					0x69, 0xbf, 0x1f, 0x56, 0xac, 0xbd, 0x36, 0x53,
				]))
	}

	// MARK: - `ctSealPSK` composition KAT (label / "exported" / Hash(context) / len)

	/// Pins the RFC 9420 §8.5 exporter composition against silent drift: a
	/// relabel (`pskLabel` or `"exported"`) or an unhashed context still
	/// interoperates Swift↔Swift, so the cross-party equality test in
	/// `RatchetTests` cannot catch it — this fixed vector over the pure
	/// `exporterSecret`/`groupID` core can. Regression pin (captured from this
	/// implementation), not yet a cross-impl Rust vector.
	func testCtSealPSKCompositionKAT() throws {
		let exporterSecret = try SecretBytes(bytes: Data(repeating: 0x03, count: 32))
		let groupID = Data([0xAA, 0xBB, 0xCC])
		let psk = try CTSeal.ctSealPSK(
			exporterSecret: exporterSecret, groupID: groupID,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(rawBytes(psk).count, 32)
		XCTAssertEqual(
			rawBytes(psk),
			Data(
				[
					0xbd, 0xa8, 0x37, 0xf0, 0x48, 0xfd, 0xff, 0x60,
					0x65, 0xdf, 0xc1, 0x38, 0xfd, 0xf4, 0x6e, 0xba,
					0x00, 0x76, 0x40, 0x56, 0x62, 0xff, 0xa4, 0x96,
					0x49, 0x5b, 0xc1, 0x8a, 0x3e, 0xc2, 0x16, 0x58,
				]))
	}

	// MARK: - seal/open round-trip

	// Chunk B: RatchetTests asserts cross-party ctSealPSK equality on a bootstrapped pair.
	func testSealOpenRoundTripRecoversS() throws {
		let (secretKey, ek) = try MLKEM768KEM.generateEphemeral()
		let ctSealPSK = try SecretBytes(bytes: Data(repeating: 0xAB, count: 32))
		let aead = SessionTestSupport.classicalProvider

		let (s, wireCT) = try CTSeal.seal(ek: ek, ctSealPSK: ctSealPSK, aead: aead)
		let opened = try CTSeal.open(
			wireCT: wireCT, secretKey: secretKey, ctSealPSK: ctSealPSK, aead: aead)
		XCTAssertEqual(rawBytes(s), rawBytes(opened))
		XCTAssertEqual(rawBytes(s).count, 32)
	}

	func testTamperedSealedFailsToOpen() throws {
		let (secretKey, ek) = try MLKEM768KEM.generateEphemeral()
		let ctSealPSK = try SecretBytes(bytes: Data(repeating: 0xAB, count: 32))
		let aead = SessionTestSupport.classicalProvider

		let (_, wireCT) = try CTSeal.seal(ek: ek, ctSealPSK: ctSealPSK, aead: aead)
		var tampered = wireCT
		tampered[tampered.index(before: tampered.endIndex)] ^= 0x01
		XCTAssertThrowsError(
			try CTSeal.open(
				wireCT: tampered, secretKey: secretKey, ctSealPSK: ctSealPSK,
				aead: aead)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
	}

	func testWrongCtSealPSKFailsToOpen() throws {
		let (secretKey, ek) = try MLKEM768KEM.generateEphemeral()
		let ctSealPSK = try SecretBytes(bytes: Data(repeating: 0xAB, count: 32))
		let wrongPSK = try SecretBytes(bytes: Data(repeating: 0xCD, count: 32))
		let aead = SessionTestSupport.classicalProvider

		let (_, wireCT) = try CTSeal.seal(ek: ek, ctSealPSK: ctSealPSK, aead: aead)
		XCTAssertThrowsError(
			try CTSeal.open(
				wireCT: wireCT, secretKey: secretKey, ctSealPSK: wrongPSK,
				aead: aead)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
	}

	// MARK: - Truncation

	/// Keep the intact `LE32` length header but truncate deep into the `enc`
	/// section — the declared `enc` length then overruns the buffer, and the
	/// bounds check must catch it before any KEM/AEAD work.
	func testTruncatedWireCTThrowsDecryptionFailed() throws {
		let (secretKey, ek) = try MLKEM768KEM.generateEphemeral()
		let ctSealPSK = try SecretBytes(bytes: Data(repeating: 0xAB, count: 32))
		let aead = SessionTestSupport.classicalProvider

		let (_, wireCT) = try CTSeal.seal(ek: ek, ctSealPSK: ctSealPSK, aead: aead)
		let truncated = wireCT.prefix(10)
		XCTAssertThrowsError(
			try CTSeal.open(
				wireCT: Data(truncated), secretKey: secretKey, ctSealPSK: ctSealPSK,
				aead: aead)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
	}

	func testUndersizedWireCTThrowsDecryptionFailed() throws {
		let (secretKey, _) = try MLKEM768KEM.generateEphemeral()
		let ctSealPSK = try SecretBytes(bytes: Data(repeating: 0xAB, count: 32))
		let aead = SessionTestSupport.classicalProvider

		XCTAssertThrowsError(
			try CTSeal.open(
				wireCT: Data([0x01, 0x02, 0x03]), secretKey: secretKey,
				ctSealPSK: ctSealPSK,
				aead: aead)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
	}
}
