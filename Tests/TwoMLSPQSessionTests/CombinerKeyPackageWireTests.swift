import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import Testing

@testable import TwoMLSPQSession

/// The deployed Germ opaque combiner-blob framing — byte-compatible with the
/// Rust engine's `encode_combiner_key_package` / `decode_combiner_key_package`.
@Suite struct CombinerKeyPackageWireTests {
	/// A fresh identity per call, mirroring the XCTest `setUp` this replaces
	/// (which ran before every test method). Kept out of a stored property:
	/// `TwoMLSIdentity` is gated to iOS/macOS 26 and this suite type is not,
	/// so a stored property of that type would have to exist unconditionally.
	@available(iOS 26, macOS 26, *)
	private func makeIdentity() throws -> TwoMLSIdentity {
		try TwoMLSIdentity.generate(
			clientID: Data("combiner-blob-wire".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	@available(iOS 26, macOS 26, *)
	@Test func roundTripsThroughDeployedFraming() throws {
		let keyPackage = try makeIdentity().keyPackage
		let blob = try keyPackage.publishedBlob()

		let decoded = try #require(CombinerKeyPackage(publishedBlob: blob))
		#expect(decoded.classical == keyPackage.classical)
		#expect(decoded.pq == keyPackage.pq)
	}

	@available(iOS 26, macOS 26, *)
	@Test func blobIsByteStable() throws {
		let keyPackage = try makeIdentity().keyPackage
		let blob = try keyPackage.publishedBlob()
		let republished = try #require(CombinerKeyPackage(publishedBlob: blob))
			.publishedBlob()
		#expect(blob == republished)
	}

	@available(iOS 26, macOS 26, *)
	@Test func framingShape() throws {
		let keyPackage = try makeIdentity().keyPackage
		// [version byte = 3][varint len][classical MLSMessage][varint len][pq MLSMessage]
		let blob = try keyPackage.publishedBlob()
		#expect(blob.first == CombinerKeyPackage.publishedWireVersion)

		var reader = MLS.Reader(blob)
		#expect(try reader.readUInt8() == CombinerKeyPackage.publishedWireVersion)
		let classical = try reader.readOpaque()
		let pq = try reader.readOpaque()
		try reader.finish()  // no trailing bytes

		// Each half is a full MLSMessage envelope carrying a KeyPackage whose
		// suite matches the pure stack's declared suites.
		for (bytes, expected) in [(classical, TwoMLSSuite.classical), (pq, TwoMLSSuite.pq)]
		{
			var half = MLS.Reader(Data(bytes))
			let message = try MLS.RFC9420.Message(from: &half)
			try half.finish()
			guard case .keyPackage(let kp) = message else {
				Issue.record("half is not a keyPackage MLSMessage")
				return
			}
			#expect(kp.cipherSuite == expected)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsWrongVersionTruncationTrailingAndNonKeyPackage() throws {
		let identity = try makeIdentity()
		var blob = try identity.keyPackage.publishedBlob()

		// Wrong version byte (v2 = rejected AppBinding-cut predecessor).
		blob[0] = 2
		#expect(CombinerKeyPackage(publishedBlob: blob) == nil)
		blob[0] = CombinerKeyPackage.publishedWireVersion

		// Truncated / trailing bytes.
		#expect(CombinerKeyPackage(publishedBlob: blob.dropLast()) == nil)
		#expect(CombinerKeyPackage(publishedBlob: blob + Data([0])) == nil)

		// A bare MLSMessage (no Germ prefix) is not a blob.
		#expect(
			CombinerKeyPackage(
				publishedBlob: try MLS.RFC9420.Message.keyPackage(
					identity.keyPackage.classical
				).mlsEncoded()) == nil)
	}
}
