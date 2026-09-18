import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// The deployed Germ opaque combiner-blob framing — byte-compatible with the
/// Rust engine's `encode_combiner_key_package` / `decode_combiner_key_package`.
@available(iOS 26, macOS 26, *)
final class CombinerKeyPackageWireTests: XCTestCase {
	private var identity: TwoMLSIdentity!

	private var keyPackage: CombinerKeyPackage { identity.keyPackage }

	override func setUp() {
		super.setUp()
		identity = try! TwoMLSIdentity.generate(
			clientID: Data("combiner-blob-wire".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	func testRoundTripsThroughDeployedFraming() throws {
		let blob = try keyPackage.publishedBlob()

		let decoded = try XCTUnwrap(CombinerKeyPackage(publishedBlob: blob))
		XCTAssertEqual(decoded.classical, keyPackage.classical)
		XCTAssertEqual(decoded.pq, keyPackage.pq)
	}

	func testBlobIsByteStable() throws {
		let blob = try keyPackage.publishedBlob()
		let republished = try CombinerKeyPackage(publishedBlob: blob)!.publishedBlob()
		XCTAssertEqual(blob, republished)
	}

	func testFramingShape() throws {
		// [version byte = 3][varint len][classical MLSMessage][varint len][pq MLSMessage]
		let blob = try keyPackage.publishedBlob()
		XCTAssertEqual(blob.first, CombinerKeyPackage.publishedWireVersion)

		var reader = MLS.Reader(blob)
		XCTAssertEqual(try reader.readUInt8(), CombinerKeyPackage.publishedWireVersion)
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
				return XCTFail("half is not a keyPackage MLSMessage")
			}
			XCTAssertEqual(kp.cipherSuite, expected)
		}
	}

	func testRejectsWrongVersionTruncationTrailingAndNonKeyPackage() throws {
		var blob = try identity.keyPackage.publishedBlob()

		// Wrong version byte (v2 = rejected AppBinding-cut predecessor).
		blob[0] = 2
		XCTAssertNil(CombinerKeyPackage(publishedBlob: blob))
		blob[0] = CombinerKeyPackage.publishedWireVersion

		// Truncated / trailing bytes.
		XCTAssertNil(CombinerKeyPackage(publishedBlob: blob.dropLast()))
		XCTAssertNil(CombinerKeyPackage(publishedBlob: blob + Data([0])))

		// A bare MLSMessage (no Germ prefix) is not a blob.
		XCTAssertNil(
			CombinerKeyPackage(
				publishedBlob: try MLS.RFC9420.Message.keyPackage(
					identity.keyPackage.classical
				).mlsEncoded()))
	}
}
