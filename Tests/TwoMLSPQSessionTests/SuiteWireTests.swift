import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// Pins the on-wire classical suite to `0x0003` (curve25519ChaCha, the
/// Rust-compat suite) end to end: the RFC 9420 Welcome's own `cipher_suite`
/// field, both parties' live group contexts, the `APQInfo` GCE, and the
/// `KeyPackage`/capabilities each identity advertises. Every assertion below
/// is a literal, not `TwoMLSSuite.classical`/`.pq` — comparing against the
/// same constant under test would not catch a regression in that constant
/// itself. Fails if the classical suite ever regresses to `0x0001`
/// (curve25519Aes128).
@available(iOS 26, macOS 26, *)
final class SuiteWireTests: XCTestCase {
	func testClassicalSuiteIsPinnedAcrossWelcomeGroupsAndKeyPackage() throws {
		let (alice, bob, identity, _, welcomeA, welcomeB) =
			try SessionTestSupport.established()

		// RFC 9420 Welcome.cipher_suite: a plain uint16, big-endian on the wire.
		let (tBytesA, _) = try Frames.decodeAPQWelcome(welcomeA)
		XCTAssertEqual(tBytesA.prefix(2), Data([0x00, 0x03]))
		XCTAssertEqual(try MLS.RFC9420.Welcome(mlsEncoded: tBytesA).cipherSuite.id, 0x0003)

		let (tBytesB, _) = try Frames.decodeAPQWelcome(welcomeB)
		XCTAssertEqual(tBytesB.prefix(2), Data([0x00, 0x03]))
		XCTAssertEqual(try MLS.RFC9420.Welcome(mlsEncoded: tBytesB).cipherSuite.id, 0x0003)

		// Live group contexts: Group_A (both halves, both sides) and Group_B
		// (classical-only, Bob's founder copy).
		let groupA = try XCTUnwrap(alice.sendGroup)
		XCTAssertEqual(groupA.classical.context.cipherSuite.id, 0x0003)
		XCTAssertEqual(try XCTUnwrap(groupA.pq).context.cipherSuite.id, 0xFDEA)

		let bobGroupA = try XCTUnwrap(bob.recvGroup)
		XCTAssertEqual(bobGroupA.classical.context.cipherSuite.id, 0x0003)

		let bobGroupB = try XCTUnwrap(bob.sendGroup)
		XCTAssertEqual(bobGroupB.classical.context.cipherSuite.id, 0x0003)

		// The APQInfo GCE, read off both Group_A's and Group_B's classical half.
		let groupAInfo = try XCTUnwrap(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: groupA.classical.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))
		XCTAssertEqual(groupAInfo.tCipherSuite.id, 0x0003)

		let groupBInfo = try XCTUnwrap(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: bobGroupB.classical.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))
		XCTAssertEqual(groupBInfo.tCipherSuite.id, 0x0003)

		// The identity's own signed KeyPackage + advertised leaf capabilities.
		XCTAssertEqual(identity.keyPackage.classical.cipherSuite.id, 0x0003)
		XCTAssertEqual(
			identity.keyPackage.classical.leafNode.capabilities.cipherSuites.map(\.id),
			[0x0003, 0xFDEA])
	}

	func testProviderAeadKeySizesMatchDeployedSuites() {
		XCTAssertEqual(SessionTestSupport.classicalProvider.aeadKeySize, 32)
		XCTAssertEqual(SessionTestSupport.pqProvider.aeadKeySize, 16)
	}

	/// `TwoMLSIdentity.generate` rejects a classical provider whose suite is
	/// not `TwoMLSSuite.classical`, before claiming any state — the up-front
	/// guard mirroring the Rust reference's early `CipherSuiteMismatch`.
	func testGenerateRejectsWrongClassicalProvider() throws {
		let wrongClassicalProvider = try XCTUnwrap(
			SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128))

		XCTAssertThrowsError(
			try TwoMLSIdentity.generate(
				clientID: Data("carol".utf8),
				classicalProvider: wrongClassicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .cipherSuiteMismatch)
		}
	}
}
