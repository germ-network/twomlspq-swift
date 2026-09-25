import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import Testing

@testable import TwoMLSPQSession

/// Pins the on-wire classical suite to `0x0003` (curve25519ChaCha, the
/// Rust-compat suite) end to end: the RFC 9420 Welcome's own `cipher_suite`
/// field, both parties' live group contexts, the `APQInfo` GCE, and the
/// `KeyPackage`/capabilities each identity advertises. Every assertion below
/// is a literal, not `TwoMLSSuite.classical`/`.pq` — comparing against the
/// same constant under test would not catch a regression in that constant
/// itself. Fails if the classical suite ever regresses to `0x0001`
/// (curve25519Aes128).
@Suite struct SuiteWireTests {
	@available(iOS 26, macOS 26, *)
	@Test func classicalSuiteIsPinnedAcrossWelcomeGroupsAndKeyPackage() throws {
		let (alice, bob, identity, _, welcomeA, welcomeB) =
			try SessionTestSupport.established()

		// RFC 9420 Welcome.cipher_suite: a plain uint16, big-endian on the wire.
		let (tBytesA, pqBytesA) = try Frames.decodeAPQWelcome(welcomeA)
		#expect(tBytesA.prefix(6) == Data([0x00, 0x01, 0x00, 0x03, 0x00, 0x03]))
		#expect(
			try EstablishmentMessages.decodeWelcome(tBytesA).cipherSuite.id == 0x0003)

		// The pq half pins its own prefix too — decoded via `MLS.RFC9420.Message`
		// directly rather than the helper, so this pin cannot pass on a bare
		// (unwrapped) pq half that the helper alone would still refuse.
		#expect(pqBytesA.prefix(6) == Data([0x00, 0x01, 0x00, 0x03, 0xFD, 0xEA]))
		guard case .welcome(let pqWelcomeA) = try MLS.RFC9420.Message(mlsEncoded: pqBytesA)
		else {
			Issue.record("expected the pq half to decode as a welcome message")
			return
		}
		#expect(pqWelcomeA.cipherSuite.id == 0xFDEA)

		let (tBytesB, _) = try Frames.decodeAPQWelcome(welcomeB)
		#expect(tBytesB.prefix(6) == Data([0x00, 0x01, 0x00, 0x03, 0x00, 0x03]))
		#expect(
			try EstablishmentMessages.decodeWelcome(tBytesB).cipherSuite.id == 0x0003)

		// Live group contexts: Group_A (both halves, both sides) and Group_B
		// (classical-only, Bob's founder copy).
		let groupA = try #require(alice.sendGroup)
		#expect(groupA.classical.context.cipherSuite.id == 0x0003)
		#expect(try #require(groupA.pq).context.cipherSuite.id == 0xFDEA)

		let bobGroupA = try #require(bob.recvGroup)
		#expect(bobGroupA.classical.context.cipherSuite.id == 0x0003)

		let bobGroupB = try #require(bob.sendGroup)
		#expect(bobGroupB.classical.context.cipherSuite.id == 0x0003)

		// The APQInfo GCE, read off both Group_A's and Group_B's classical half.
		let groupAInfo = try #require(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: groupA.classical.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))
		#expect(groupAInfo.tCipherSuite.id == 0x0003)

		let groupBInfo = try #require(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: bobGroupB.classical.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))
		#expect(groupBInfo.tCipherSuite.id == 0x0003)

		// The identity's own signed KeyPackage + advertised leaf capabilities.
		#expect(identity.keyPackage.classical.cipherSuite.id == 0x0003)
		#expect(
			identity.keyPackage.classical.leafNode.capabilities.cipherSuites.map(\.id)
				== [0x0003, 0xFDEA])
	}

	@available(iOS 26, macOS 26, *)
	@Test func providerAeadKeySizesMatchDeployedSuites() {
		#expect(SessionTestSupport.classicalProvider.aeadKeySize == 32)
		#expect(SessionTestSupport.pqProvider.aeadKeySize == 16)
	}

	/// `TwoMLSIdentity.generate` rejects a classical provider whose suite is
	/// not `TwoMLSSuite.classical`, before claiming any state — the up-front
	/// guard mirroring the Rust reference's early `CipherSuiteMismatch`.
	@available(iOS 26, macOS 26, *)
	@Test func generateRejectsWrongClassicalProvider() throws {
		let wrongClassicalProvider = try #require(
			SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519Aes128))

		#expect(throws: TwoMLSError.cipherSuiteMismatch) {
			try TwoMLSIdentity.generate(
				clientID: Data("carol".utf8),
				classicalProvider: wrongClassicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}
}
