import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// Shared scaffolding for the session tests: identity generation and a
/// two-party establishment helper, mirroring `CombinerTestSupport`'s
/// `member(...)`/`establishedPair(...)` shape one layer up.
@available(iOS 26, macOS 26, *)
enum SessionTestSupport {
	static let classicalProvider = SwiftCryptoProvider().cipherSuiteProvider(
		for: .curve25519Aes128)!
	static let pqProvider = MLKEM768CipherSuiteProvider()

	static func identity(_ name: String) throws -> TwoMLSIdentity {
		try TwoMLSIdentity.generate(
			clientID: Data(name.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
	}

	/// Alice initiates, Bob receives. Bob is established immediately; Alice
	/// becomes established only once she processes Bob's first inbound frame
	/// (see `establishedAndExchanged`). Both identities are returned too —
	/// needed by tests that reach for a peer's own join credentials (e.g. the
	/// cross-party PSK binding proof).
	static func established(alice aliceName: String = "alice", bob bobName: String = "bob")
		throws -> (
			alice: TwoMLSSession, bob: TwoMLSSession, aliceIdentity: TwoMLSIdentity,
			bobIdentity: TwoMLSIdentity, welcomeA: Data, welcomeB: Data
		)
	{
		let alice = try identity(aliceName)
		let bob = try identity(bobName)

		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let received = try TwoMLSSession.receive(
			identity: bob, welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		return (
			alice: initiated.session, bob: received.session, aliceIdentity: alice,
			bobIdentity: bob, welcomeA: initiated.welcome, welcomeB: received.welcome
		)
	}

	/// `established()`, plus Bob's first frame (a no-op app message) delivered
	/// to Alice, so both sides are `isEstablished` — matching the reference's
	/// "initiator established only once it has received the acceptor's first
	/// frame" ordering.
	static func establishedAndExchanged(
		alice aliceName: String = "alice", bob bobName: String = "bob"
	) throws -> (alice: TwoMLSSession, bob: TwoMLSSession) {
		var (alice, bob, _, _, _, _) = try established(alice: aliceName, bob: bobName)
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8))
		_ = try alice.processIncoming(frame)
		return (alice: alice, bob: bob)
	}
}
