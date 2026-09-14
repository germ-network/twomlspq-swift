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
		for: .curve25519ChaCha)!
	static let pqProvider = MLKEM768CipherSuiteProvider()

	static func identity(_ name: String) throws -> TwoMLSIdentity {
		try TwoMLSIdentity.generate(
			clientID: Data(name.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
	}

	/// Alice initiates to Bob's freshly-minted invitation, Bob receives. Bob
	/// is established immediately; Alice becomes established only once she
	/// processes Bob's first inbound frame (see `establishedAndExchanged`).
	/// Both identities are returned too — needed by tests that reach for a
	/// peer's own join credentials (e.g. the cross-party PSK binding proof);
	/// each is the fresh leaf bundle `Principal`/`Invitation` minted for
	/// this session (`session.identity`), not the principal itself.
	static func established(alice aliceName: String = "alice", bob bobName: String = "bob")
		throws -> (
			alice: TwoMLSSession, bob: TwoMLSSession, aliceIdentity: TwoMLSIdentity,
			bobIdentity: TwoMLSIdentity, welcomeA: Data, welcomeB: Data
		)
	{
		let alicePrincipal = try Principal.generate(
			clientID: Data(aliceName.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data(bobName.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		guard let theirCombinerKP = invitation.combinerKeyPackage else {
			throw TwoMLSError.invitationSpent
		}

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let spawnToken = classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken)

		return (
			alice: initiated.session, bob: received.session,
			aliceIdentity: initiated.session.identity,
			bobIdentity: received.session.identity, welcomeA: initiated.welcome,
			welcomeB: received.session.currentStaple
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
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncoming(frame)
		return (alice: alice, bob: bob)
	}
}
