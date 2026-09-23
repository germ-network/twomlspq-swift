import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Shared scaffolding for the session tests: identity generation and a
/// two-party establishment helper, mirroring `CombinerTestSupport`'s
/// `member(...)`/`establishedPair(...)` shape one layer up.
@available(iOS 26, macOS 26, *)
enum SessionTestSupport {
	/// The differential oracle's observer, installed exactly once —
	/// piggybacked on `classicalProvider`'s own lazy `static let`
	/// initializer (Swift's once-guarantee), since every test that touches
	/// a session touches this provider first. A test that expects a miss
	/// opts in for itself via `OracleCheck.allow(_:)` rather than this
	/// install site tracking which test is live.
	private static let installOracleObserverOnce: Void = {
		#if DEBUG
			TwoMLSSessionTestHooks.observer = { session in OracleCheck.run(session) }
		#endif
	}()

	static let classicalProvider: any MLS.CipherSuiteProvider = {
		_ = installOracleObserverOnce
		return SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519ChaCha)!
	}()
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
	/// Slice 11: `established()`'s born-dedicated analogue — Bob receives
	/// under a fresh `newClientID`, so his session founds Group_B under a
	/// dedicated principal D distinct from the invitation identity, and owes
	/// the contract-26 handoff envelope. `invitationClientID` is Bob's
	/// invitation identity's own clientID (== `bobName`, `TwoMLSIdentity.
	/// generate`'s `clientID` param passed straight through by
	/// `Principal.generateInvitation`) — the id `bob.recvLeafPrincipal`
	/// should carry until the recv-leaf catch-up.
	static func establishedDedicated(
		alice aliceName: String = "alice", bob bobName: String = "bob",
		dedicatedClientID: Data = Data("bob-dedicated".utf8)
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, aliceIdentity: TwoMLSIdentity,
		invitationClientID: Data, dedicatedClientID: Data
	) {
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
			spawnToken: spawnToken, newClientID: dedicatedClientID)

		return (
			alice: initiated.session, bob: received.session,
			aliceIdentity: initiated.session.identity,
			invitationClientID: Data(bobName.utf8), dedicatedClientID: dedicatedClientID
		)
	}

	/// `establishedDedicated()` taken through the install/standalone/approve
	/// dance: install the envelope, deliver the welcome standalone, and
	/// approve it — landing both parties established (not yet
	/// `isFullyEstablished`; no §A.3 bootstrap has run). Shared by
	/// `BornDedicatedTests` and any other suite needing a born-dedicated
	/// starting point.
	static func establishedDedicatedAndApproved(
		dedicatedClientID: Data = Data("bob-dedicated".utf8)
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, invitationClientID: Data,
		dedicatedClientID: Data, envelope: Data
	) {
		var (alice, bob, _, invitationClientID, resolvedDedicatedClientID) =
			try establishedDedicated(dedicatedClientID: dedicatedClientID)
		let envelope = Data("fake-signed-handoff".utf8)
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try XCTUnwrap(try bob.standaloneWelcome())
		let opened = try XCTUnwrap(try alice.openIncoming(standalone))
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			XCTFail("expected a pause on the un-approved 0x0B")
			throw TwoMLSError.notEstablished
		}
		let (envelopeBytes, welcomeBytes) = try Frames.decodeEstablishmentHandoff(
			bob.currentStaple)
		guard
			case .joined = try alice.processIncomingApproved(
				opened.frame,
				approvedEnvelopeDigest: try classicalProvider.hash(envelopeBytes),
				approvedWelcomeDigest: try classicalProvider.hash(welcomeBytes),
				expectedCreator: resolvedDedicatedClientID)
		else {
			XCTFail("expected .joined on the approved re-feed")
			throw TwoMLSError.notEstablished
		}
		return (
			alice: alice, bob: bob, invitationClientID: invitationClientID,
			dedicatedClientID: resolvedDedicatedClientID, envelope: envelope
		)
	}

	static func establishedAndExchanged(
		alice aliceName: String = "alice", bob bobName: String = "bob"
	) throws -> (alice: TwoMLSSession, bob: TwoMLSSession) {
		var (alice, bob, _, _, _, _) = try established(alice: aliceName, bob: bobName)
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(frame)
		return (alice: alice, bob: bob)
	}
}

/// Slice 11: `processIncoming` now returns the 4-case `IncomingResult`
/// instead of a bare `DecryptResult` — this mechanically migrates the
/// hundreds of pre-existing call sites that only ever cared about the
/// everyday `0x03` app-frame path. Fails the test (via `XCTFail`, not a
/// thrown error) on any other case, since none of those call sites expect
/// one.
@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	mutating func processIncomingDecrypted(
		_ inbound: Data, file: StaticString = #filePath, line: UInt = #line
	) throws -> DecryptResult {
		switch try processIncoming(inbound) {
		case .decrypted(let result):
			return result
		case .joined, .pendingEstablishment, .ignored:
			XCTFail(
				"expected .decrypted, got a non-decrypted IncomingResult",
				file: file,
				line: line)
			throw TwoMLSError.notEstablished
		}
	}
}
