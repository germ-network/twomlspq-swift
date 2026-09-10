import Foundation
import XCTest

@testable import TwoMLSPQSession

@available(iOS 26, macOS 26, *)
final class MessageRoundTripTests: XCTestCase {
	/// Acceptor (Bob) → initiator (Alice): the first frame both establishes
	/// Alice's receive group (Group_B) and carries a real app message, and
	/// decrypts to the exact plaintext.
	func testAcceptorToInitiatorRoundTrip() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		let plaintext = Data("hello from bob".utf8)

		let prepared = try bob.prepareToEncrypt()
		XCTAssertFalse(prepared.didCommit)
		let frame = try bob.encrypt(plaintext)

		let result = try alice.processIncoming(frame)
		XCTAssertEqual(result.applicationMessage, plaintext)
		XCTAssertTrue(alice.isEstablished)
	}

	/// Initiator (Alice) → acceptor (Bob), once both sides are established.
	func testInitiatorToAcceptorRoundTrip() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let plaintext = Data("hello from alice".utf8)

		let prepared = try alice.prepareToEncrypt()
		XCTAssertFalse(prepared.didCommit)
		let frame = try alice.encrypt(plaintext)

		let result = try bob.processIncoming(frame)
		XCTAssertEqual(result.applicationMessage, plaintext)
	}

	/// M1, the carried-hash property: the app message's own carried
	/// `authenticated_data` round-trips as `sha256` of the proposal bytes the
	/// sender framed alongside it — a VALUE, not a decrypt-time cross-check.
	/// `unprotect` never compares it against the frame's separate proposal
	/// section, so this only asserts the round-trip, never that tampering the
	/// proposal section fails decryption (it does not).
	func testAuthenticatedDataCarriesProposalHash() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()

		let prepared = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("payload".utf8))
		let result = try alice.processIncoming(frame)

		let expectedHash = try SessionTestSupport.classicalProvider.hash(
			prepared.proposalMessage)
		XCTAssertEqual(prepared.proposalHash, expectedHash)
		XCTAssertEqual(result.authenticatedData, expectedHash)
		XCTAssertEqual(result.queuedProposal.digest, expectedHash)
	}

	/// The app section is AEAD-sealed (`Group.protect`), not merely encoded:
	/// a distinctive plaintext payload must not appear anywhere in the wire
	/// frame's bytes, including inside the un-header-sealed staple/proposal
	/// sections that ride alongside it in the clear.
	func testEncryptedFrameCarriesNoPlaintextCopyOfTheApplicationPayload() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		let plaintext = Data("the-quick-brown-fox-jumps-over-the-lazy-dog-0xDEADBEEF".utf8)

		let prepared = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(plaintext)
		XCTAssertNil(frame.range(of: plaintext))

		let result = try alice.processIncoming(frame)
		XCTAssertEqual(result.applicationMessage, plaintext)
		XCTAssertFalse(prepared.didCommit)
	}
}
