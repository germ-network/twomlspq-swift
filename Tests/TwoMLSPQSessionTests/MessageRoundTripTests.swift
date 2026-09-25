import Foundation
import Testing

@testable import TwoMLSPQSession

@Suite struct MessageRoundTripTests {
	/// Acceptor (Bob) → initiator (Alice): the first frame both establishes
	/// Alice's receive group (Group_B) and carries a real app message, and
	/// decrypts to the exact plaintext.
	@available(iOS 26, macOS 26, *)
	@Test func acceptorToInitiatorRoundTrip() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		let plaintext = Data("hello from bob".utf8)

		let prepared = try bob.prepareToEncrypt()
		#expect(!prepared.didCommit)
		let frame = try bob.encrypt(plaintext).frame

		let result = try alice.processIncomingDecrypted(frame)
		#expect(result.applicationMessage == plaintext)
		#expect(alice.isEstablished)
	}

	/// Initiator (Alice) → acceptor (Bob), once both sides are established.
	@available(iOS 26, macOS 26, *)
	@Test func initiatorToAcceptorRoundTrip() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let plaintext = Data("hello from alice".utf8)

		let prepared = try alice.prepareToEncrypt()
		#expect(!prepared.didCommit)
		let frame = try alice.encrypt(plaintext).frame

		let result = try bob.processIncomingDecrypted(frame)
		#expect(result.applicationMessage == plaintext)
	}

	/// The carried-hash property: the app message's own carried
	/// `authenticated_data` round-trips as `sha256` of the proposal bytes the
	/// sender framed alongside it — a VALUE, not a decrypt-time cross-check.
	/// `unprotect` never compares it against the frame's separate proposal
	/// section, so this only asserts the round-trip, never that tampering the
	/// proposal section fails decryption (it does not).
	@available(iOS 26, macOS 26, *)
	@Test func authenticatedDataCarriesProposalHash() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()

		let prepared = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("payload".utf8)).frame
		let result = try alice.processIncomingDecrypted(frame)

		let expectedHash = try SessionTestSupport.classicalProvider.hash(
			prepared.proposalMessage)
		#expect(prepared.proposalHash == expectedHash)
		#expect(result.authenticatedData == expectedHash)
		#expect(result.queuedProposal.digest == expectedHash)
	}

	/// The app section is AEAD-sealed (`Group.protect`), not merely encoded:
	/// a distinctive plaintext payload must not appear anywhere in the wire
	/// frame's bytes, including inside the un-header-sealed staple/proposal
	/// sections that ride alongside it in the clear.
	@available(iOS 26, macOS 26, *)
	@Test func encryptedFrameCarriesNoPlaintextCopyOfTheApplicationPayload() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		let plaintext = Data("the-quick-brown-fox-jumps-over-the-lazy-dog-0xDEADBEEF".utf8)

		let prepared = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(plaintext).frame
		#expect(frame.range(of: plaintext) == nil)

		let result = try alice.processIncomingDecrypted(frame)
		#expect(result.applicationMessage == plaintext)
		#expect(!prepared.didCommit)
	}
}
