import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// The §A.1 HPKE establishment envelope codec
/// (`EstablishmentEnvelope`) and `TwoMLSSession.pendingOutbound()`. The
/// invitation-side counterpart (`Invitation.openInitial`'s no-consume /
/// spent-invitation / restored-invitation behavior) lives in
/// `InvitationTests.swift`, alongside the rest of `Invitation`'s tests.
@available(iOS 26, macOS 26, *)
final class EnvelopeTests: XCTestCase {
	private func makePrincipals() throws -> (alice: Principal, bob: Principal) {
		(
			try Principal.generate(
				clientID: Data("alice".utf8),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider),
			try Principal.generate(
				clientID: Data("bob".utf8),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		)
	}

	// MARK: - Round-trip

	/// `initiate` -> `pendingOutbound()` (envelope) -> `Invitation.openInitial`
	/// recovers `welcome` + `returnKeyPackage` -> `receive` -> an established
	/// session; app messages then flow both ways. Also pins that `initiate`'s
	/// `currentStaple` stays the plaintext welcome, never the envelope.
	func testPendingOutboundRoundTripsThroughOpenInitialToAnEstablishedSession() throws {
		let (alicePrincipal, bobPrincipal) = try makePrincipals()
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)
		XCTAssertEqual(initiated.session.currentStaple, initiated.welcome)

		let envelope = try initiated.session.pendingOutbound()
		XCTAssertNotEqual(envelope, initiated.welcome)

		guard case .establishment(let frame) = try invitation.openInitial(envelope) else {
			return XCTFail("expected .establishment")
		}
		XCTAssertNil(frame.appPayload)
		XCTAssertNil(frame.stapledMessage)
		XCTAssertEqual(frame.welcome, initiated.welcome)
		let returnKPBytes = try XCTUnwrap(frame.returnKeyPackage)
		XCTAssertEqual(
			returnKPBytes,
			try EstablishmentMessages.encodeKeyPackage(
				initiated.session.identity.keyPackage.classical))
		let returnKP = try EstablishmentMessages.decodeKeyPackage(returnKPBytes)

		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: try XCTUnwrap(frame.welcome), theirClassicalKeyPackage: returnKP,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken)

		var alice = initiated.session
		var bob = received.session
		XCTAssertTrue(bob.isEstablished)

		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobFrame)
		XCTAssertTrue(alice.isEstablished)

		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-hello".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(aliceFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("alice-hello".utf8))
	}

	// MARK: - Re-send freshness

	/// Two `pendingOutbound()` calls on the same live session differ in
	/// outer bytes (fresh HPKE ephemeral each send, wire-format.md's
	/// re-send unlinkability) but `openInitial` recovers identical
	/// `welcome`/`returnKeyPackage` from both.
	func testPendingOutboundResealsFreshlyButRecoversIdenticalPlaintext() throws {
		let (alicePrincipal, bobPrincipal) = try makePrincipals()
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		let first = try initiated.session.pendingOutbound()
		let second = try initiated.session.pendingOutbound()
		XCTAssertNotEqual(first, second)

		guard case .establishment(let firstFrame) = try invitation.openInitial(first),
			case .establishment(let secondFrame) = try invitation.openInitial(second)
		else {
			return XCTFail("expected .establishment")
		}
		XCTAssertEqual(firstFrame.welcome, secondFrame.welcome)
		XCTAssertEqual(firstFrame.returnKeyPackage, secondFrame.returnKeyPackage)
	}

	/// Once the initiator has joined Group_B, `initialTheirKP` is cleared —
	/// there is nothing left to (re-)send.
	func testPendingOutboundFailsOnceGroupBIsJoined() throws {
		let (alice, _) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertThrowsError(try alice.pendingOutbound()) { error in
			XCTAssertEqual(error as? TwoMLSError, .noPendingEstablishmentEnvelope)
		}
	}

	// MARK: - AAD downgrade-bind (fail closed)

	/// Sealing under a wrong framing VERSION byte fails `openInitial` closed
	/// — `envelopeFramingAAD()` is derived locally on both sides and never
	/// transmitted, so a mismatch only ever surfaces as a decryption error.
	func testOpenInitialFailsClosedOnWrongFramingVersion() throws {
		let (alicePrincipal, bobPrincipal) = try makePrincipals()
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		var wrongAAD = EstablishmentEnvelope.envelopeFramingAAD()
		wrongAAD[wrongAAD.startIndex] = 0xFF
		let blob = try sealBareVector(
			theirKP: theirKP, initiated: initiated, aad: wrongAAD)

		XCTAssertThrowsError(try invitation.openInitial(blob)) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
	}

	/// Sealing under a wrong declared SUITE PAIR (not just the version byte)
	/// also fails closed — the AAD downgrade-binds the whole pair, classical
	/// half included, even though the HPKE operation itself never touches
	/// the classical half.
	func testOpenInitialFailsClosedOnWrongSuitePair() throws {
		let (alicePrincipal, bobPrincipal) = try makePrincipals()
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		var wrongAAD = EstablishmentEnvelope.envelopeFramingAAD()
		wrongAAD[wrongAAD.index(before: wrongAAD.endIndex)] ^= 0xFF
		let blob = try sealBareVector(
			theirKP: theirKP, initiated: initiated, aad: wrongAAD)

		XCTAssertThrowsError(try invitation.openInitial(blob)) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
	}

	/// The AAD is not just "some value both sides happen to agree on": the
	/// opener REQUIRES the framing AAD. A seal carrying NO aad (the shape a
	/// regression that dropped the downgrade-bind would produce on both
	/// sides) does not open. Guards the wiring, not just a mismatch.
	func testOpenInitialFailsClosedWhenSealCarriesNoAAD() throws {
		let (alicePrincipal, bobPrincipal) = try makePrincipals()
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		let blob = try sealBareVector(theirKP: theirKP, initiated: initiated, aad: nil)
		XCTAssertThrowsError(try invitation.openInitial(blob)) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
	}

	/// The opener binds EXACTLY `[0x01, 0x00, 0x03, 0xFD, 0xEA]`: a seal under
	/// those literal bytes opens, pinning `envelopeFramingAAD()`'s value (not
	/// only that some AAD is required).
	func testOpenInitialOpensUnderTheLiteralFramingAAD() throws {
		let (alicePrincipal, bobPrincipal) = try makePrincipals()
		let (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirKP = try XCTUnwrap(invitation.combinerKeyPackage)
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirKP)

		let blob = try sealBareVector(
			theirKP: theirKP, initiated: initiated,
			aad: Data([0x01, 0x00, 0x03, 0xFD, 0xEA]))
		guard case .establishment(let frame) = try invitation.openInitial(blob) else {
			return XCTFail("expected .establishment")
		}
		XCTAssertEqual(frame.welcome, initiated.welcome)
	}

	/// Seals the same bare vector `pendingOutbound()` would, but under a
	/// caller-supplied AAD (a wrong one, `nil`, or the exact framing bytes) —
	/// the provider-level hook to exercise the downgrade-bind directly, since
	/// `EstablishmentEnvelope.seal` always derives the correct AAD internally.
	private func sealBareVector(
		theirKP: CombinerKeyPackage, initiated: EstablishResult, aad: Data?
	) throws -> Data {
		let plaintext = EstablishmentEnvelope.encodePlaintext(
			appPayload: nil, welcome: initiated.welcome,
			returnKeyPackage: try EstablishmentMessages.encodeKeyPackage(
				initiated.session.identity.keyPackage.classical),
			stapledMessage: nil)
		let info = try basicIdentifier(theirKP.pq.leafNode.credential)
		let (enc, ciphertext) = try SessionTestSupport.pqProvider.hpkeSeal(
			publicKey: theirKP.pq.initKey, info: info, aad: aad, plaintext: plaintext)
		return EstablishmentEnvelope.frameHpkeBlob(enc: enc, ciphertext: ciphertext)
	}

	// MARK: - Outer framing codec

	/// The outer `[u32-LE kem_len][kem_output][ciphertext]` blob itself
	/// (not the HPKE-opened inner plaintext) rejects truncation — a length
	/// prefix claiming more bytes than the blob actually carries.
	func testUnframeHpkeBlobRejectsATruncatedBlob() throws {
		var truncated = Data()
		Frames.pushSection(Data(count: 100), into: &truncated)
		truncated = Data(truncated.prefix(10))  // claims 100 bytes, has far fewer
		XCTAssertThrowsError(try EstablishmentEnvelope.unframeHpkeBlob(truncated)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .truncatedSection)
		}
	}

	// MARK: - Inner plaintext codec

	func testDecodePlaintextRejectsTruncation() throws {
		let truncated = Data([EstablishmentEnvelope.establishmentVectorTag, 0x01, 0x00])
		XCTAssertThrowsError(try EstablishmentEnvelope.decodePlaintext(truncated)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .truncatedSection)
		}
	}

	func testDecodePlaintextRejectsTrailingBytes() throws {
		var plaintext = EstablishmentEnvelope.encodePlaintext(
			appPayload: nil, welcome: Data("welcome".utf8), returnKeyPackage: nil,
			stapledMessage: nil)
		plaintext.append(0xAA)
		XCTAssertThrowsError(try EstablishmentEnvelope.decodePlaintext(plaintext)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .trailingBytes)
		}
	}

	func testDecodePlaintextRejectsBothAppPayloadAndWelcomeAbsent() throws {
		// `returnKeyPackage` alone present is still rejected — the either/or
		// rule keys specifically off `appPayload`/`welcome`.
		let plaintext = EstablishmentEnvelope.encodePlaintext(
			appPayload: nil, welcome: nil, returnKeyPackage: Data("kp".utf8),
			stapledMessage: nil)
		XCTAssertThrowsError(try EstablishmentEnvelope.decodePlaintext(plaintext)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .neitherAppPayloadNorWelcomePresent)
		}
	}

	func testDecodePlaintextRejectsAnUnknownLeadingTag() throws {
		let plaintext = Data([0x99]) + Data("garbage".utf8)
		XCTAssertThrowsError(try EstablishmentEnvelope.decodePlaintext(plaintext)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .unsupportedEstablishmentTag(0x99))
		}
	}

	/// The parallel A.3 bootstrap-KP tag (`0x13`) decodes to `.bootstrapKP`,
	/// returned verbatim — the same shape `pqBootstrapEnvelope()` seals.
	func testDecodePlaintextRecognizesBootstrapKPTagVerbatim() throws {
		let verbatim = Frames.encodePQBootstrapKP(Data("kp-bytes".utf8))
		guard
			case .bootstrapKP(let frame) = try EstablishmentEnvelope.decodePlaintext(
				verbatim)
		else {
			return XCTFail("expected .bootstrapKP")
		}
		XCTAssertEqual(frame, verbatim)
	}

	// MARK: - AAD encoder

	func testEnvelopeFramingAADIsVersionThenSuitePairBigEndian() {
		let aad = EstablishmentEnvelope.envelopeFramingAAD()
		XCTAssertEqual(aad, Data([0x01, 0x00, 0x03, 0xFD, 0xEA]))
	}
}
