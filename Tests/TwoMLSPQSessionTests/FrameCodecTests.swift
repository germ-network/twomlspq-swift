import Foundation
import Testing

@testable import TwoMLSPQSession

@Suite struct FrameCodecTests {
	// MARK: - Staple self-discrimination

	@Test func stapleKindDiscriminatesOnFirstByte() {
		#expect(Frames.stapleKind(0x01) == .welcome)
		#expect(Frames.stapleKind(0x00) == .mlsMessage)
		#expect(Frames.stapleKind(0xAB) == .unsupported(0xAB))
	}

	// MARK: - `0x00` bare mlsMessage staple

	/// The fold-only staple IS the MLSMessage: the `0x00` first byte is the
	/// message's own `ProtocolVersion` high byte (`mls10` = `00 01`), not a
	/// wrapper tag — `encodeMlsMessageStaple` passes the message through
	/// unchanged and `decodeMlsMessageStaple` returns the whole slot.
	@Test func mlsMessageStapleIsTheBareMessage() throws {
		let message = Data([0x00, 0x01, 0x00, 0x01, 0xAA])
		let staple = Frames.encodeMlsMessageStaple(message)
		#expect(staple == message)
		#expect(try Frames.decodeMlsMessageStaple(staple) == message)
	}

	@Test func mlsMessageStapleRejectsWrongFirstByte() {
		#expect(throws: TwoMLSError.unsupportedStapleTag(0x02)) {
			try Frames.decodeMlsMessageStaple(Data([0x02, 0x01, 0x00, 0x01]))
		}
	}

	@Test func mlsMessageStapleRejectsTruncation() {
		#expect(throws: TwoMLSError.truncatedSection) {
			try Frames.decodeMlsMessageStaple(Data([0x00]))
		}
		#expect(throws: TwoMLSError.truncatedSection) {
			try Frames.decodeMlsMessageStaple(Data([0x00, 0x01]))
		}
	}

	// MARK: - `0x03` message frame

	@Test func messageFrameRoundTrips() throws {
		let staple = Data("staple-bytes".utf8)
		let proposal = Data("proposal-bytes".utf8)
		let app = Data("app-bytes".utf8)
		let frame = Frames.encodeMessageFrame(staple: staple, proposal: proposal, app: app)
		let decoded = try Frames.decodeMessageFrame(frame)
		#expect(decoded.staple == staple)
		#expect(decoded.proposal == proposal)
		#expect(decoded.app == app)
	}

	@Test func messageFrameRejectsWrongTag() {
		var frame = Frames.encodeMessageFrame(
			staple: Data([1]), proposal: Data([2]), app: Data([3]))
		frame[frame.startIndex] = 0x09
		#expect(throws: TwoMLSError.unsupportedFrameTag(0x09)) {
			try Frames.decodeMessageFrame(frame)
		}
	}

	/// `encodeMessageFrame` now preconditions against an empty section (nit), so
	/// this builds the malformed frame directly off `pushSection` rather than
	/// through the encoder, to exercise the decoder's own rejection.
	@Test func messageFrameRejectsEmptySection() {
		var frame = Data([Frames.messageFrameTag])
		Frames.pushSection(Data(), into: &frame)
		Frames.pushSection(Data([1]), into: &frame)
		Frames.pushSection(Data([2]), into: &frame)
		#expect(throws: TwoMLSError.emptySection) {
			try Frames.decodeMessageFrame(frame)
		}
	}

	@Test func messageFrameRejectsTruncation() {
		var frame = Frames.encodeMessageFrame(
			staple: Data([1]), proposal: Data([2]), app: Data([3]))
		frame.removeLast()
		#expect(throws: TwoMLSError.truncatedSection) {
			try Frames.decodeMessageFrame(frame)
		}
	}

	@Test func messageFrameRejectsTrailingBytes() {
		var frame = Frames.encodeMessageFrame(
			staple: Data([1]), proposal: Data([2]), app: Data([3]))
		frame.append(0xFF)
		#expect(throws: TwoMLSError.trailingBytes) {
			try Frames.decodeMessageFrame(frame)
		}
	}

	// MARK: - Proposal sub-section

	@Test func proposalSectionRejectsEmptyProposing() {
		let section = Frames.encodeProposalSection(
			proposing: Data(), message: Data("upd-message".utf8))
		#expect(throws: TwoMLSError.emptySection) {
			try Frames.decodeProposalSection(section)
		}
	}

	@Test func proposalSectionRoundTripsWithNonEmptyProposing() throws {
		let section = Frames.encodeProposalSection(
			proposing: Data("client-id".utf8), message: Data("upd-message".utf8))
		let decoded = try Frames.decodeProposalSection(section)
		#expect(decoded.proposing == Data("client-id".utf8))
		#expect(decoded.message == Data("upd-message".utf8))
	}

	@Test func proposalSectionRejectsEmptyMessage() {
		let section = Frames.encodeProposalSection(proposing: Data(), message: Data())
		#expect(throws: TwoMLSError.emptySection) {
			try Frames.decodeProposalSection(section)
		}
	}

	// MARK: - `0x01` APQ welcome

	@Test func aPQWelcomeRoundTrips() throws {
		let t = Data("classical-welcome".utf8)
		let pq = Data("pq-welcome".utf8)
		let staple = Frames.encodeAPQWelcome(t: t, pq: pq)
		let decoded = try Frames.decodeAPQWelcome(staple)
		#expect(decoded.t == t)
		#expect(decoded.pq == pq)
	}

	/// Group_B's welcome staple: the pq slot is empty (classical-only, deferred
	/// PQ), and that must round-trip cleanly rather than being rejected as an
	/// empty section.
	@Test func aPQWelcomeRoundTripsWithEmptyPQSlot() throws {
		let t = Data("classical-welcome".utf8)
		let staple = Frames.encodeAPQWelcome(t: t, pq: Data())
		let decoded = try Frames.decodeAPQWelcome(staple)
		#expect(decoded.t == t)
		#expect(decoded.pq == Data())
	}

	@Test func aPQWelcomeRejectsEmptyClassicalSlot() {
		let staple = Frames.encodeAPQWelcome(t: Data(), pq: Data("pq".utf8))
		#expect(throws: TwoMLSError.emptySection) {
			try Frames.decodeAPQWelcome(staple)
		}
	}

	@Test func aPQWelcomeRejectsWrongTag() {
		var staple = Frames.encodeAPQWelcome(t: Data([1]), pq: Data([2]))
		staple[staple.startIndex] = 0x02
		#expect(throws: TwoMLSError.unsupportedStapleTag(0x02)) {
			try Frames.decodeAPQWelcome(staple)
		}
	}

	// MARK: - `0x17`/`0x19` §A.4 PQ ratchet legs (outer frame)

	@Test func pQLegRoundTripsEKTag() throws {
		let messageBytes = Data("ek-mlsmessage-bytes".utf8)
		let frame = Frames.encodePQLeg(tag: Frames.pqEKTag, messageBytes: messageBytes)
		let decoded = try Frames.decodePQLeg(frame)
		#expect(decoded.tag == Frames.pqEKTag)
		#expect(decoded.messageBytes == messageBytes)
	}

	@Test func pQLegRoundTripsCTTag() throws {
		let messageBytes = Data("ct-mlsmessage-bytes".utf8)
		let frame = Frames.encodePQLeg(tag: Frames.pqCTTag, messageBytes: messageBytes)
		let decoded = try Frames.decodePQLeg(frame)
		#expect(decoded.tag == Frames.pqCTTag)
		#expect(decoded.messageBytes == messageBytes)
	}

	@Test func pQLegRejectsWrongOuterTag() {
		let frame = Frames.encodePQLeg(tag: 0x21, messageBytes: Data([1, 2, 3]))
		#expect(throws: TwoMLSError.unsupportedSideBandTag(0x21)) {
			try Frames.decodePQLeg(frame)
		}
	}

	// MARK: - `0x17`/`0x19` §A.4 PQ ratchet legs (inner authenticated content)

	@Test func pQLegContentRoundTripsEKTag() throws {
		let payload = Data("ek-bytes".utf8)
		let content = Frames.encodePQLegContent(tag: Frames.pqEKTag, payload: payload)
		let decoded = try Frames.decodePQLegContent(content)
		#expect(decoded.tag == Frames.pqEKTag)
		#expect(decoded.payload == payload)
	}

	@Test func pQLegContentRoundTripsCTTag() throws {
		let payload = Data("wire-ct-bytes".utf8)
		let content = Frames.encodePQLegContent(tag: Frames.pqCTTag, payload: payload)
		let decoded = try Frames.decodePQLegContent(content)
		#expect(decoded.tag == Frames.pqCTTag)
		#expect(decoded.payload == payload)
	}

	@Test func pQLegContentRejectsEmptyContent() {
		#expect(throws: TwoMLSError.truncatedSection) {
			try Frames.decodePQLegContent(Data())
		}
	}

	// MARK: - `0x0B` signed establishment handoff

	@Test func establishmentHandoffRoundTrips() throws {
		let envelope = Data("signed-handoff-blob".utf8)
		let welcome = Frames.encodeAPQWelcome(t: Data("t-welcome".utf8), pq: Data())
		let staple = Frames.encodeEstablishmentHandoff(envelope: envelope, welcome: welcome)
		let decoded = try Frames.decodeEstablishmentHandoff(staple)
		#expect(decoded.envelope == envelope)
		#expect(decoded.welcome == welcome)
	}

	/// wire-format.md:17: the inner section must be the unmodified `0x01`
	/// welcome — anything else is rejected outright, keyed on the inner
	/// section's own first byte.
	@Test func establishmentHandoffRejectsNonWelcomeInner() {
		let envelope = Data("signed-handoff-blob".utf8)
		let notAWelcome = Data([0x00, 0xAA, 0xBB])
		let staple = Frames.encodeEstablishmentHandoff(
			envelope: envelope, welcome: notAWelcome)
		#expect(throws: TwoMLSError.unsupportedStapleTag(0x00)) {
			try Frames.decodeEstablishmentHandoff(staple)
		}
	}

	@Test func establishmentHandoffRejectsEmptyEnvelopeSection() {
		let welcome = Frames.encodeAPQWelcome(t: Data("t-welcome".utf8), pq: Data())
		let staple = Frames.encodeEstablishmentHandoff(envelope: Data(), welcome: welcome)
		#expect(throws: TwoMLSError.emptySection) {
			try Frames.decodeEstablishmentHandoff(staple)
		}
	}

	@Test func establishmentHandoffRejectsEmptyWelcomeSection() {
		let staple = Frames.encodeEstablishmentHandoff(
			envelope: Data("signed-handoff-blob".utf8), welcome: Data())
		#expect(throws: TwoMLSError.emptySection) {
			try Frames.decodeEstablishmentHandoff(staple)
		}
	}

	@Test func establishmentHandoffRejectsWrongOuterTag() {
		var staple = Frames.encodeEstablishmentHandoff(
			envelope: Data("signed-handoff-blob".utf8),
			welcome: Frames.encodeAPQWelcome(t: Data("t-welcome".utf8), pq: Data()))
		staple[staple.startIndex] = 0x02
		#expect(throws: TwoMLSError.unsupportedStapleTag(0x02)) {
			try Frames.decodeEstablishmentHandoff(staple)
		}
	}

	@Test func establishmentHandoffRejectsTrailingBytes() {
		var staple = Frames.encodeEstablishmentHandoff(
			envelope: Data("signed-handoff-blob".utf8),
			welcome: Frames.encodeAPQWelcome(t: Data("t-welcome".utf8), pq: Data()))
		staple.append(0xFF)
		#expect(throws: TwoMLSError.trailingBytes) {
			try Frames.decodeEstablishmentHandoff(staple)
		}
	}

	@Test func establishmentHandoffRejectsTruncation() {
		var staple = Frames.encodeEstablishmentHandoff(
			envelope: Data("signed-handoff-blob".utf8),
			welcome: Frames.encodeAPQWelcome(t: Data("t-welcome".utf8), pq: Data()))
		staple.removeLast()
		#expect(throws: TwoMLSError.truncatedSection) {
			try Frames.decodeEstablishmentHandoff(staple)
		}
	}
}
