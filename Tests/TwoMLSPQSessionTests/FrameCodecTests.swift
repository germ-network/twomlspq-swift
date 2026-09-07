import Foundation
import XCTest

@testable import TwoMLSPQSession

final class FrameCodecTests: XCTestCase {
	// MARK: - Staple self-discrimination

	func testStapleKindDiscriminatesOnFirstByte() {
		XCTAssertEqual(Frames.stapleKind(0x01), .welcome)
		XCTAssertEqual(Frames.stapleKind(0x00), .mlsMessage)
		XCTAssertEqual(Frames.stapleKind(0xAB), .unsupported(0xAB))
	}

	// MARK: - `0x03` message frame

	func testMessageFrameRoundTrips() throws {
		let staple = Data("staple-bytes".utf8)
		let proposal = Data("proposal-bytes".utf8)
		let app = Data("app-bytes".utf8)
		let frame = Frames.encodeMessageFrame(staple: staple, proposal: proposal, app: app)
		let decoded = try Frames.decodeMessageFrame(frame)
		XCTAssertEqual(decoded.staple, staple)
		XCTAssertEqual(decoded.proposal, proposal)
		XCTAssertEqual(decoded.app, app)
	}

	func testMessageFrameRejectsWrongTag() {
		var frame = Frames.encodeMessageFrame(
			staple: Data([1]), proposal: Data([2]), app: Data([3]))
		frame[frame.startIndex] = 0x09
		XCTAssertThrowsError(try Frames.decodeMessageFrame(frame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .unsupportedFrameTag(0x09))
		}
	}

	func testMessageFrameRejectsEmptySection() {
		let frame = Frames.encodeMessageFrame(
			staple: Data(), proposal: Data([1]), app: Data([2]))
		XCTAssertThrowsError(try Frames.decodeMessageFrame(frame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .emptySection)
		}
	}

	func testMessageFrameRejectsTruncation() {
		var frame = Frames.encodeMessageFrame(
			staple: Data([1]), proposal: Data([2]), app: Data([3]))
		frame.removeLast()
		XCTAssertThrowsError(try Frames.decodeMessageFrame(frame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .truncatedSection)
		}
	}

	func testMessageFrameRejectsTrailingBytes() {
		var frame = Frames.encodeMessageFrame(
			staple: Data([1]), proposal: Data([2]), app: Data([3]))
		frame.append(0xFF)
		XCTAssertThrowsError(try Frames.decodeMessageFrame(frame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .trailingBytes)
		}
	}

	// MARK: - Proposal sub-section

	func testProposalSectionRoundTripsWithEmptyProposing() throws {
		let section = Frames.encodeProposalSection(
			proposing: Data(), message: Data("upd-message".utf8))
		let decoded = try Frames.decodeProposalSection(section)
		XCTAssertEqual(decoded.proposing, Data())
		XCTAssertEqual(decoded.message, Data("upd-message".utf8))
	}

	func testProposalSectionRoundTripsWithNonEmptyProposing() throws {
		let section = Frames.encodeProposalSection(
			proposing: Data("client-id".utf8), message: Data("upd-message".utf8))
		let decoded = try Frames.decodeProposalSection(section)
		XCTAssertEqual(decoded.proposing, Data("client-id".utf8))
		XCTAssertEqual(decoded.message, Data("upd-message".utf8))
	}

	func testProposalSectionRejectsEmptyMessage() {
		let section = Frames.encodeProposalSection(proposing: Data(), message: Data())
		XCTAssertThrowsError(try Frames.decodeProposalSection(section)) { error in
			XCTAssertEqual(error as? TwoMLSError, .emptySection)
		}
	}

	// MARK: - `0x01` APQ welcome

	func testAPQWelcomeRoundTrips() throws {
		let t = Data("classical-welcome".utf8)
		let pq = Data("pq-welcome".utf8)
		let staple = Frames.encodeAPQWelcome(t: t, pq: pq)
		let decoded = try Frames.decodeAPQWelcome(staple)
		XCTAssertEqual(decoded.t, t)
		XCTAssertEqual(decoded.pq, pq)
	}

	/// Group_B's welcome staple: the pq slot is empty (classical-only, deferred
	/// PQ), and that must round-trip cleanly rather than being rejected as an
	/// empty section.
	func testAPQWelcomeRoundTripsWithEmptyPQSlot() throws {
		let t = Data("classical-welcome".utf8)
		let staple = Frames.encodeAPQWelcome(t: t, pq: Data())
		let decoded = try Frames.decodeAPQWelcome(staple)
		XCTAssertEqual(decoded.t, t)
		XCTAssertEqual(decoded.pq, Data())
	}

	func testAPQWelcomeRejectsEmptyClassicalSlot() {
		let staple = Frames.encodeAPQWelcome(t: Data(), pq: Data("pq".utf8))
		XCTAssertThrowsError(try Frames.decodeAPQWelcome(staple)) { error in
			XCTAssertEqual(error as? TwoMLSError, .emptySection)
		}
	}

	func testAPQWelcomeRejectsWrongTag() {
		var staple = Frames.encodeAPQWelcome(t: Data([1]), pq: Data([2]))
		staple[staple.startIndex] = 0x02
		XCTAssertThrowsError(try Frames.decodeAPQWelcome(staple)) { error in
			XCTAssertEqual(error as? TwoMLSError, .unsupportedStapleTag(0x02))
		}
	}
}
