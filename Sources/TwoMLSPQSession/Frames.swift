import Foundation

/// The Germ wire codec: pure functions over `Data`, no MLS state. Every
/// length prefix is a 4-byte little-endian count.
enum Frames {
	static let messageFrameTag: UInt8 = 0x03
	static let apqWelcomeTag: UInt8 = 0x01

	/// The staple slot self-discriminates by its first byte.
	enum StapleKind: Equatable {
		case welcome
		case mlsMessage
		case unsupported(UInt8)
	}

	static func stapleKind(_ firstByte: UInt8) -> StapleKind {
		switch firstByte {
		case apqWelcomeTag: .welcome
		case 0x00: .mlsMessage
		default: .unsupported(firstByte)
		}
	}

	// MARK: - Length-prefixed sections

	static func pushSection(_ data: Data, into buffer: inout Data) {
		let length = UInt32(data.count)
		buffer.append(UInt8(truncatingIfNeeded: length))
		buffer.append(UInt8(truncatingIfNeeded: length >> 8))
		buffer.append(UInt8(truncatingIfNeeded: length >> 16))
		buffer.append(UInt8(truncatingIfNeeded: length >> 24))
		buffer.append(data)
	}

	/// Read one length-prefixed section starting at `index`, advancing it past
	/// the section. Shared by `readSections` (whole-buffer, fixed count) and
	/// `decodeProposalSection` (one prefixed field followed by unprefixed
	/// trailing bytes).
	private static func readLengthPrefixedSection(_ data: Data, at index: inout Data.Index)
		throws
		-> Data
	{
		guard data.distance(from: index, to: data.endIndex) >= 4 else {
			throw TwoMLSError.truncatedSection
		}
		let b0 = Int(data[index])
		let b1 = Int(data[data.index(index, offsetBy: 1)])
		let b2 = Int(data[data.index(index, offsetBy: 2)])
		let b3 = Int(data[data.index(index, offsetBy: 3)])
		let length = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
		index = data.index(index, offsetBy: 4)
		guard data.distance(from: index, to: data.endIndex) >= length else {
			throw TwoMLSError.truncatedSection
		}
		let end = data.index(index, offsetBy: length)
		defer { index = end }
		return Data(data[index..<end])
	}

	/// Read exactly `count` length-prefixed sections, rejecting truncation and
	/// any trailing bytes after the last one. Does not itself reject empty
	/// sections — callers decide which of their sections may be empty.
	static func readSections(_ data: Data, count: Int) throws -> [Data] {
		var index = data.startIndex
		var sections: [Data] = []
		for _ in 0..<count {
			sections.append(try readLengthPrefixedSection(data, at: &index))
		}
		guard index == data.endIndex else { throw TwoMLSError.trailingBytes }
		return sections
	}

	// MARK: - `0x03` message frame

	/// `[0x03][u32 staple][u32 proposal][u32 app]` — all three sections
	/// mandatory and non-empty.
	static func encodeMessageFrame(staple: Data, proposal: Data, app: Data) -> Data {
		var buffer = Data([messageFrameTag])
		pushSection(staple, into: &buffer)
		pushSection(proposal, into: &buffer)
		pushSection(app, into: &buffer)
		return buffer
	}

	static func decodeMessageFrame(_ frame: Data) throws -> (
		staple: Data, proposal: Data, app: Data
	) {
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		guard tag == messageFrameTag else { throw TwoMLSError.unsupportedFrameTag(tag) }
		let sections = try readSections(
			frame[frame.index(after: frame.startIndex)...], count: 3)
		guard sections.allSatisfy({ !$0.isEmpty }) else { throw TwoMLSError.emptySection }
		return (sections[0], sections[1], sections[2])
	}

	// MARK: - Proposal sub-section

	/// `[u32 proposing][message]` — `proposing` may be empty (slice 1 always
	/// sends `Data()`, the born-dedicated `ClientId` staple is a later slice);
	/// `message` is the remaining bytes and must be non-empty.
	static func encodeProposalSection(proposing: Data, message: Data) -> Data {
		var buffer = Data()
		pushSection(proposing, into: &buffer)
		buffer.append(message)
		return buffer
	}

	static func decodeProposalSection(_ section: Data) throws -> (
		proposing: Data, message: Data
	) {
		var index = section.startIndex
		let proposing = try readLengthPrefixedSection(section, at: &index)
		let message = Data(section[index...])
		guard !message.isEmpty else { throw TwoMLSError.emptySection }
		return (proposing, message)
	}

	// MARK: - `0x01` APQ welcome

	/// `[0x01][u32 t][u32 pq]` — `t` is always present; `pq` is empty for
	/// Group_B (classical-only, deferred PQ).
	static func encodeAPQWelcome(t: Data, pq: Data) -> Data {
		var buffer = Data([apqWelcomeTag])
		pushSection(t, into: &buffer)
		pushSection(pq, into: &buffer)
		return buffer
	}

	static func decodeAPQWelcome(_ staple: Data) throws -> (t: Data, pq: Data) {
		guard let tag = staple.first else { throw TwoMLSError.truncatedSection }
		guard tag == apqWelcomeTag else { throw TwoMLSError.unsupportedStapleTag(tag) }
		let sections = try readSections(
			staple[staple.index(after: staple.startIndex)...], count: 2)
		guard !sections[0].isEmpty else { throw TwoMLSError.emptySection }
		return (sections[0], sections[1])
	}
}
