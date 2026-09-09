import Foundation

/// The Germ wire codec: pure functions over `Data`, no MLS state. Every
/// length prefix is a 4-byte little-endian count.
enum Frames {
	static let messageFrameTag: UInt8 = 0x03
	static let apqWelcomeTag: UInt8 = 0x01
	static let mlsMessageStapleTag: UInt8 = 0x00
	static let apqPrivateMessageTag: UInt8 = 0x05
	static let pqBootstrapKPTag: UInt8 = 0x13
	static let pqBootstrapWelcomeTag: UInt8 = 0x15
	static let pqEKTag: UInt8 = 0x17
	static let pqCTTag: UInt8 = 0x19
	static let pqRekeyUpdTag: UInt8 = 0x1B
	static let pqRekeyCommitTag: UInt8 = 0x1D

	/// The staple slot self-discriminates by its first byte.
	enum StapleKind: Equatable {
		case welcome
		case mlsMessage
		case apqPrivateMessage
		case unsupported(UInt8)
	}

	static func stapleKind(_ firstByte: UInt8) -> StapleKind {
		switch firstByte {
		case apqWelcomeTag: .welcome
		case mlsMessageStapleTag: .mlsMessage
		case apqPrivateMessageTag: .apqPrivateMessage
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
		precondition(!staple.isEmpty && !proposal.isEmpty && !app.isEmpty)
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

	/// `[u32 proposing][message]` — `proposing` is the sender's current
	/// `ClientId` and is non-empty on every routine round; a future slice's
	/// rotation *candidate* `ClientId` rides the same field, but it too is
	/// never empty. `message` is the remaining bytes and must be non-empty.
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
		guard !proposing.isEmpty else { throw TwoMLSError.emptySection }
		let message = Data(section[index...])
		guard !message.isEmpty else { throw TwoMLSError.emptySection }
		return (proposing, message)
	}

	// MARK: - `0x00` bare mlsMessage staple (classical fold-only commit)

	/// `[0x00][Commit MLSMessage bytes]` — bare remainder, no inner length
	/// prefix, like `encodePQBootstrapKP`. Slice 5's fold-only staple: a
	/// classical commit that folds a peer Update but carries no bind (a bind
	/// riding the same commit staples `0x05` instead, `encodeAPQPrivateMessage`).
	static func encodeMlsMessageStaple(_ message: Data) -> Data {
		precondition(!message.isEmpty)
		return Data([mlsMessageStapleTag]) + message
	}

	static func decodeMlsMessageStaple(_ staple: Data) throws -> Data {
		guard let tag = staple.first else { throw TwoMLSError.truncatedSection }
		guard tag == mlsMessageStapleTag else {
			throw TwoMLSError.unsupportedStapleTag(tag)
		}
		let message = Data(staple[staple.index(after: staple.startIndex)...])
		guard !message.isEmpty else { throw TwoMLSError.emptySection }
		return message
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

	// MARK: - `0x13`/`0x15` PQ bootstrap side-band frames

	/// `[0x13][KP′ bytes]` — bare remainder, no inner length prefix.
	/// `messageBytes` is an MLSMessage-wrapped `KeyPackage` (§11 #7).
	static func encodePQBootstrapKP(_ messageBytes: Data) -> Data {
		Data([pqBootstrapKPTag]) + messageBytes
	}

	static func decodePQBootstrapKP(_ frame: Data) throws -> Data {
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		guard tag == pqBootstrapKPTag else { throw TwoMLSError.unsupportedSideBandTag(tag) }
		return Data(frame[frame.index(after: frame.startIndex)...])
	}

	/// `[0x15][Welcome′ bytes]` — bare remainder, no inner length prefix.
	/// `messageBytes` is an MLSMessage-wrapped `Welcome` (§11 #7).
	static func encodePQBootstrapWelcome(_ messageBytes: Data) -> Data {
		Data([pqBootstrapWelcomeTag]) + messageBytes
	}

	static func decodePQBootstrapWelcome(_ frame: Data) throws -> Data {
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		guard tag == pqBootstrapWelcomeTag else {
			throw TwoMLSError.unsupportedSideBandTag(tag)
		}
		return Data(frame[frame.index(after: frame.startIndex)...])
	}

	// MARK: - `0x17`/`0x19` §A.4 PQ ratchet legs

	/// **Outer frame:** `[0x17][MLSMessage bytes]` / `[0x19][MLSMessage bytes]`
	/// — bare remainder, no inner length prefix, like `encodePQBootstrapKP`.
	/// The `MLSMessage` is the app-message carrier (a `PrivateMessage` wrapping
	/// the inner-tagged content below).
	static func encodePQLeg(tag: UInt8, messageBytes: Data) -> Data {
		Data([tag]) + messageBytes
	}

	static func decodePQLeg(_ frame: Data) throws -> (tag: UInt8, messageBytes: Data) {
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		guard tag == pqEKTag || tag == pqCTTag else {
			throw TwoMLSError.unsupportedSideBandTag(tag)
		}
		return (tag, Data(frame[frame.index(after: frame.startIndex)...]))
	}

	/// **Inner authenticated content** — the app message's plaintext:
	/// `[0x17][ek]` / `[0x19][wireCT]`. The inner tag rides inside the MLS
	/// signature, so it is checked against the outer tag by the caller, not
	/// here.
	static func encodePQLegContent(tag: UInt8, payload: Data) -> Data {
		Data([tag]) + payload
	}

	static func decodePQLegContent(_ content: Data) throws -> (tag: UInt8, payload: Data) {
		guard let tag = content.first else { throw TwoMLSError.truncatedSection }
		return (tag, Data(content[content.index(after: content.startIndex)...]))
	}

	// MARK: - `0x1B`/`0x1D` §A.5 PQ re-key legs

	/// `[0x1B][Upd′ MLSMessage bytes]` — bare remainder, no inner length
	/// prefix, like `encodePQBootstrapKP`. The Upd′ is a `.publicMessage`
	/// proposal, MLS-authenticated in its own right (no app-message carrier,
	/// unlike the `0x17`/`0x19` ratchet legs).
	static func encodePQRekeyUpd(_ messageBytes: Data) -> Data {
		Data([pqRekeyUpdTag]) + messageBytes
	}

	static func decodePQRekeyUpd(_ frame: Data) throws -> Data {
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		guard tag == pqRekeyUpdTag else { throw TwoMLSError.unsupportedSideBandTag(tag) }
		return Data(frame[frame.index(after: frame.startIndex)...])
	}

	/// `[0x1D][Commit′ MLSMessage bytes]` — bare remainder, no inner length
	/// prefix. The Commit′ is a `.publicMessage` commit, MLS-authenticated in
	/// its own right.
	static func encodePQRekeyCommit(_ messageBytes: Data) -> Data {
		Data([pqRekeyCommitTag]) + messageBytes
	}

	static func decodePQRekeyCommit(_ frame: Data) throws -> Data {
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		guard tag == pqRekeyCommitTag else { throw TwoMLSError.unsupportedSideBandTag(tag) }
		return Data(frame[frame.index(after: frame.startIndex)...])
	}

	// MARK: - `0x05` APQ private message (bind staple)

	/// `[0x05][u32 t][u32 pq]` — both sections mandatory and non-empty; `t`
	/// and `pq` are each a full `MLS.RFC9420.Message`.
	static func encodeAPQPrivateMessage(t: Data, pq: Data) -> Data {
		precondition(!t.isEmpty && !pq.isEmpty)
		var buffer = Data([apqPrivateMessageTag])
		pushSection(t, into: &buffer)
		pushSection(pq, into: &buffer)
		return buffer
	}

	static func decodeAPQPrivateMessage(_ staple: Data) throws -> (t: Data, pq: Data) {
		guard let tag = staple.first else { throw TwoMLSError.truncatedSection }
		guard tag == apqPrivateMessageTag else {
			throw TwoMLSError.unsupportedStapleTag(tag)
		}
		let sections = try readSections(
			staple[staple.index(after: staple.startIndex)...], count: 2)
		guard sections.allSatisfy({ !$0.isEmpty }) else { throw TwoMLSError.emptySection }
		return (sections[0], sections[1])
	}
}
