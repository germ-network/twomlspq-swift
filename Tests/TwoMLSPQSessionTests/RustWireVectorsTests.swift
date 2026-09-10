import MLSCodec
import MLSCombiner
import MLSExtensions
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// Differential byte-identity tests against the deployed Rust reference (golden hex +
/// regeneration recipe in `RustWireVectors.swift`): (b) the §7 Germ message-frame /
/// proposal-section u32-LE framing, and (c) the deployed uint32 `ComponentID` width
/// feeding the AppDataUpdate attestation body. (a) is recorded as a documented,
/// non-passing divergence — see
/// `testAppDataUpdateWrapperDivergesFromDeployedRustPendingUpstreamSeam`.
@available(iOS 26, macOS 26, *)
final class RustWireVectorsTests: XCTestCase {

	private func hexData(_ hex: String) -> Data {
		var out = Data(capacity: hex.count / 2)
		var index = hex.startIndex
		while index < hex.endIndex {
			let next = hex.index(index, offsetBy: 2)
			out.append(UInt8(hex[index..<next], radix: 16)!)
			index = next
		}
		return out
	}

	// MARK: - (b) §7 framing

	func testMessageFrameByteIdenticalBothDirections() throws {
		let staple = Data(repeating: 0xAA, count: 3)
		let proposal = Data(repeating: 0xBB, count: 5)
		let app = Data(repeating: 0xCC, count: 7)
		let golden = hexData(RustWireVectors.messageFrame)

		XCTAssertEqual(
			Frames.encodeMessageFrame(staple: staple, proposal: proposal, app: app),
			golden)

		let decoded = try Frames.decodeMessageFrame(golden)
		XCTAssertEqual(decoded.staple, staple)
		XCTAssertEqual(decoded.proposal, proposal)
		XCTAssertEqual(decoded.app, app)
	}

	func testProposalSectionByteIdenticalBothDirections() throws {
		let proposing = Data(repeating: 0x11, count: 4)
		let message = Data(repeating: 0x22, count: 6)
		let golden = hexData(RustWireVectors.proposalSection)

		XCTAssertEqual(
			Frames.encodeProposalSection(proposing: proposing, message: message),
			golden)

		let decoded = try Frames.decodeProposalSection(golden)
		XCTAssertEqual(decoded.proposing, proposing)
		XCTAssertEqual(decoded.message, message)
	}

	/// The shared length-prefix primitive both frames above are built from, pinned on
	/// its own fixed input.
	func testPushSectionByteIdentical() {
		var buffer = Data()
		Frames.pushSection(Data(repeating: 0x33, count: 9), into: &buffer)
		XCTAssertEqual(buffer, hexData(RustWireVectors.pushSection))
	}

	// MARK: - (c) uint32 component-id width

	/// `component_id(uint32 BE) ‖ op ‖ opaque update<V>` — the AppDataUpdate BODY,
	/// built through the port's actual production call
	/// (`ApqInfoUpdate.proposal(componentID:)`, `TwoMLSSession+ClassicalCommit.swift`
	/// / `+Bootstrap.swift`), byte-matches deployed Rust once the port's ambient
	/// `ComponentID` wire width is the deployed `.uint32` (draft-08) instead of
	/// swift-mls's `.uint16` default (draft-09).
	func testAppDataUpdateBodyMatchesDeployedUint32Width() throws {
		let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 1)
		let componentID = MLS.Combiner.Codepoints.deployed.apqComponentID
		let proposal = try attestation.proposal(componentID: componentID)

		let fullEncoded = try withDeployedWireWidth { try proposal.mlsEncoded() }

		// Leading 2 bytes are the RFC 9420 ProposalType (0x0008, big-endian) — strip
		// them to isolate the AppDataUpdate BODY the divergence (a) is about.
		XCTAssertEqual(fullEncoded.prefix(2), Data([0x00, 0x08]))
		XCTAssertEqual(
			Data(fullEncoded.dropFirst(2)), hexData(RustWireVectors.appDataUpdateBody))

		// Round-trips under the same width scope.
		let decoded = try withDeployedWireWidth {
			try MLS.RFC9420.Proposal(mlsEncoded: fullEncoded)
		}
		XCTAssertEqual(decoded, proposal)
	}

	// MARK: - (a) documented divergence — NOT a passing byte-match

	/// The AppDataUpdate `0x0008` wrapper: deployed Rust builds this proposal as an
	/// mls-rs `CustomProposal`, whose `Proposal::Custom` encoding adds an outer
	/// `opaque<V>`/VarInt length prefix around the body
	/// (`0x0008 ‖ VarInt(body.len) ‖ body`). swift-mls's `.appDataUpdate` arm is a
	/// typed, spec-correct decoder with no such wrapper — it emits the BARE body
	/// (`0x0008 ‖ body`). Closing this requires a swift-mls custom/raw-proposal seam
	/// (authorized, tracked as a separate upstream change) that has not landed; until
	/// it does, the port emits the bare, spec-correct form and does NOT byte-match
	/// deployed Rust's FULL commit bytes for this one proposal. This test pins that
	/// gap precisely rather than leaving it undocumented: the two forms differ by
	/// EXACTLY the outer VarInt length-prefix byte.
	func testAppDataUpdateWrapperDivergesFromDeployedRustPendingUpstreamSeam() throws {
		let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 1)
		let componentID = MLS.Combiner.Codepoints.deployed.apqComponentID
		let proposal = try attestation.proposal(componentID: componentID)
		let swiftBareFull = try withDeployedWireWidth { try proposal.mlsEncoded() }

		let rustWrappedFull = hexData(RustWireVectors.appDataUpdateFullWrapped)

		XCTAssertNotEqual(swiftBareFull, rustWrappedFull)

		// Rust = 0x0008 ‖ VarInt(body.len) ‖ body; swift = 0x0008 ‖ body. Splicing the
		// one-byte VarInt out of Rust's bytes (index 2, right after the 2-byte
		// ProposalType) must recover swift's bare bytes exactly — the ONLY delta.
		XCTAssertEqual(rustWrappedFull.count, swiftBareFull.count + 1)
		let body = swiftBareFull.dropFirst(2)
		let rustVarIntByte = rustWrappedFull[rustWrappedFull.startIndex + 2]
		XCTAssertEqual(Int(rustVarIntByte), body.count)

		var reconstructed = rustWrappedFull
		reconstructed.remove(at: reconstructed.startIndex + 2)
		XCTAssertEqual(reconstructed, swiftBareFull)
	}
}
