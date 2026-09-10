import MLSCodec
import MLSCombiner
import MLSExtensions
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

/// Differential byte-identity tests against the deployed Rust reference (golden hex +
/// regeneration recipe in `RustWireVectors.swift`): (b) the §7 Germ message-frame /
/// proposal-section u32-LE framing, (c) the deployed uint32 `ComponentID` width
/// feeding the AppDataUpdate attestation body, and (a) the deployed `opaque<V>`
/// wrapper around the AppDataUpdate (`0x0008`) proposal — see
/// `testAppDataUpdateWrapperByteMatchesDeployedRust`.
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
	/// (`ApqInfoUpdate.appDataUpdate(componentID:)`, `TwoMLSSession+ClassicalCommit.swift`
	/// / `+Bootstrap.swift`), byte-matches deployed Rust once the port's ambient
	/// `ComponentID` wire width is the deployed `.uint32` (draft-08) instead of
	/// swift-mls's `.uint16` default (draft-09). Then round-trips as the wrapped
	/// `.custom` proposal the port actually emits (see (a) below) under the same
	/// `withDeployedWireConventions` scope the receive path requires.
	func testAppDataUpdateBodyMatchesDeployedUint32Width() throws {
		let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 1)
		let componentID = MLS.Combiner.Codepoints.deployed.apqComponentID

		let body = try withDeployedWireConventions {
			try attestation.appDataUpdate(componentID: componentID).mlsEncoded()
		}
		XCTAssertEqual(body, hexData(RustWireVectors.appDataUpdateBody))

		let proposal = MLS.RFC9420.Proposal.custom(type: .init(.appDataUpdate), body: body)
		let fullEncoded = try withDeployedWireConventions { try proposal.mlsEncoded() }
		let decoded = try withDeployedWireConventions {
			try MLS.RFC9420.Proposal(mlsEncoded: fullEncoded)
		}
		XCTAssertEqual(decoded, proposal)
	}

	// MARK: - (a) the deployed `opaque<V>` wrapper

	/// The AppDataUpdate `0x0008` wrapper: deployed Rust builds this proposal as an
	/// mls-rs `CustomProposal`, whose `Proposal::Custom` encoding adds an outer
	/// `opaque<V>`/VarInt length prefix around the body
	/// (`0x0008 ‖ VarInt(body.len) ‖ body`). The port now reproduces that
	/// byte-for-byte via `Proposal.custom(type:body:)`
	/// (`TwoMLSSession+ClassicalCommit.swift` / `+Bootstrap.swift`), so the FULL
	/// commit-carried proposal bytes byte-match deployed Rust — not just the body.
	func testAppDataUpdateWrapperByteMatchesDeployedRust() throws {
		let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 1)
		let componentID = MLS.Combiner.Codepoints.deployed.apqComponentID

		let fullEncoded = try withDeployedWireConventions {
			try MLS.RFC9420.Proposal.custom(
				type: .init(.appDataUpdate),
				body: try attestation.appDataUpdate(componentID: componentID)
					.mlsEncoded()
			).mlsEncoded()
		}

		XCTAssertEqual(fullEncoded, hexData(RustWireVectors.appDataUpdateFullWrapped))
	}

	/// The accept direction of the same wrapper: the deployed-Rust golden wire
	/// decodes, under the `customProposalTypes` ambient, as a `.custom` proposal
	/// naming the `appDataUpdate` type and carrying the same BODY (c) pins.
	func testAppDataUpdateWrapperAcceptsDeployedRustWireUnderAmbient() throws {
		let golden = hexData(RustWireVectors.appDataUpdateFullWrapped)

		let decoded = try withDeployedWireConventions {
			try MLS.RFC9420.Proposal(mlsEncoded: golden)
		}

		guard case .custom(let type, let body) = decoded else {
			XCTFail("expected a wrapped .custom proposal, got \(decoded)")
			return
		}
		XCTAssertEqual(type, .init(.appDataUpdate))
		XCTAssertEqual(body, hexData(RustWireVectors.appDataUpdateBody))
	}
}
