import Foundation
import MLSCodec
import MLSCombiner
import MLSExtensions
import MLSProfileRFC9420
import Testing

@testable import TwoMLSPQSession

/// Differential byte-identity tests against the deployed Rust reference (golden hex +
/// regeneration recipe in `RustWireVectors.swift`): (b) the Germ message-frame /
/// proposal-section u32-LE framing, (c) the deployed uint32 `ComponentID` width
/// feeding the AppDataUpdate attestation body, and (a) the deployed `opaque<V>`
/// wrapper around the AppDataUpdate (`0x0008`) proposal — see
/// `testAppDataUpdateWrapperByteMatchesDeployedRust`.
@Suite struct RustWireVectorsTests {

	private func hexData(_ hex: String) throws -> Data {
		var out = Data(capacity: hex.count / 2)
		var index = hex.startIndex
		while index < hex.endIndex {
			let next = hex.index(index, offsetBy: 2)
			out.append(try #require(UInt8(hex[index..<next], radix: 16)))
			index = next
		}
		return out
	}

	// MARK: - (b) framing

	@available(iOS 26, macOS 26, *)
	@Test func messageFrameByteIdenticalBothDirections() throws {
		let staple = Data(repeating: 0xAA, count: 3)
		let proposal = Data(repeating: 0xBB, count: 5)
		let app = Data(repeating: 0xCC, count: 7)
		let golden = try hexData(RustWireVectors.messageFrame)

		#expect(
			Frames.encodeMessageFrame(staple: staple, proposal: proposal, app: app)
				== golden)

		let decoded = try Frames.decodeMessageFrame(golden)
		#expect(decoded.staple == staple)
		#expect(decoded.proposal == proposal)
		#expect(decoded.app == app)
	}

	@available(iOS 26, macOS 26, *)
	@Test func proposalSectionByteIdenticalBothDirections() throws {
		let proposing = Data(repeating: 0x11, count: 4)
		let message = Data(repeating: 0x22, count: 6)
		let golden = try hexData(RustWireVectors.proposalSection)

		#expect(
			Frames.encodeProposalSection(proposing: proposing, message: message)
				== golden)

		let decoded = try Frames.decodeProposalSection(golden)
		#expect(decoded.proposing == proposing)
		#expect(decoded.message == message)
	}

	/// The shared length-prefix primitive both frames above are built from, pinned on
	/// its own fixed input.
	@available(iOS 26, macOS 26, *)
	@Test func pushSectionByteIdentical() throws {
		var buffer = Data()
		Frames.pushSection(Data(repeating: 0x33, count: 9), into: &buffer)
		#expect(buffer == (try hexData(RustWireVectors.pushSection)))
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
	@available(iOS 26, macOS 26, *)
	@Test func appDataUpdateBodyMatchesDeployedUint32Width() throws {
		let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 1)
		let componentID = MLS.Combiner.Codepoints.deployed.apqComponentID

		let body = try withDeployedWireConventions {
			try attestation.appDataUpdate(componentID: componentID).mlsEncoded()
		}
		#expect(body == (try hexData(RustWireVectors.appDataUpdateBody)))

		let proposal = MLS.RFC9420.Proposal.custom(type: .init(.appDataUpdate), body: body)
		let fullEncoded = try withDeployedWireConventions { try proposal.mlsEncoded() }
		let decoded = try withDeployedWireConventions {
			try MLS.RFC9420.Proposal(mlsEncoded: fullEncoded)
		}
		#expect(decoded == proposal)
	}

	// MARK: - (a) the deployed `opaque<V>` wrapper

	/// The AppDataUpdate `0x0008` wrapper: deployed Rust builds this proposal as an
	/// mls-rs `CustomProposal`, whose `Proposal::Custom` encoding adds an outer
	/// `opaque<V>`/VarInt length prefix around the body
	/// (`0x0008 ‖ VarInt(body.len) ‖ body`). The port now reproduces that
	/// byte-for-byte via `Proposal.custom(type:body:)`
	/// (`TwoMLSSession+ClassicalCommit.swift` / `+Bootstrap.swift`), so the FULL
	/// commit-carried proposal bytes byte-match deployed Rust — not just the body.
	@available(iOS 26, macOS 26, *)
	@Test func appDataUpdateWrapperByteMatchesDeployedRust() throws {
		let attestation = MLS.Combiner.ApqInfoUpdate(tEpoch: 2, pqEpoch: 1)
		let componentID = MLS.Combiner.Codepoints.deployed.apqComponentID

		let fullEncoded = try withDeployedWireConventions {
			try MLS.RFC9420.Proposal.custom(
				type: .init(.appDataUpdate),
				body: try attestation.appDataUpdate(componentID: componentID)
					.mlsEncoded()
			).mlsEncoded()
		}

		#expect(fullEncoded == (try hexData(RustWireVectors.appDataUpdateFullWrapped)))
	}

	/// The accept direction of the same wrapper: the deployed-Rust golden wire
	/// decodes, under the `customProposalTypes` ambient, as a `.custom` proposal
	/// naming the `appDataUpdate` type and carrying the same BODY (c) pins.
	@available(iOS 26, macOS 26, *)
	@Test func appDataUpdateWrapperAcceptsDeployedRustWireUnderAmbient() throws {
		let golden = try hexData(RustWireVectors.appDataUpdateFullWrapped)

		let decoded = try withDeployedWireConventions {
			try MLS.RFC9420.Proposal(mlsEncoded: golden)
		}

		guard case .custom(let type, let body) = decoded else {
			Issue.record("expected a wrapped .custom proposal, got \(decoded)")
			return
		}
		#expect(type == MLS.RFC9420.ProposalType(.appDataUpdate))
		#expect(body == (try hexData(RustWireVectors.appDataUpdateBody)))
	}

	// MARK: - (d) a real fold-only commit staple

	/// A real fold-only commit staple captured off the deployed Rust reference (see the
	/// regeneration recipe in `RustWireVectors.swift`) is accepted whole by
	/// `decodeMlsMessageStaple`, dispatches through `stapleKind` as `.mlsMessage`, and
	/// decodes as an MLS `.publicMessage` commit — pinning that the port's "the staple
	/// IS the message, `0x00` is not a wrapper tag" model matches what Rust actually
	/// staples.
	@available(iOS 26, macOS 26, *)
	@Test func foldOnlyStapleAcceptsRealRustCommit() throws {
		let staple = try hexData(RustWireVectors.foldOnlyStaple)

		let stapleFirstByte = try #require(staple.first)
		#expect(Frames.stapleKind(stapleFirstByte) == .mlsMessage)

		let decoded = try Frames.decodeMlsMessageStaple(staple)
		#expect(decoded == staple)

		try withDeployedWireConventions {
			guard
				case .publicMessage(let commitPub) = try MLS.RFC9420.Message(
					mlsEncoded: decoded)
			else {
				Issue.record("expected a publicMessage commit staple")
				return
			}
			guard case .commit = commitPub.content.content else {
				Issue.record("expected the staple to decode as a commit")
				return
			}
		}
	}
}
