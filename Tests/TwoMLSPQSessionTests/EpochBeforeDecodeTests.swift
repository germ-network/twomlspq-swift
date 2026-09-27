import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// GER-2586. Two properties:
///
/// 1. A message frame's staple epoch is classified before any further decode:
///    a commit ahead of the receive group is `epochDesync` before the app
///    section is even decoded.
/// 2. A blob that never header-opened is the book's indistinguishable receive
///    space — an out-of-window frame and garbage — and resolves wholly to
///    `decryptionFailed`, never a wire-codec error whatever tag its ciphertext
///    mimics (the harness's seed-5 op-109 collision).
@Suite struct EpochBeforeDecodeTests {
	@available(iOS 26, macOS 26, *)
	@Test func staleSessionMeetingCurrentEraFrameReportsDecryptionFailed() throws {
		let (_, _, checkpoints, bobFrames, _) =
			try SessionTestSupport.behindRestoreFixture()
		var restored = try SessionTestSupport.restore(checkpoint: checkpoints[0])

		// A current-era sealed frame the establishment-era session cannot open.
		// Its random nonce's first byte can equal `MESSAGE_FRAME_TAG` and route
		// the ciphertext into the message-frame decoder; pin the byte so that
		// wire path is exercised deterministically rather than one run in 256.
		var frame = bobFrames[5]
		frame[frame.startIndex] = Frames.messageFrameTag
		let seqBefore = restored.stateSeq

		#expect(throws: TwoMLSError.decryptionFailed) {
			_ = try restored.processIncoming(frame)
		}
		#expect(restored.stateSeq == seqBefore, "fail-closed: nothing consumed")
	}

	/// The rest of the never-opened space: an unknown leading byte resolves to
	/// the same receive family, not `unsupportedFrameTag`.
	@available(iOS 26, macOS 26, *)
	@Test func unopenableUnknownTagReportsDecryptionFailed() throws {
		let (_, _, checkpoints, bobFrames, _) =
			try SessionTestSupport.behindRestoreFixture()
		var restored = try SessionTestSupport.restore(checkpoint: checkpoints[0])

		var frame = bobFrames[5]
		frame[frame.startIndex] = 0x77  // no frame kind uses this tag
		let seqBefore = restored.stateSeq

		#expect(throws: TwoMLSError.decryptionFailed) {
			_ = try restored.processIncoming(frame)
		}
		#expect(restored.stateSeq == seqBefore, "fail-closed: nothing consumed")
	}

	/// A frame that DID open keeps an honest tag rejection.
	@available(iOS 26, macOS 26, *)
	@Test func openedFrameWithUnknownTagKeepsUnsupportedFrameTag() throws {
		var (alice, bob, _, _, _) = try SessionTestSupport.behindRestoreFixture()
		// Sealed by the peer: bob seals under his recv group (alice's send
		// group), which alice's own receive window opens.
		let sealed = try bob.seal(Data([0x77]))

		#expect(throws: TwoMLSError.unsupportedFrameTag(0x77)) {
			_ = try alice.processIncoming(sealed)
		}
	}

	/// Part 1: a readable staple commit AHEAD of the receive group is
	/// `epochDesync` even when the app section is malformed — the epoch check
	/// precedes the app section's structural decode, so no raw `MLSCodec` error
	/// escapes.
	@available(iOS 26, macOS 26, *)
	@Test func aheadStapleWithMalformedAppReportsEpochDesync() throws {
		let (alice, _, checkpoints, bobFrames, _) =
			try SessionTestSupport.behindRestoreFixture()
		let plaintext = try #require(try alice.openIncoming(bobFrames[5])?.frame)
		let (staple, proposal, _) = try Frames.decodeMessageFrame(plaintext)
		var restored = try SessionTestSupport.restore(checkpoint: checkpoints[0])
		let recvEpoch = try #require(restored.recvGroup).classical.context.epoch
		#expect(try #require(TwoMLSSession.stapleCommitEpoch(staple)) > recvEpoch)

		// The app section is not a decodable `MLSMessage`; only the epoch
		// classification stands between this and a raw codec error.
		let crafted = Frames.encodeMessageFrame(
			staple: staple, proposal: proposal, app: Data([0x00]))
		#expect(throws: TwoMLSError.epochDesync) {
			_ = try restored.processIncoming(crafted)
		}
	}

	/// Part 1, the `0x05` bind-staple arm: the epoch is read off the bind's
	/// classical half and classified the same way.
	@available(iOS 26, macOS 26, *)
	@Test func aheadBindStapleWithMalformedAppReportsEpochDesync() throws {
		let (alice, _, checkpoints, bobFrames, _) =
			try SessionTestSupport.behindRestoreFixture()
		let plaintext = try #require(try alice.openIncoming(bobFrames[5])?.frame)
		let (commit, proposal, _) = try Frames.decodeMessageFrame(plaintext)
		// Wrap the classical commit as a bind's `t` half; the PQ half is only
		// split, never decoded, by the epoch read.
		let bindStaple = Frames.encodeAPQPrivateMessage(
			t: commit, pq: Data([0x00, 0x00, 0x00, 0x00]))
		var restored = try SessionTestSupport.restore(checkpoint: checkpoints[0])
		let recvEpoch = try #require(restored.recvGroup).classical.context.epoch
		#expect(try #require(TwoMLSSession.stapleCommitEpoch(bindStaple)) > recvEpoch)

		let crafted = Frames.encodeMessageFrame(
			staple: bindStaple, proposal: proposal, app: Data([0x00]))
		#expect(throws: TwoMLSError.epochDesync) {
			_ = try restored.processIncoming(crafted)
		}
	}
}
