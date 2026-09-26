import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// GER-2587: a peer app message can be sealed at an epoch this session no
/// longer holds message secrets for. swift-mls rejects it with
/// `GroupError.messageFromUnretainedEpoch`; the session boundary folds that
/// into the classified `TwoMLSError.messageFromUnretainedEpoch(epoch:)` —
/// carrying the epoch, naming the detected condition, no interpretation
/// baked in — instead of letting it cross as an unmapped dependency error.
@Suite struct MessageFromUnretainedEpochTests {
	/// The harness's direction: the restored sender seals a fresh frame at its
	/// rewound epoch, and the current-era peer no longer retains it.
	@available(iOS 26, macOS 26, *)
	@Test func restoredSenderFreshFrameAtPeerSurfacesUnretainedEpoch() throws {
		let (_, bobUnrestored, checkpoints, _, _) =
			try SessionTestSupport.behindRestoreFixture()
		var bob = bobUnrestored
		var restored = try SessionTestSupport.restore(checkpoint: checkpoints[2])
		_ = try restored.prepareToEncrypt()
		let fresh = try restored.encrypt(Data("fresh".utf8)).frame
		let senderEpoch = try #require(restored.sendGroup).classical.context.epoch
		let bobSeqBefore = bob.stateSeq

		do {
			_ = try bob.processIncoming(fresh)
			Issue.record("expected messageFromUnretainedEpoch")
		} catch let TwoMLSError.messageFromUnretainedEpoch(epoch) {
			#expect(epoch == senderEpoch)
		} catch {
			Issue.record("unexpected error: \(error)")
		}
		#expect(bob.stateSeq == bobSeqBefore, "fail-closed: nothing consumed")
	}

	/// The mirror direction: the restored session receives a peer frame sealed
	/// at an epoch its rewound receive group no longer retains.
	@available(iOS 26, macOS 26, *)
	@Test func behindRestoredSessionReceivingOldFrameSurfacesUnretainedEpoch() throws {
		let (_, _, checkpoints, bobFrames, bobSendEpochs) =
			try SessionTestSupport.behindRestoreFixture()
		var restored = try SessionTestSupport.restore(checkpoint: checkpoints[2])
		let seqBefore = restored.stateSeq

		do {
			_ = try restored.processIncoming(bobFrames[0])
			Issue.record("expected messageFromUnretainedEpoch")
		} catch let TwoMLSError.messageFromUnretainedEpoch(epoch) {
			// The frame's app was protected at the acceptor's send-group epoch
			// when it was emitted — the rewound receive group no longer retains
			// it, and that epoch is what the error carries.
			#expect(epoch == bobSendEpochs[0])
		} catch {
			Issue.record("unexpected error: \(error)")
		}
		#expect(restored.stateSeq == seqBefore, "fail-closed: nothing consumed")
	}
}
