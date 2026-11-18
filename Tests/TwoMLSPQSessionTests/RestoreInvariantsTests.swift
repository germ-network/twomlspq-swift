import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// Restore and migration mint refuse state no live path writes, and rebuild
/// what they can re-derive instead of trusting it.
@Suite struct RestoredGroupInvariantTests {
	/// A tree with a third member is refused, as every live ingress refuses it.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsTreeWithThirdMember() throws {}

	/// A PQ half that carries an AppBinding is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsBoundPQHalf() throws {}

	/// A PQ half that records a profile is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsPQHalfWithRecordedProfile() throws {}

	/// Classical halves that disagree on the AppBinding are refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsClassicalHalvesWithDifferentAppBindings() throws {}

	/// A classical half whose AppBinding is malformed is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsMalformedAppBinding() throws {}

	/// Classical halves that disagree on the recorded profile are refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsClassicalHalvesWithDifferentProfiles() throws {}

	/// Restore runs the group checks: an archive whose recv half is swapped
	/// for an equally bound one restores, and for a differently bound one is
	/// refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoreRejectsMismatchedAppBindings() throws {}

	/// A core-kind mint runs the group checks too, since it gets no trial
	/// restore; the equally bound swap still mints.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func coreMintRejectsMismatchedAppBindings() throws {}

	/// Leaf capabilities are not a restore check, because a peer's commit path
	/// leaf is never capability-checked live: a group with a capability-less
	/// leaf passes the restore group check and fails the mint advert check.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func capabilityLessLeafPassesRestoreCheckButNotMint() throws {}
}

@Suite struct MigratedLeafAdvertTests {
	/// A migrated leaf missing the APQ capabilities is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintRejectsLeafWithoutAPQCapabilities() throws {}

	/// A migrated leaf of a bound classical half that does not advertise the
	/// AppBinding is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintRejectsBoundLeafWithoutBindingAdvert() throws {}
}

@Suite struct RestoredAuthShapeTests {
	/// An empty history is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsEmptyHistory() throws {}

	/// A history longer than the credential history window is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsHistoryLongerThanWindow() throws {}

	/// A history that repeats an id is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsDuplicateHistoryEntry() throws {}

	/// An id in both parties' history or authorizations is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsIDKnownToBothParties() throws {}

	/// An own authorization of a retired own id, which the public API can
	/// write, still restores.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoresAuthorizationOfRetiredOwnID() throws {}

	/// A peer PQ leaf presenting my own id pins it on both sides; the
	/// archive still restores.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoresWhenPeerPQLeafPresentsMyID() throws {}

	/// Restore runs the auth shape check.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoreRejectsDuplicateHistoryEntry() throws {}

	/// A core-kind mint runs the auth shape check.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func coreMintRejectsDuplicateHistoryEntry() throws {}
}

@Suite struct MigratedPeerApprovalTests {
	/// A migrated peer authorization is dropped at mint, so it cannot admit
	/// an unapproved peer rotation after restore.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintDropsTheirAuthorization() throws {}

	/// A migrated queued proposal is dropped at mint, so the next fold cannot
	/// canonicalize a peer rotation the app never approved.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintDropsQueuedProposal() throws {}

	/// After a migrated approval is dropped, the next fold canonicalizes no
	/// peer rotation: the peer stays in sync on its old id.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func droppedApprovalLeavesPeerOnOldID() throws {}

	/// A dropped peer rotation converges once the peer re-requests it and the
	/// app approves it again.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func droppedPeerRotationConvergesAfterReapproval() throws {}

	/// My own migrated authorizations survive the mint unchanged.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintKeepsMyAuthorizations() throws {}
}

@Suite struct EstablishmentOwedInvariantTests {
	/// An initiator that claims to owe the envelope is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsOwedOnInitiator() throws {}

	/// An owed envelope with a staple other than the `0x01` welcome is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsOwedWithMovedStaple() throws {}

	/// A non-dedicated acceptor on its welcome staple that claims to owe the
	/// envelope is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsOwedOnNonDedicatedAcceptor() throws {}

	/// A dedicated acceptor still on its welcome staple that claims not to owe
	/// the envelope is refused, so the signed-handoff gate cannot be skipped.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsUnowedDedicatedAcceptorBeforeInstall() throws {}

	/// The migration path refuses the same unowed dedicated acceptor.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintRejectsUnowedDedicatedAcceptorBeforeInstall() throws {}

	/// A non-dedicated acceptor whose recv leaf rotated ahead of its send leaf
	/// on the welcome staple still restores.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoresNonDedicatedAcceptorAfterPeerFoldedRotation()
		throws
	{}
}

@Suite struct WindowEpochInvariantTests {
	/// A rendezvous entry keyed above the send-classical epoch is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsRendezvousEntryAboveCurrentEpoch() throws {}

	/// A header-key entry keyed above the send-classical epoch is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsHeaderKeyEntryAboveCurrentEpoch() throws {}

	/// A PQ header-key entry keyed above the send-PQ epoch is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsPQHeaderKeyEntryAboveCurrentEpoch() throws {}

	/// PQ header keys with no send PQ group are refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsPQHeaderKeysWithoutSendPQ() throws {}

	/// A core-kind mint refuses a future-keyed window entry.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func coreMintRejectsHeaderKeyEntryAboveCurrentEpoch() throws {}
}

@Suite struct WindowRederivationTests {
	/// A tampered current-epoch rendezvous entry is replaced by the derived value.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoreReplacesTamperedCurrentRendezvous() throws {}

	/// A tampered current-epoch header key is replaced by the derived value.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoreReplacesTamperedCurrentHeaderKey() throws {}

	/// A tampered current-epoch PQ header key is replaced by the derived value.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoreReplacesTamperedCurrentPQHeaderKey() throws {}
}
