import Foundation

/// The session layer's own error surface — wire-codec failures and the
/// deferred-half / two-party checks the combiner and profile have no seam
/// for. Combiner (`MLS.Combiner.Error`) and profile (`MLS.RFC9420.GroupError`)
/// errors are not wrapped here; they propagate as thrown.
public enum TwoMLSError: Error, Sendable, Equatable {
	// MARK: Frame codec

	/// A length-prefixed section was empty where the wire format requires
	/// content (every `0x03` frame section; a message frame's proposal body).
	case emptySection
	/// A length prefix ran past the end of the buffer.
	case truncatedSection
	/// Bytes remained after every declared section was consumed.
	case trailingBytes
	/// The staple's leading tag byte matched none of slice 1's cases.
	case unsupportedStapleTag(UInt8)
	/// The frame's leading tag byte was not `MESSAGE_FRAME_TAG`.
	case unsupportedFrameTag(UInt8)

	// MARK: Establishment / deferred-half verification

	/// `verifyAPQInfoDeferred` found Group_B's `APQInfo` inconsistent with a
	/// deferred (pq-less) pair — a wrong mode/suite, a bound `pqEpoch`, or an
	/// identity field that does not match the group it rides in.
	case deferredApqInfoMismatch
	/// A commit staple arrived — slice 1 sends no commits, so receiving one is
	/// a protocol state this slice cannot process.
	case commitStapleUnsupported
	/// A staple welcome not already joined carried a non-empty pq slot — a
	/// full (Group_A-shaped) welcome. Slice 1 only ever joins one of those via
	/// the explicit `receive()` entry point, never through `processIncoming`.
	case fullEstablishmentStapleUnsupported
	/// The frame's app section did not decode to `.privateMessage`.
	case appSectionNotPrivateMessage
	/// A decrypted app-section message was not `.application` content.
	case unprotectedContentNotApplication

	// MARK: Two-party rules

	/// A group's non-blank leaf count was not exactly two.
	case notTwoParty(count: Int)
	/// A creation commit's proposal list was not exactly `[Add, PreSharedKey]`
	/// (classical-only) or `[Add, PreSharedKey, AppDataUpdate]` (full).
	case invalidCreationProposals

	// MARK: Session state

	/// `encrypt` was called with no proposal staged by `prepareToEncrypt`.
	case noPendingProposal
	/// `prepareToEncrypt`/`encrypt` requires both the send and receive groups
	/// (i.e. `isEstablished`).
	case notEstablished
}
