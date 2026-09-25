import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import SecretBytes

// MARK: - Attachment CEK export (value-engine parity)
//
// The deployed engine derives each attachment's content-encryption key from
// a THIRD session-layer component, `0xFF03` — distinct from the combiner's
// own `apq_psk` (`0xFF01`) and the cross-party PSK (`0xFF02`,
// `TwoMLSSession.crossPartyComponentID`):
//
//   CEK = ExpandWithLabel(SafeExportSecret_classical(0xFF03),
//                         "attachment", keyId, 32)
//
// — draft-ietf-mls-extensions-08 §4.4 `SafeExportSecret` feeding RFC 9420
// §8's `ExpandWithLabel`. `keyId` is the caller's own random 32-byte
// namespacing context for one attachment, never carried on the wire. This
// file only ports that one pinned recipe byte-for-byte; it invents no new
// derivation.
//
// `SafeExportSecret` CONSUMES its `(group, epoch, component)` leaf on export
// (SafeExport.swift) — the same constraint `sendCrossPSKLedger` already
// works around for the `0xFF02` cross-party PSK
// (+ClassicalCommit.swift's `rememberSendCrossPSK`). This file mirrors that
// ledger discipline for `0xFF03`, on both directions:
//
// - SEND: `rememberSendAttachmentComponent` runs at every site
//   `sendGroup.classical`'s epoch advances or the group is first created —
//   a SUPERSET of the sites `rememberSendCrossPSK` runs at (this ledger also
//   captures at group creation and at `restore`, which `rememberSendCrossPSK`
//   does not need to) — so `exportAttachmentCEKSend` stays a PURE READ (no
//   live export), matching the return-based persistence contract: a
//   method with no `StateUpdate` to return must never consume
//   single-shot state.
// - RECV: `rememberRecvAttachmentComponent` is CAPTURE-ON-ENTRY — every
//   recv-group creation/advance site ledgers the NEWLY-CURRENT epoch
//   immediately, rather than a departing one. This port's own
//   `exportAttachmentCEKRecv` is a pure read with no live-export fallback,
//   so the current epoch MUST already be ledgered by the time a caller asks
//   for it, or a fetch at the live epoch would wrongly throw — capture-on-
//   entry is what this port does to satisfy that; it makes no claim about
//   how the deployed engine itself times its own capture.

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// draft-ietf-mls-extensions-08 §4.4: export+ledger `classical`'s
	/// CURRENT-epoch `0xFF03` attachment component into `ledger`, unless
	/// that epoch is already there — the shared body behind both
	/// `rememberSendAttachmentComponent` and `rememberRecvAttachmentComponent`
	/// below (byte-identical derivation either direction; only their call
	/// sites' invariants differ, which is why each keeps its own name and
	/// doc rather than being called directly). Pure with respect to `self`:
	/// both parameters are `inout` local copies the caller owns, so a caller
	/// can discard both on failure and a retry re-derives (or re-reuses the
	/// ledgered value) cleanly — `safeExportSecret` consumes a `(group,
	/// epoch, component)` leaf on first export, so re-exporting an
	/// already-ledgered epoch would throw `componentSecretConsumed`.
	private func rememberAttachmentComponent(
		classical: inout MLS.RFC9420.Group,
		ledger: inout [UInt64: SecretBytes]
	) throws {
		let epoch = classical.context.epoch
		guard ledger[epoch] == nil else { return }
		let component = try classical.safeExportSecret(
			classicalProvider, componentID: Self.attachmentComponentID)
		ledger[epoch] = component
		if ledger.count > Self.attachmentLedgerWindow {
			for evict in ledger.keys.sorted().prefix(
				ledger.count - Self.attachmentLedgerWindow)
			{
				ledger[evict] = nil
			}
		}
	}

	/// `rememberAttachmentComponent`, over `sendGroup.classical`. Call sites
	/// are a SUPERSET of `rememberSendCrossPSK`'s own (+ClassicalCommit.swift):
	/// every send-classical commit (`committingRound`/`applyFoldCommit`/
	/// `applyBind`), `joinGroupBIfNeeded` (+Messaging.swift), AND send-group
	/// creation/restore (`initiate`/`receive`/`restore`, via
	/// `captureSendAttachmentComponent`, +Establishment.swift/+Restore.swift)
	/// — the extra sites are what let `exportAttachmentCEKSend` stay a pure
	/// read from the moment a send group exists, rather than only from its
	/// first commit onward.
	// internal: used by ClassicalCommit/Messaging's send-commit sites
	internal func rememberSendAttachmentComponent(
		classical: inout MLS.RFC9420.Group,
		ledger: inout [UInt64: SecretBytes]
	) throws {
		try rememberAttachmentComponent(classical: &classical, ledger: &ledger)
	}

	/// `rememberAttachmentComponent`, over `recvGroup.classical` — same
	/// derivation, same idempotent-per-epoch/value-semantics/window-evict
	/// shape as the send side, but its call sites carry a DIFFERENT
	/// invariant: CAPTURE-ON-ENTRY. `classical` must already be at the epoch
	/// the caller wants ledgered — every recv-group creation/advance site
	/// calls this on the group's NEWLY-CURRENT epoch (`applyFoldCommit`/
	/// `applyBind`, right after their own `pending.apply`; `receive`/
	/// `joinGroupBIfNeeded`, when a recv group is first set; `restore`) —
	/// never on a "departing" epoch the way the send side's `committingRound`
	/// also ledgers alongside the landed one, because a recv frame's own
	/// epoch is exactly what `exportAttachmentCEKRecv`'s caller names, with
	/// no live-export fallback to cover a miss.
	// internal: used by ClassicalCommit's applyFoldCommit/applyBind and
	// Messaging's joinGroupBIfNeeded
	internal func rememberRecvAttachmentComponent(
		classical: inout MLS.RFC9420.Group,
		ledger: inout [UInt64: SecretBytes]
	) throws {
		try rememberAttachmentComponent(classical: &classical, ledger: &ledger)
	}

	/// `rememberSendAttachmentComponent`'s convenience wrapper for call
	/// sites with no local `APQGroup` copy already in scope (`initiate`/
	/// `receive`/`restore`) — mirrors `recordListenRendezvous`'s own role
	/// over its lower-level capture (+Routing.swift). No-op absent a send
	/// group (never observed in practice: `sendGroup` is populated from
	/// construction and never cleared). Idempotent per epoch.
	mutating func captureSendAttachmentComponent() throws {
		guard var send = sendGroup else { return }
		try rememberSendAttachmentComponent(
			classical: &send.classical, ledger: &sendAttachmentLedger)
		sendGroup = send
	}

	/// The receive-side analogue of `captureSendAttachmentComponent`, for
	/// the same class of call site (`receive`/`restore` — `applyFoldCommit`/
	/// `applyBind`/`joinGroupBIfNeeded` already hold a local `recv`/`groupB`
	/// copy for other reasons and call `rememberRecvAttachmentComponent`
	/// directly). No-op absent a receive group.
	mutating func captureRecvAttachmentComponent() throws {
		guard var recv = recvGroup else { return }
		try rememberRecvAttachmentComponent(
			classical: &recv.classical, ledger: &recvAttachmentLedger)
		recvGroup = recv
	}

	/// CEK for a send-side attachment at the CURRENT classical send epoch:
	/// `ExpandWithLabel(SafeExportSecret_classical(0xFF03), "attachment",
	/// keyId, 32)`. A PURE READ — `sendAttachmentLedger` is already
	/// populated at every send-classical commit/creation site (this file's
	/// own header doc), so this never touches `sendGroup` or exports
	/// anything itself. `keyId` is the caller's own random 32-byte
	/// namespacing context for one attachment, never carried on the wire.
	public func exportAttachmentCEKSend(keyId: Data) throws -> Data {
		guard let send = sendGroup else { throw TwoMLSError.notEstablished }
		guard let component = sendAttachmentLedger[send.classical.context.epoch]
		else {
			throw TwoMLSError.attachmentComponentUnavailable
		}
		return try MLS.expandWithLabel(
			classicalProvider, secret: component, label: "attachment",
			context: keyId, length: 32)
	}

	/// CEK for a received attachment framed at classical `epoch` — the
	/// frame's OWN epoch, as the peer's `exportAttachmentCEKSend` saw it
	/// when it sent, not necessarily `recvGroup.classical`'s CURRENT one
	/// (the whole reason this ledgers by epoch rather than reading the live
	/// group: a peer's attachment may still arrive after this session's
	/// recv group has advanced past the epoch it was sent at). A PURE READ,
	/// same shape as `exportAttachmentCEKSend`.
	///
	/// API contract: `epoch`'s component is retained only for
	/// `attachmentLedgerWindow` (8) further classical advances past it —
	/// bounded, like every ledger in this module, not indefinite. Callers
	/// should derive and store the CEK at `processIncoming` time (off that
	/// call's own `DecryptResult.epoch`), not lazily defer the derivation to
	/// whenever the attachment itself is actually opened — a message held
	/// unopened across enough subsequent commits can otherwise see its
	/// epoch's component evicted, and this throws
	/// `.attachmentComponentUnavailable` rather than silently deriving
	/// nothing.
	public func exportAttachmentCEKRecv(keyId: Data, epoch: UInt64) throws -> Data {
		guard let component = recvAttachmentLedger[epoch] else {
			throw TwoMLSError.attachmentComponentUnavailable
		}
		return try MLS.expandWithLabel(
			classicalProvider, secret: component, label: "attachment",
			context: keyId, length: 32)
	}
}
