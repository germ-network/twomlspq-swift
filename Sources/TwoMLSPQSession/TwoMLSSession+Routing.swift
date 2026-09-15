import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Rendezvous routing (slice 9, PR1)
//
// Both ends of a directional pair independently derive the SAME rendezvous
// address off a classical group's exporter secret (book
// session-lifecycle.md, "Routing"): `send_rendezvous()` reads it off MY
// receive group (the peer's send group) at its current epoch;
// `should_listen_on()` reports one address per retained epoch of MY OWN send
// group, since the peer may still be posting at a recently-prior epoch's
// address. This slice is classical-only — the PQ side-band carries no
// routing addresses of its own.

/// A 32-byte rendezvous address — one classical group's `exportSecret(label:
/// "rendezvous", context: "TwoMLS")` output at a single epoch.
public struct RendezvousId: Sendable, Equatable, Hashable {
	public let rawValue: Data

	public init(_ rawValue: Data) {
		self.rawValue = rawValue
	}
}

/// One retained classical epoch's rendezvous address, as `shouldListenOn`
/// reports it.
public struct EpochRendezvous: Sendable, Equatable {
	public let epoch: UInt64
	public let rendezvousId: RendezvousId
}

/// A directional group pair's ids as the host sees them — mirrors the
/// combiner's own `{classical, pq}` shape. `pq` is `nil` while that half is
/// deferred.
public struct CombinerGroupId: Sendable, Equatable {
	public let classical: Data
	public let pq: Data?
}

/// `shouldListenOn`'s result: where the transport should watch — the send
/// group's own ids, plus one rendezvous address per retained classical
/// epoch.
public struct ListenChannels: Sendable, Equatable {
	public let sendGroup: CombinerGroupId
	public let rendezvousByEpoch: [EpochRendezvous]
}

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// The book's fixed `(label, context, length)` triple
	/// (session-lifecycle.md, "Routing") — a raw, un-pre-hashed context:
	/// `Group.exportSecret` hashes it internally (RFC 9420 §8.5).
	enum RendezvousConstants {
		static let label = "rendezvous"
		static let context = Data("TwoMLS".utf8)
		static let length = 32
	}

	/// RFC 9420 §8.5 MLS-Exporter off a classical group's CURRENT epoch —
	/// non-consuming and repeatable, so both this session and its peer (each
	/// holding their own copy of the same group) derive identical bytes.
	func rendezvousSecret(_ classical: MLS.RFC9420.Group) throws -> Data {
		let secret = try classical.exportSecret(
			classicalProvider, label: RendezvousConstants.label,
			context: RendezvousConstants.context, length: RendezvousConstants.length)
		return secret.withUnsafeBytes { Data($0) }
	}

	/// Where to post: the receive group's exporter at its CURRENT epoch — the
	/// receive group IS the peer's send group, so this value appears verbatim
	/// in the peer's own `shouldListenOn()`. `nil` before the receive group
	/// exists (the initiator's first frame travels the invitation channel
	/// instead).
	public func sendRendezvous() -> RendezvousId? {
		guard let recv = recvGroup else { return nil }
		// `rendezvousSecret` only fails for a genuinely broken provider/
		// group pairing — never for a live, correctly-established recv
		// group — so a throw here folds into the same "not routable yet"
		// `nil` as the no-recv-group case, rather than widening this read's
		// signature to `throws`.
		guard let secret = try? rendezvousSecret(recv.classical) else { return nil }
		return RendezvousId(secret)
	}

	/// Capture THIS session's own send-group classical epoch's rendezvous
	/// address into the retained listen map, then prune to the retention
	/// window. Idempotent per epoch. Call from every site where
	/// `sendGroup.classical`'s epoch advances or the group is first created —
	/// never from `shouldListenOn` (see `listenRendezvous`'s doc).
	mutating func recordListenRendezvous() throws {
		guard let send = sendGroup else { return }
		let epoch = send.classical.context.epoch
		if listenRendezvous[epoch] == nil {
			listenRendezvous[epoch] = try rendezvousSecret(send.classical)
		}
		let depth = UInt64(send.classical.retention.resumptionPskDepth)
		let floor = epoch > depth ? epoch - depth : 0
		listenRendezvous = listenRendezvous.filter { $0.key >= floor }
	}

	/// A **pure read** — the send group's ids plus one rendezvous address
	/// per retained classical epoch. Never mutates or captures: every
	/// capture happens deterministically at the mutation sites that already
	/// return a `StateUpdate` (`listenRendezvous`'s doc), so a read-only call
	/// here has nothing new to persist.
	public func shouldListenOn() -> ListenChannels {
		let ids = CombinerGroupId(
			// `sendGroup` is populated from the moment `initiate`/`receive`
			// construct a session and never cleared, so the `nil` arm below
			// is unreachable in practice — kept for the type's honesty
			// rather than a force-unwrap.
			classical: sendGroup?.classical.context.groupID ?? Data(),
			pq: sendGroup?.pq?.context.groupID)
		let rendezvous =
			listenRendezvous
			.map {
				EpochRendezvous(epoch: $0.key, rendezvousId: RendezvousId($0.value))
			}
			.sorted { $0.epoch < $1.epoch }
		return ListenChannels(sendGroup: ids, rendezvousByEpoch: rendezvous)
	}
}
