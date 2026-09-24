import Foundation
import SecretBytes

// MARK: - Migration inputs on stored per-group signing keys
//
// The public shapes a migrator supplies alongside `MigratedSession` once it
// carries per-group signing keys of its own (`MigratedLeafKeys`, replacing
// `SessionMigration`'s temporary owner-keyed conversion), an on-demand own-
// offer window (minted into its OWN blob, never the session archives), and
// the deployed engine's own PQ-wedge / no-custody flags.

/// One leaf's own signing keypair, migrated. Every key is derive-checked at
/// mint (`InvitationMigration.derivedEd25519Public`).
@available(iOS 26, macOS 26, *)
public struct MigratedLeafKey: Sendable {
	/// Ed25519 `rawRepresentation` (32 B).
	public var signingKey: SecretBytes
	public var signatureKey: Data

	public init(signingKey: SecretBytes, signatureKey: Data) {
		self.signingKey = signingKey
		self.signatureKey = signatureKey
	}
}

/// One `pending` entry: the Basic credential id a key is staged for, plus
/// the key itself. `target` must be non-empty.
@available(iOS 26, macOS 26, *)
public struct MigratedPendingLeafKey: Sendable {
	public var target: Data
	public var key: MigratedLeafKey

	public init(target: Data, key: MigratedLeafKey) {
		self.target = target
		self.key = key
	}
}

/// One group's own stored key set, migrated — mirrors `GroupKeySet`'s shape
/// exactly. `current` is `nil` only when the group is named in
/// `MigratedDeployedState.noCustody`.
@available(iOS 26, macOS 26, *)
public struct MigratedGroupKeys: Sendable {
	public var current: MigratedLeafKey?
	public var pending: [MigratedPendingLeafKey]

	public init(current: MigratedLeafKey?, pending: [MigratedPendingLeafKey] = []) {
		self.current = current
		self.pending = pending
	}
}

/// The four groups' own stored key sets, migrated — mirrors `LeafKeys`'s
/// shape exactly. All four are required: a not-yet-existing group still
/// carries its reservation (rule 4).
@available(iOS 26, macOS 26, *)
public struct MigratedLeafKeys: Sendable {
	public var sendClassical: MigratedGroupKeys
	public var recvClassical: MigratedGroupKeys
	public var sendPQ: MigratedGroupKeys
	public var recvPQ: MigratedGroupKeys

	public init(
		sendClassical: MigratedGroupKeys, recvClassical: MigratedGroupKeys,
		sendPQ: MigratedGroupKeys, recvPQ: MigratedGroupKeys
	) {
		self.sendClassical = sendClassical
		self.recvClassical = recvClassical
		self.sendPQ = sendPQ
		self.recvPQ = recvPQ
	}
}

/// One own-Update offer this session staged into `recvGroup.classical`
/// before migration — everything `insertMigratedOwnUpdate` needs to restore
/// it: the RFC 9420 reference the deployed engine's commit may name, the
/// bare (non-framed) RFC 9420 `Proposal` encoding (must decode to
/// `.update`), and the HPKE secret for the proposed leaf's encryption key.
@available(iOS 26, macOS 26, *)
public struct MigratedOwnOffer: Sendable {
	/// `RefHash`, exactly 32 bytes.
	public var ref: Data
	/// RFC 9420 `Proposal` encoding (bare, not MLSMessage-framed); must be
	/// `.update`.
	public var proposal: Data
	/// HPKE secret for the proposal leaf's encryption key.
	public var leafSecret: SecretBytes

	public init(ref: Data, proposal: Data, leafSecret: SecretBytes) {
		self.ref = ref
		self.proposal = proposal
		self.leafSecret = leafSecret
	}
}

/// The own-offer window: minted into its own blob (`SessionMigration.
/// mintOwnOfferWindow`), never into the session archives. `offers` rides in
/// the exporter's own selection order (latest first) — order is otherwise
/// meaningless; both mints canonically sort by ref before computing the id.
@available(iOS 26, macOS 26, *)
public struct MigratedOwnOfferWindow: Sendable {
	public static let maximumOfferCount = 102_400

	/// The recv-classical group's CURRENT epoch, group id and this session's
	/// own leaf index, at the moment the window was exported.
	public var epoch: UInt64
	public var groupID: Data
	public var senderLeafIndex: UInt32
	public var offers: [MigratedOwnOffer]

	public init(
		epoch: UInt64, groupID: Data, senderLeafIndex: UInt32, offers: [MigratedOwnOffer]
	) {
		self.epoch = epoch
		self.groupID = groupID
		self.senderLeafIndex = senderLeafIndex
		self.offers = offers
	}
}

/// Which of a session's four groups a stored key set names — mirrors
/// `LeafKeys`'s own four slots. `UInt8`-raw for a stable archive encoding.
@available(iOS 26, macOS 26, *)
public enum MigratedGroupRole: UInt8, Hashable, CaseIterable, Sendable {
	case sendClassical = 0
	case recvClassical = 1
	case sendPQ = 2
	case recvPQ = 3
}

/// Which PQ side-band round the deployed engine's own trigger wedged past
/// its point of no return, if any — matches the Rust `PqWedge` tags
/// (`pq_ops.rs`) exactly.
@available(iOS 26, macOS 26, *)
public enum MigratedPQWedge: UInt8, Sendable {
	case bootstrap = 0
	case ratchet = 1
	case rekey = 2
}

/// The deployed engine's own migration-only flags: the own-offer window
/// (nil when the exporter has nothing to carry), the PQ wedge state, and
/// which groups this session presently has no signing custody over. All
/// three are additive to `SessionMigration.mintArchive` and read-only at
/// runtime.
@available(iOS 26, macOS 26, *)
public struct MigratedDeployedState: Sendable {
	public var ownOffers: MigratedOwnOfferWindow?
	public var pqWedged: MigratedPQWedge?
	public var noCustody: Set<MigratedGroupRole>

	public init(
		ownOffers: MigratedOwnOfferWindow? = nil, pqWedged: MigratedPQWedge? = nil,
		noCustody: Set<MigratedGroupRole> = []
	) {
		self.ownOffers = ownOffers
		self.pqWedged = pqWedged
		self.noCustody = noCustody
	}
}

/// `SessionMigration.mintOwnOfferWindow`'s result: the unsealed window blob
/// (internal wire shape — see `OwnOfferWindow.swift`) and its id, which
/// `processIncoming(_:ownOfferWindow:)` cross-checks against the session's
/// own restored record.
@available(iOS 26, macOS 26, *)
public struct MintedOwnOfferWindow: Sendable {
	/// Unsealed — the caller seals it with its own archive key, same
	/// convention as every other `SecretArchive` this library returns.
	public let archive: SecretArchive
	/// 32 bytes.
	public let id: Data

	public init(archive: SecretArchive, id: Data) {
		self.archive = archive
		self.id = id
	}
}
