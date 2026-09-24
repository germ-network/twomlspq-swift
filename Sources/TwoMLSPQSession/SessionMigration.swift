import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto

// MARK: - Session migration minter (GER-2433 slice B)
//
// The cross-module session migrator's parts-to-archive entry: mint the
// Swift-native v1 `SessionArchive` body directly from raw parts a legacy Rust
// TwoMLSPQ session supplies — no live `TwoMLSSession`, no `TwoMLSIdentity`
// construction, and no `Principal`. Unlike `InvitationMigration.mintArchive`
// this minter is NOT provider-free: the per-group ingress needs the two
// `CipherSuiteProvider`s (below), though `SecretArchive(encoding:)` itself
// never touches crypto. "Mint the archive, not a live object": the migrator
// dual-reads the legacy side, single-writes this one.

/// Raw migrated identity parts for a SESSION, mirroring `IdentityArchive`'s
/// field types exactly. Same shape and byte representations as
/// `MigratedIdentity`, with one difference the session path forces: the init
/// secrets are OPTIONAL. A session's identity carries them only while
/// establishment is in flight — an initiator holds the classical init secret
/// until it joins Group_B (the PQ one is already cleared at `initiate`), an
/// established session holds neither (both spent; `TwoMLSIdentity.
/// clearingInitSecrets`). The mint gates on that semantics directly: init
/// secrets are accepted only when the parts' `recvGroup` is `nil`
/// (pre-establishment), mirroring the native `includeInitSecrets:
/// recvGroup == nil`, and each supplied one is cross-checked against its
/// `KeyPackage`'s `initKey` exactly like `MigratedIdentity`'s non-optional
/// pair.
///
/// Secret-key byte representations (same conventions as `MigratedIdentity`):
///  - The two Ed25519 signing keys: `rawRepresentation` (32 B each).
///  - The classical HPKE secrets: X25519 `rawRepresentation` (32 B).
///  - The PQ HPKE secrets: `MLKEM768.PrivateKey.integrityCheckedRepresentation`
///    (96 B — seed‖SHA3-256(ek)).
///  - `classicalKeyPackage`/`pqKeyPackage`: BARE `KeyPackage` wire bytes.
@available(iOS 26, macOS 26, *)
public struct MigratedSessionIdentity: Sendable {
	/// Must equal both `KeyPackage`s' Basic credential identities.
	public var clientID: Data
	/// Ed25519 `rawRepresentation` (32 B).
	public var signingKey: SecretBytes
	public var signatureKey: Data
	/// Ed25519 `rawRepresentation` (32 B) — independent of `signingKey`
	/// (per-half keys are the native model).
	public var pqSigningKey: SecretBytes
	public var pqSignatureKey: Data
	/// X25519 `rawRepresentation` (32 B).
	public var classicalLeafSecretKey: SecretBytes
	/// X25519 `rawRepresentation` (32 B). Supplied only for a
	/// pre-establishment initiator (see the type doc).
	public var classicalInitSecretKey: SecretBytes?
	/// ML-KEM-768 `integrityCheckedRepresentation` (96 B).
	public var pqLeafSecretKey: SecretBytes
	/// ML-KEM-768 `integrityCheckedRepresentation` (96 B). The native session
	/// path never carries one (`initiate` clears it as dead before any
	/// archive can exist); supplying one is a mint-time `archiveInvalid`.
	public var pqInitSecretKey: SecretBytes?
	/// BARE classical `KeyPackage` wire bytes.
	public var classicalKeyPackage: Data
	/// BARE PQ `KeyPackage` wire bytes.
	public var pqKeyPackage: Data

	public init(
		clientID: Data,
		signingKey: SecretBytes,
		signatureKey: Data,
		pqSigningKey: SecretBytes,
		pqSignatureKey: Data,
		classicalLeafSecretKey: SecretBytes,
		classicalInitSecretKey: SecretBytes?,
		pqLeafSecretKey: SecretBytes,
		pqInitSecretKey: SecretBytes?,
		classicalKeyPackage: Data,
		pqKeyPackage: Data
	) {
		self.clientID = clientID
		self.signingKey = signingKey
		self.signatureKey = signatureKey
		self.pqSigningKey = pqSigningKey
		self.pqSignatureKey = pqSignatureKey
		self.classicalLeafSecretKey = classicalLeafSecretKey
		self.classicalInitSecretKey = classicalInitSecretKey
		self.pqLeafSecretKey = pqLeafSecretKey
		self.pqInitSecretKey = pqInitSecretKey
		self.classicalKeyPackage = classicalKeyPackage
		self.pqKeyPackage = pqKeyPackage
	}
}

/// One party's migrated credential sequence — the raw parts of the internal
/// `PartySequence` (`CredentialAuthentication.swift`).
@available(iOS 26, macOS 26, *)
public struct MigratedPartySequence: Sendable {
	/// Oldest → newest canonical credentials, trimmed to the AS history
	/// window by the live path; supplied as the legacy state holds them.
	public var history: [Data]
	public var authorizedNext: [Data]
	public var pinned: [Data]

	public init(history: [Data], authorizedNext: [Data], pinned: [Data]) {
		self.history = history
		self.authorizedNext = authorizedNext
		self.pinned = pinned
	}
}

/// The migrated 2-party AS state — the raw parts of the internal `AuthCore`.
@available(iOS 26, macOS 26, *)
public struct MigratedAuth: Sendable {
	public var mine: MigratedPartySequence
	public var theirs: MigratedPartySequence

	public init(mine: MigratedPartySequence, theirs: MigratedPartySequence) {
		self.mine = mine
		self.theirs = theirs
	}
}

/// One group half's migrated state: each side's per-half snapshot as a
/// `SecretArchive` — the value `MLS.RFC9420.Group.archive()` produces for a
/// format-2 snapshot (and what the migrator builds from a Rust exporter's
/// format-2 snapshot bytes via `SecretArchive(decodingPlaintext:)`, the same
/// plaintext-ingress SPI swift-mls's own mls-rs migration path uses).
///
/// The archive must carry the CURRENT epoch's exporter tree: the mint
/// re-snapshots through a live `Group.restore` (the only public way to reach
/// a `Group.Snapshot` value), and a group with no exporter tree for its
/// current epoch cannot be re-archived — a legacy export without one is a
/// legacy-exporter gap, not something this minter can paper over.
@available(iOS 26, macOS 26, *)
public struct MigratedGroupHalf: Sendable {
	public var classical: SecretArchive
	public var pq: SecretArchive?

	public init(classical: SecretArchive, pq: SecretArchive?) {
		self.classical = classical
		self.pq = pq
	}
}

/// Raw parts of the internal `PendingProposalArchive`.
@available(iOS 26, macOS 26, *)
public struct MigratedProposal: Sendable {
	public var proposing: Data
	public var message: Data
	public var hash: Data

	public init(proposing: Data, message: Data, hash: Data) {
		self.proposing = proposing
		self.message = message
		self.hash = hash
	}
}

/// Raw parts of the internal `DigestedProposalArchive` (offered/queued).
@available(iOS 26, macOS 26, *)
public struct MigratedDigestedProposal: Sendable {
	public var digest: Data
	public var proposing: Data
	public var message: Data

	public init(digest: Data, proposing: Data, message: Data) {
		self.digest = digest
		self.proposing = proposing
		self.message = message
	}
}

/// Raw parts of one internal `StagedUpdateArchive` entry.
@available(iOS 26, macOS 26, *)
public struct MigratedStagedUpdate: Sendable {
	public var digest: Data
	public var message: Data

	public init(digest: Data, message: Data) {
		self.digest = digest
		self.message = message
	}
}

/// Raw parts of the internal `OwedBind`.
@available(iOS 26, macOS 26, *)
public struct MigratedOwedBind: Sendable {
	public var pqCommitMessage: Data
	public var tEpoch: UInt64
	public var pqEpoch: UInt64

	public init(pqCommitMessage: Data, tEpoch: UInt64, pqEpoch: UInt64) {
		self.pqCommitMessage = pqCommitMessage
		self.tEpoch = tEpoch
		self.pqEpoch = pqEpoch
	}
}

/// Raw parts of the internal `BootstrapKPSecretArchive`: KP′'s leaf/init
/// HPKE secrets (X25519 `rawRepresentation`, 32 B each) plus the KP itself
/// (BARE `KeyPackage` wire bytes).
@available(iOS 26, macOS 26, *)
public struct MigratedBootstrapKPSecret: Sendable {
	public var leafSecretKey: SecretBytes
	public var initSecretKey: SecretBytes
	public var keyPackage: Data

	public init(leafSecretKey: SecretBytes, initSecretKey: SecretBytes, keyPackage: Data) {
		self.leafSecretKey = leafSecretKey
		self.initSecretKey = initSecretKey
		self.keyPackage = keyPackage
	}
}

/// Raw parts of the internal `PQInflightArchive` — every case, including the
/// held KEM secret/`S`/parked wire CT, so a Responding or initiating round
/// survives the migration intact.
@available(iOS 26, macOS 26, *)
public enum MigratedPQInflight: Sendable {
	case bootstrapInitiated
	case bootstrapResponded
	/// ML-KEM-768 `integrityCheckedRepresentation` (96 B) secret key.
	case initiating(secretKey: SecretBytes, ek: Data)
	case responding(secret: SecretBytes, wireCT: Data)
	case rekeyInitiated(updMessage: Data)
	case rekeyResponded
}

/// Raw parts of one internal `ExportedPskArchive` ledger entry.
@available(iOS 26, macOS 26, *)
public struct MigratedExportedPsk: Sendable {
	public var componentID: UInt16
	public var pskID: Data
	public var psk: SecretBytes

	public init(componentID: UInt16, pskID: Data, psk: SecretBytes) {
		self.componentID = componentID
		self.pskID = pskID
		self.psk = psk
	}
}

/// Raw parts of the internal `RotationCandidateArchive`.
@available(iOS 26, macOS 26, *)
public struct MigratedRotationCandidate: Sendable {
	public var clientID: Data
	/// Ed25519 `rawRepresentation` (32 B).
	public var signingKey: SecretBytes
	public var signatureKey: Data
	public var proposedAtRecvEpoch: UInt64

	public init(
		clientID: Data, signingKey: SecretBytes, signatureKey: Data,
		proposedAtRecvEpoch: UInt64
	) {
		self.clientID = clientID
		self.signingKey = signingKey
		self.signatureKey = signatureKey
		self.proposedAtRecvEpoch = proposedAtRecvEpoch
	}
}

/// Raw parts of the internal `RecvLeafPrincipalArchive` — the retained
/// recv-leaf custody's classical AND PQ pairs (both non-optional, mirroring
/// the live `RecvLeafPrincipal`).
@available(iOS 26, macOS 26, *)
public struct MigratedRecvLeafPrincipal: Sendable {
	public var clientID: Data
	/// Ed25519 `rawRepresentation` (32 B).
	public var signingKey: SecretBytes
	public var signatureKey: Data
	/// Ed25519 `rawRepresentation` (32 B).
	public var pqSigningKey: SecretBytes
	public var pqSignatureKey: Data

	public init(
		clientID: Data, signingKey: SecretBytes, signatureKey: Data,
		pqSigningKey: SecretBytes, pqSignatureKey: Data
	) {
		self.clientID = clientID
		self.signingKey = signingKey
		self.signatureKey = signatureKey
		self.pqSigningKey = pqSigningKey
		self.pqSignatureKey = pqSignatureKey
	}
}

/// The raw session parts `SessionMigration.mintArchive` mints from — one
/// property per `SessionArchive` field the mint doesn't set itself, mirroring
/// the internal archive field types with raw ones (`SecretBytes`/`Data` and
/// small public mirrors; `version`/suites/`kind` are minter-set, and the
/// four manifest fields are derived from the restored group halves — see
/// `mintArchive`). Defaults make the pre-establishment and fully-quiescent
/// states expressible without listing every empty slot.
///
/// The attachment ledgers (`sendAttachmentLedger`/`recvAttachmentLedger`)
/// are NOT safe to pass empty for any source that already consumed its
/// current epoch's `0xFF03` component — this port and the deployed engine
/// both export-and-consume at group creation, so that is every realistic
/// source: restore re-captures the current epoch with the CONSUMING
/// `safeExportSecret`, which throws for an already-consumed epoch, so a
/// ledger missing the current epoch mints an archive that fails
/// `.archiveInvalid` at restore (and a legacy source that never exported
/// `0xFF03` at all restores fine either way). The three re-derivable
/// windows (`listenRendezvous`/`recvHeaderKeys`/`recvHeaderKeysPQ`) ARE
/// safe to pass empty — restore re-captures their current-epoch entries
/// from the non-consuming exporter — at the cost of the retained
/// past-epoch entries (recently-prior epochs stop being
/// listenable/openable).
@available(iOS 26, macOS 26, *)
public struct MigratedSession: Sendable {
	public var stateSeq: UInt64
	public var initiated: Bool
	public var identity: MigratedSessionIdentity
	public var auth: MigratedAuth
	/// Never `nil` — the send group exists from construction and is never
	/// cleared (the founding full pair for an initiator, the bootstrapped
	/// Group_B for a responder).
	public var sendGroup: MigratedGroupHalf
	/// `nil` only for a pre-establishment initiator.
	public var recvGroup: MigratedGroupHalf?
	public var currentStaple: Data
	public var pendingProposal: MigratedProposal?
	public var joinedWelcomeDigest: Data?
	public var bootstrapKPSecret: MigratedBootstrapKPSecret?
	public var expectedBootstrapKPCommitment: Data?
	public var pqTurnMine: Bool
	public var owedBind: MigratedOwedBind?
	public var pqInflight: MigratedPQInflight?
	public var pendingSideBand: Data?
	public var peerAppliedSendEpoch: UInt64?
	public var lastCrossInjected: UInt64?
	public var lastCrossInjectedPQ: UInt64?
	public var lastSendPQExported: UInt64?
	public var offeredProposal: MigratedDigestedProposal?
	public var queuedProposal: MigratedDigestedProposal?
	public var stagedUpdates: [MigratedStagedUpdate]
	public var sendCrossPSKLedger: [UInt64: MigratedExportedPsk]
	public var rotationCandidate: MigratedRotationCandidate?
	public var spawnToken: Data?
	public var listenRendezvous: [UInt64: Data]
	public var recvHeaderKeys: [UInt64: Data]
	public var recvHeaderKeysPQ: [UInt64: Data]
	public var sendAttachmentLedger: [UInt64: SecretBytes]
	public var recvAttachmentLedger: [UInt64: SecretBytes]
	/// The peer's published combiner key package, BARE `KeyPackage` wire
	/// bytes per half — carried only by a live pre-Group_B-join initiator.
	public var initialTheirKP: (classical: Data, pq: Data)?
	public var recvLeafPrincipal: MigratedRecvLeafPrincipal?
	public var owesEstablishmentEnvelope: Bool
	/// Step 3, rule 1: per-group signing keys — authoritative when present.
	/// `nil` falls back to the temporary owner-keyed conversion
	/// (`convertDeployedKeys`), deleted once every migrator supplies this.
	public var leafKeys: MigratedLeafKeys?
	/// Step 3, rule 9: non-empty only for a pre-join initiator. Stored and
	/// validated only — there is no host accessor; a later step's envelope/
	/// pre-establishment change consumes it through `pendingOutbound()`.
	public var initialAppPayload: Data?

	public init(
		stateSeq: UInt64 = 0,
		initiated: Bool,
		identity: MigratedSessionIdentity,
		auth: MigratedAuth,
		sendGroup: MigratedGroupHalf,
		recvGroup: MigratedGroupHalf? = nil,
		currentStaple: Data = Data(),
		pendingProposal: MigratedProposal? = nil,
		joinedWelcomeDigest: Data? = nil,
		bootstrapKPSecret: MigratedBootstrapKPSecret? = nil,
		expectedBootstrapKPCommitment: Data? = nil,
		pqTurnMine: Bool = false,
		owedBind: MigratedOwedBind? = nil,
		pqInflight: MigratedPQInflight? = nil,
		pendingSideBand: Data? = nil,
		peerAppliedSendEpoch: UInt64? = nil,
		lastCrossInjected: UInt64? = nil,
		lastCrossInjectedPQ: UInt64? = nil,
		lastSendPQExported: UInt64? = nil,
		offeredProposal: MigratedDigestedProposal? = nil,
		queuedProposal: MigratedDigestedProposal? = nil,
		stagedUpdates: [MigratedStagedUpdate] = [],
		sendCrossPSKLedger: [UInt64: MigratedExportedPsk] = [:],
		rotationCandidate: MigratedRotationCandidate? = nil,
		spawnToken: Data? = nil,
		listenRendezvous: [UInt64: Data] = [:],
		recvHeaderKeys: [UInt64: Data] = [:],
		recvHeaderKeysPQ: [UInt64: Data] = [:],
		sendAttachmentLedger: [UInt64: SecretBytes] = [:],
		recvAttachmentLedger: [UInt64: SecretBytes] = [:],
		initialTheirKP: (classical: Data, pq: Data)? = nil,
		recvLeafPrincipal: MigratedRecvLeafPrincipal? = nil,
		owesEstablishmentEnvelope: Bool = false,
		leafKeys: MigratedLeafKeys? = nil,
		initialAppPayload: Data? = nil
	) {
		self.stateSeq = stateSeq
		self.initiated = initiated
		self.identity = identity
		self.auth = auth
		self.sendGroup = sendGroup
		self.recvGroup = recvGroup
		self.currentStaple = currentStaple
		self.pendingProposal = pendingProposal
		self.joinedWelcomeDigest = joinedWelcomeDigest
		self.bootstrapKPSecret = bootstrapKPSecret
		self.expectedBootstrapKPCommitment = expectedBootstrapKPCommitment
		self.pqTurnMine = pqTurnMine
		self.owedBind = owedBind
		self.pqInflight = pqInflight
		self.pendingSideBand = pendingSideBand
		self.peerAppliedSendEpoch = peerAppliedSendEpoch
		self.lastCrossInjected = lastCrossInjected
		self.lastCrossInjectedPQ = lastCrossInjectedPQ
		self.lastSendPQExported = lastSendPQExported
		self.offeredProposal = offeredProposal
		self.queuedProposal = queuedProposal
		self.stagedUpdates = stagedUpdates
		self.sendCrossPSKLedger = sendCrossPSKLedger
		self.rotationCandidate = rotationCandidate
		self.spawnToken = spawnToken
		self.listenRendezvous = listenRendezvous
		self.recvHeaderKeys = recvHeaderKeys
		self.recvHeaderKeysPQ = recvHeaderKeysPQ
		self.sendAttachmentLedger = sendAttachmentLedger
		self.recvAttachmentLedger = recvAttachmentLedger
		self.initialTheirKP = initialTheirKP
		self.recvLeafPrincipal = recvLeafPrincipal
		self.owesEstablishmentEnvelope = owesEstablishmentEnvelope
		self.leafKeys = leafKeys
		self.initialAppPayload = initialAppPayload
	}
}

/// The shared mint-time identity check behind both the invitation and the
/// session minter: the SAME checks `IdentityArchive.restore` runs (both
/// per-half Ed25519 derive-checks, each half's leaf `signatureKey` binding),
/// plus the HPKE/KP checks restore never does — each secret's derived public
/// must match its `KeyPackage`'s `initKey`/`encryptionKey`, and both Basic
/// credentials (and the invitation-level `clientID` for the invitation
/// caller) must be `clientID` — so a mis-mapped part fails loudly at mint as
/// `.archiveInvalid` instead of restoring cleanly and failing opaquely at
/// first use. Init secrets are checked only when supplied; the caller owns
/// the supply-condition gate (the invitation path always supplies, the
/// session path only pre-establishment).
@available(iOS 26, macOS 26, *)
func checkedIdentityArchive(
	clientID: Data,
	signingKey: SecretBytes,
	signatureKey: Data,
	pqSigningKey: SecretBytes,
	pqSignatureKey: Data,
	classicalLeafSecretKey: SecretBytes,
	classicalInitSecretKey: SecretBytes?,
	pqLeafSecretKey: SecretBytes,
	pqInitSecretKey: SecretBytes?,
	classicalKeyPackage: Data,
	pqKeyPackage: Data
) throws -> IdentityArchive {
	guard try InvitationMigration.derivedEd25519Public(from: signingKey) == signatureKey,
		try InvitationMigration.derivedEd25519Public(from: pqSigningKey)
			== pqSignatureKey
	else {
		throw TwoMLSError.archiveInvalid
	}
	// Keyed decodes folded to fail-closed `archiveInvalid` — an
	// MLSMessage-FRAMED KeyPackage (the migrator's likeliest mistake)
	// otherwise escapes as a raw `CodecError`.
	let classicalKP: MLS.RFC9420.KeyPackage
	let pqKP: MLS.RFC9420.KeyPackage
	do {
		classicalKP = try MLS.RFC9420.KeyPackage(mlsEncoded: classicalKeyPackage)
		pqKP = try MLS.RFC9420.KeyPackage(mlsEncoded: pqKeyPackage)
	} catch is MLS.CodecError {
		throw TwoMLSError.archiveInvalid
	}
	let classicalInitOK = try matchInitSecret(
		classicalInitSecretKey, classicalKP.initKey
	) { secret in try InvitationMigration.classicalPublic(from: secret) }
	let pqInitOK = try matchInitSecret(
		pqInitSecretKey, pqKP.initKey
	) { secret in try InvitationMigration.pqPublic(from: secret) }
	guard classicalKP.version == .mls10, pqKP.version == .mls10,
		classicalKP.cipherSuite == TwoMLSSuite.classical,
		pqKP.cipherSuite == TwoMLSSuite.pq,
		try basicIdentifier(classicalKP.leafNode.credential) == clientID,
		try basicIdentifier(pqKP.leafNode.credential) == clientID,
		classicalKP.leafNode.signatureKey.data == signatureKey,
		pqKP.leafNode.signatureKey.data == pqSignatureKey,
		try InvitationMigration.classicalPublic(from: classicalLeafSecretKey)
			== classicalKP.leafNode.encryptionKey.data,
		try InvitationMigration.pqPublic(from: pqLeafSecretKey)
			== pqKP.leafNode.encryptionKey.data,
		classicalInitOK,
		pqInitOK
	else {
		throw TwoMLSError.archiveInvalid
	}
	return IdentityArchive(
		clientID: clientID,
		signingKey: signingKey,
		signatureKey: signatureKey,
		pqSigningKey: pqSigningKey,
		pqSignatureKey: pqSignatureKey,
		classicalLeafSecretKey: classicalLeafSecretKey,
		classicalInitSecretKey: classicalInitSecretKey.map {
			SecretField(wrappedValue: $0)
		},
		pqLeafSecretKey: pqLeafSecretKey,
		pqInitSecretKey: pqInitSecretKey.map { SecretField(wrappedValue: $0) },
		classicalKeyPackage: classicalKeyPackage,
		pqKeyPackage: pqKeyPackage)
}

/// `nil` matches `nil` (nothing supplied, nothing checked); a supplied init
/// secret must derive to its `KeyPackage`'s `initKey` — the same check the
/// invitation minter runs unconditionally on its non-optional pair.
private func matchInitSecret(
	_ secret: SecretBytes?, _ initKey: MLS.HpkePublicKey,
	using derive: (SecretBytes) throws -> Data
) throws -> Bool {
	guard let secret else { return true }
	return try derive(secret) == initKey.data
}

@available(iOS 26, macOS 26, *)
public enum SessionMigration {
	/// Mint a native, unsealed, zeroizing session `SecretArchive` from raw
	/// migrated parts — the session-level analogue of
	/// `InvitationMigration.mintArchive`. The result is
	/// value-identical to what `makeSessionArchive(kind:)` would have
	/// produced for the same state (the group halves arrive as snapshot
	/// archives and are re-snapshotted through a live `Group.restore`, the
	/// only public path to a `Group.Snapshot` value; restore→`makeSnapshot()`
	/// is value-preserving, so the minted entry equals the native one) —
	/// value-identical, not byte-identical: the integer-keyed maps encode in
	/// `Dictionary` order, exactly as the native path's own encodings do.
	/// The app seals it with its own key; this library never holds a sealing
	/// key.
	///
	/// NOT provider-free (unlike the invitation minter): each group half's
	/// snapshot archive is restored with its half's provider to validate it
	/// and read the manifest fields (`Snapshot`'s own members are internal to
	/// swift-mls). The manifest fields the native path derives from the live
	/// groups — `sendPQEpoch`/`recvPQEpoch`/
	/// `sendClassicalGroupID`/`recvClassicalGroupID` — are derived here the
	/// same way, never taken from the parts, so a migrated archive cannot
	/// disagree with its own snapshots.
	///
	/// After building the body the mint trial-restores it
	/// (`TwoMLSSession.restore(core: nil, checkpoint:)`, result discarded) —
	/// side-effect-free on the archive, and it converts every structural
	/// mis-mapping (decode invariants, pair identity, manifest-vs-groups,
	/// attachment-ledger consistency) into a loud mint-time failure instead
	/// of an opaque one at first use. Core-kind bodies skip the trial (a
	/// Core alone is never restorable — `restore` requires the Checkpoint
	/// slot); they pair with the minted Checkpoint in the app's reconcile
	/// slots exactly as the native return cadence's blobs do.
	///
	/// - Throws: `TwoMLSError.cipherSuiteMismatch` if a provider doesn't back
	///   its suite; `TwoMLSError.archiveInvalid` if any migrated part fails
	///   its cross-check — a signing keypair that doesn't derive to its
	///   public, a secret whose derived public doesn't match its
	///   `KeyPackage`'s `initKey`/`encryptionKey`, a Basic credential
	///   identity that isn't `clientID`, an init secret shaped against the
	///   native gate (the PQ one is NEVER accepted — the native path clears
	///   it before any session archive can exist; the classical one only
	///   for a pre-establishment initiator, and REQUIRED there), a group
	///   half whose snapshot doesn't restore, a group's own leaf presenting
	///   a signing key the converted `leafKeys` set doesn't hold at
	///   `current`, a `KeyPackage` part that doesn't MLS-decode or whose secrets don't
	///   derive to it (the identity pair AND KP′/`initialTheirKP`), a
	///   topology violation (`recvGroup` absent without `initiated`; the
	///   standard pair missing its PQ snapshot), a decode-invariant breach
	///   (the 32-byte rules), `validateLeafKeys`'s own checks failing
	///   against the converted parts (an own current-epoch
	///   staged/pending/parked Update naming a key the converted
	///   `leafKeys` doesn't hold, a reservation not matching `identity`,
	///   or an outstanding rotation candidate / rule-4 catch-up target
	///   incoherent with its expected `pending` entry), or any other
	///   structural inconsistency the trial restore rejects.
	public static func mintArchive(
		kind: BlobKind,
		parts: MigratedSession,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		deployedState: MigratedDeployedState? = nil
	) throws -> SecretArchive {
		guard
			classicalProvider.cipherSuite == TwoMLSSuite.classical,
			pqProvider.cipherSuite == TwoMLSSuite.pq
		else { throw TwoMLSError.cipherSuiteMismatch }

		// Topology invariants the restore path assumes of any archive it
		// decodes: a session without a receive group is an in-flight
		// INITIATOR (`initiated` is `let`, set `true` only by `initiate`;
		// the responder's `receive` always sets its recv group), and the
		// standard (full-combiner) pair always has a PQ half —
		// `restoreStandardPair` fail-closes on its absence.
		if parts.recvGroup == nil, !parts.initiated {
			throw TwoMLSError.archiveInvalid
		}
		let standardHalf = parts.initiated ? parts.sendGroup : parts.recvGroup
		guard standardHalf?.pq != nil else { throw TwoMLSError.archiveInvalid }
		// The init-secret gate is the native `includeInitSecrets:
		// recvGroup == nil` semantics, stated as mint-time requirements
		// instead of an encode-time flag. The PQ init secret is cleared at
		// `initiate` before any session archive can exist, so the native
		// path NEVER emits one — rejected unconditionally, before the
		// identity cross-checks could otherwise admit a (legacy-supplied)
		// correct one. A PRE-ESTABLISHMENT initiator carries the classical
		// init secret — live until the same step that sets the recv group
		// (`joinGroupBIfNeeded`) clears it — so a recv-less session without
		// one could never complete establishment after restore; an
		// ESTABLISHED session carries neither (both spent).
		if parts.identity.pqInitSecretKey != nil {
			throw TwoMLSError.archiveInvalid
		}
		if parts.recvGroup != nil {
			if parts.identity.classicalInitSecretKey != nil {
				throw TwoMLSError.archiveInvalid
			}
		} else {
			if parts.identity.classicalInitSecretKey == nil {
				throw TwoMLSError.archiveInvalid
			}
		}

		let identityArchive = try checkedIdentityArchive(
			clientID: parts.identity.clientID,
			signingKey: parts.identity.signingKey,
			signatureKey: parts.identity.signatureKey,
			pqSigningKey: parts.identity.pqSigningKey,
			pqSignatureKey: parts.identity.pqSignatureKey,
			classicalLeafSecretKey: parts.identity.classicalLeafSecretKey,
			classicalInitSecretKey: parts.identity.classicalInitSecretKey,
			pqLeafSecretKey: parts.identity.pqLeafSecretKey,
			pqInitSecretKey: parts.identity.pqInitSecretKey,
			classicalKeyPackage: parts.identity.classicalKeyPackage,
			pqKeyPackage: parts.identity.pqKeyPackage)

		// Both halves restore up front (the manifest derives from the LIVE
		// restored groups, never from the parts), then every half's own leaf
		// must match what the converted `leafKeys` holds at `current` — the
		// same check `assertLeafKeysPresented()` enforces at every live
		// state update, so a mis-mapping fails at mint instead of as
		// `.credentialUnknown` on the first post-restore send.
		let sendClassical = try restoredGroup(
			parts.sendGroup.classical, classicalProvider)
		let sendPQ = try parts.sendGroup.pq.map {
			try restoredGroup($0, pqProvider)
		}
		let recvClassical = try parts.recvGroup.map {
			try restoredGroup($0.classical, classicalProvider)
		}
		let recvPQ = try parts.recvGroup?.pq.map {
			try restoredGroup($0, pqProvider)
		}

		// A.2 step 2 ("drop at import", both leafKeys paths — run before
		// `convertDeployedKeys`/`nativeLeafKeys` and before
		// `validateLeafKeys`): a parked §A.5 Upd′ that fails to verify
		// against the restored recv-PQ group is exactly what `pqRekeyApply`
		// would fail on forever (book anomaly 5's resolution,
		// session-lifecycle.md at 69a9f0e: "drops its mis-signed parked
		// Upd' and re-proposes under the carried key"), so mint drops it
		// here instead of minting a session that can never apply its own
		// round.
		var effectivePqInflight = parts.pqInflight
		var effectivePendingSideBand = parts.pendingSideBand
		var droppedRekeyTarget: Data?
		if case .rekeyInitiated(let updMessage) = parts.pqInflight {
			let verifies: Bool = {
				guard let recvPQ else { return false }
				return
					(try? TwoMLSSession.decodedUpdateTarget(
						updMessage, against: recvPQ, provider: pqProvider))
					!= nil
			}()
			if !verifies {
				guard
					parts.pendingSideBand == nil
						|| parts.pendingSideBand
							== Frames.encodePQRekeyUpd(updMessage)
				else {
					throw TwoMLSError.archiveInvalid
				}
				effectivePqInflight = nil
				effectivePendingSideBand = nil
				droppedRekeyTarget = Self.decodedUpdateTargetIgnoringSignature(
					updMessage)
			}
		}

		// The two optional custody records derive-check kind-independently —
		// a core-kind mint gets no trial restore (which would run these via
		// the archive types' own `restore()`s), and `convertDeployedKeys`
		// below only ever copies these secrets, never re-derives them —
		// so an underived candidate/principal key must fail HERE rather
		// than silently riding into the converted `leafKeys`.
		if let candidate = parts.rotationCandidate,
			try InvitationMigration.derivedEd25519Public(from: candidate.signingKey)
				!= candidate.signatureKey
		{
			throw TwoMLSError.archiveInvalid
		}
		if let recvLeaf = parts.recvLeafPrincipal {
			guard
				try InvitationMigration.derivedEd25519Public(
					from: recvLeaf.signingKey)
					== recvLeaf.signatureKey,
				try InvitationMigration.derivedEd25519Public(
					from: recvLeaf.pqSigningKey) == recvLeaf.pqSignatureKey
			else {
				throw TwoMLSError.archiveInvalid
			}
		}

		// KP′ (bootstrap) and the peer's published combiner KP get the same
		// decode/derive cross-checks as the identity's pair — the
		// "MLSMessage-FRAMED KeyPackage" fold included — so a mis-mapped
		// bootstrap secret fails at mint instead of opaquely at the §A.3
		// welcome open (or never, for a core-kind mint). Hoisted above the
		// `leafKeys` conversion below, which needs KP′'s already-checked
		// leaf key for the pre-A.3 initiator's recv-PQ reservation.
		let bootstrapKPSecret = try parts.bootstrapKPSecret.map { secret in
			try Self.checkBootstrapKPSecret(secret)
		}
		if let initial = parts.initialTheirKP {
			do {
				_ = try MLS.RFC9420.KeyPackage(mlsEncoded: initial.classical)
				_ = try MLS.RFC9420.KeyPackage(mlsEncoded: initial.pq)
			} catch is MLS.CodecError {
				throw TwoMLSError.archiveInvalid
			}
		}

		// Rule 1 (precedence): a supplied `parts.leafKeys` is authoritative;
		// `nil` falls back to the temporary one-time conversion from
		// today's owner-keyed parts — replaces `checkClassicalCustody`/
		// `checkPQCustody`, which this subsumes (a lookup miss within a
		// half is the exact same `.archiveInvalid` the old custody check
		// threw). Deleted once every migrator supplies per-group keys of
		// its own. Either way, the drop-at-import's EFFECTIVE `pqInflight`
		// (not `parts.pqInflight`) governs any Upd′-justified recv-PQ
		// pending entry `convertDeployedKeys` would otherwise add.
		var leafKeys: LeafKeys
		let mode: LeafKeysValidationMode
		if let migratedLeafKeys = parts.leafKeys {
			leafKeys = try nativeLeafKeys(migratedLeafKeys)
			mode = .mintSupplied
		} else {
			leafKeys = try convertDeployedKeys(
				parts: parts, sendClassical: sendClassical, sendPQ: sendPQ,
				recvClassical: recvClassical, recvPQ: recvPQ,
				bootstrapKPSecret: bootstrapKPSecret,
				pqInflight: effectivePqInflight,
				classicalProvider: classicalProvider, pqProvider: pqProvider)
			mode = .mintConverted
		}
		// A.2 step 2, continued: drop the dropped round's now-orphaned
		// recv-PQ pending entry, UNLESS it is the rule-7 catch-up key step
		// 7's self-drive needs (`t == auth.mine.current` and the recv-PQ
		// leaf still lags).
		if let droppedRekeyTarget {
			let mineCurrent = parts.auth.mine.history.last
			let recvPQLags: Bool = {
				guard let recvPQ, let mineCurrent else { return false }
				guard
					let ownID = try? basicIdentifier(
						TwoMLSSession.ownLeaf(of: recvPQ).credential)
				else { return false }
				return ownID != mineCurrent
			}()
			let isRuleSevenKey = droppedRekeyTarget == mineCurrent && recvPQLags
			if !isRuleSevenKey {
				leafKeys.recvPQ.pending[droppedRekeyTarget] = nil
			}
		}

		// Rule 10 (the window), when `deployedState` carries one — shares
		// the id function and validation with `mintOwnOfferWindow`, so the
		// two calls' ids always agree given the same window (B.2 #1: same
		// array, unchanged, to both).
		var windowTargets: [(id: Data, signatureKey: MLS.SignaturePublicKey)] = []
		var ownOfferWindowRecord: OwnOfferWindowRecord?
		if let window = deployedState?.ownOffers {
			guard let recvClassical else { throw TwoMLSError.archiveInvalid }
			let (windowID, targets) = try OwnOfferWindow.validate(
				window, recvClassical: recvClassical,
				myLeafIndex: recvClassical.myLeafIndex, provider: classicalProvider)
			windowTargets = targets
			ownOfferWindowRecord = OwnOfferWindowRecord(
				id: windowID, epoch: window.epoch, groupID: window.groupID,
				senderLeafIndex: window.senderLeafIndex,
				count: UInt32(window.offers.count))
		}

		// Rule 9: `initialAppPayload` is non-empty and accepted only for a
		// pre-join initiator.
		if let initialAppPayload = parts.initialAppPayload {
			guard !initialAppPayload.isEmpty, parts.initiated, parts.recvGroup == nil
			else {
				throw TwoMLSError.archiveInvalid
			}
		}

		// Today this mostly re-checks `convertDeployedKeys`'s own conversion
		// (`.mintConverted`); it becomes load-bearing against genuinely
		// adversarial input for a caller-supplied `leafKeys`
		// (`.mintSupplied`).
		try TwoMLSSession.validateLeafKeys(
			leafKeys,
			sendGroup: APQGroup(
				classical: sendClassical, pq: sendPQ,
				pskStore: MLS.Combiner.PSKStore(),
				codepoints: .deployed),
			recvGroup: recvClassical.map {
				APQGroup(
					classical: $0, pq: recvPQ,
					pskStore: MLS.Combiner.PSKStore(),
					codepoints: .deployed)
			},
			identity: try identityArchive.restore(),
			bootstrapKPSecret: try bootstrapKPSecret.map {
				(
					leafSecretKey: try MLS.HpkeSecretKey($0.leafSecretKey),
					initSecretKey: try MLS.HpkeSecretKey($0.initSecretKey),
					keyPackage: try MLS.RFC9420.KeyPackage(
						mlsEncoded: $0.keyPackage)
				)
			},
			stagedUpdates: parts.stagedUpdates.map { ($0.digest, $0.message) },
			pendingProposal: parts.pendingProposal.map {
				($0.proposing, $0.message, $0.hash)
			},
			pqInflight: try effectivePqInflight.map(Self.nativePQInflight),
			rotationCandidate: try parts.rotationCandidate.map {
				RotationCandidate(
					clientID: $0.clientID,
					signingKey: try MLS.SignatureSecretKey($0.signingKey),
					signatureKey: MLS.SignaturePublicKey($0.signatureKey),
					proposedAtRecvEpoch: $0.proposedAtRecvEpoch)
			},
			recvLeafPrincipal: try parts.recvLeafPrincipal.map {
				RecvLeafPrincipal(
					clientID: $0.clientID,
					signingKey: try MLS.SignatureSecretKey($0.signingKey),
					signatureKey: MLS.SignaturePublicKey($0.signatureKey),
					pqSigningKey: try MLS.SignatureSecretKey($0.pqSigningKey),
					pqSignatureKey: MLS.SignaturePublicKey($0.pqSignatureKey))
			},
			auth: AuthCore(
				mine: PartySequence(
					history: parts.auth.mine.history,
					authorizedNext: parts.auth.mine.authorizedNext,
					pinned: parts.auth.mine.pinned),
				theirs: PartySequence(
					history: parts.auth.theirs.history,
					authorizedNext: parts.auth.theirs.authorizedNext,
					pinned: parts.auth.theirs.pinned)),
			mode: mode,
			noCustody: deployedState?.noCustody ?? [],
			windowTargets: windowTargets,
			classicalProvider: classicalProvider, pqProvider: pqProvider)

		let noCustodyRoles = deployedState?.noCustody ?? []
		let candidateCarry = DeployedCarryArchive(
			ownOfferWindow: ownOfferWindowRecord,
			pqWedged: deployedState?.pqWedged?.rawValue,
			noCustody: noCustodyRoles.isEmpty
				? nil : noCustodyRoles.map { $0.rawValue }.sorted())
		let deployedCarry = candidateCarry.isEmpty ? nil : candidateCarry

		let body = SessionArchive(
			version: sessionArchiveVersion,
			classicalSuite: TwoMLSSuite.classical.id,
			pqSuite: TwoMLSSuite.pq.id,
			kind: kind,
			stateSeq: parts.stateSeq,
			sendPQEpoch: sendPQ?.context.epoch,
			recvPQEpoch: recvPQ?.context.epoch,
			sendClassicalGroupID: sendClassical.context.groupID,
			recvClassicalGroupID: recvClassical?.context.groupID,
			identity: identityArchive,
			auth: AuthCore(
				mine: PartySequence(
					history: parts.auth.mine.history,
					authorizedNext: parts.auth.mine.authorizedNext,
					pinned: parts.auth.mine.pinned),
				theirs: PartySequence(
					history: parts.auth.theirs.history,
					authorizedNext: parts.auth.theirs.authorizedNext,
					pinned: parts.auth.theirs.pinned)),
			sendGroup: GroupEntry(
				classical: try reSnapshot(sendClassical),
				pq: kind == .checkpoint ? try sendPQ.map(reSnapshot) : nil),
			recvGroup: try recvClassical.map {
				GroupEntry(
					classical: try reSnapshot($0),
					pq: kind == .checkpoint ? try recvPQ.map(reSnapshot) : nil)
			},
			currentStaple: parts.currentStaple,
			pendingProposal: parts.pendingProposal.map {
				PendingProposalArchive(
					proposing: $0.proposing, message: $0.message, hash: $0.hash)
			},
			joinedWelcomeDigest: parts.joinedWelcomeDigest,
			initiated: parts.initiated,
			bootstrapKPSecret: bootstrapKPSecret.map {
				BootstrapKPSecretArchive(
					leafSecretKey: $0.leafSecretKey,
					initSecretKey: $0.initSecretKey, keyPackage: $0.keyPackage)
			},
			expectedBootstrapKPCommitment: parts.expectedBootstrapKPCommitment,
			pqTurnMine: parts.pqTurnMine,
			owedBind: parts.owedBind.map {
				OwedBind(
					pqCommitMessage: $0.pqCommitMessage, tEpoch: $0.tEpoch,
					pqEpoch: $0.pqEpoch)
			},
			pqInflight: effectivePqInflight.map(PQInflightArchive.init),
			pendingSideBand: effectivePendingSideBand,
			peerAppliedSendEpoch: parts.peerAppliedSendEpoch,
			lastCrossInjected: parts.lastCrossInjected,
			lastCrossInjectedPQ: parts.lastCrossInjectedPQ,
			lastSendPQExported: parts.lastSendPQExported,
			offeredProposal: parts.offeredProposal.map {
				DigestedProposalArchive(
					digest: $0.digest, proposing: $0.proposing,
					message: $0.message)
			},
			queuedProposal: parts.queuedProposal.map {
				DigestedProposalArchive(
					digest: $0.digest, proposing: $0.proposing,
					message: $0.message)
			},
			stagedUpdates: parts.stagedUpdates.map {
				StagedUpdateArchive(digest: $0.digest, message: $0.message)
			},
			sendCrossPSKLedger: ArchiveIntegerKeyedMap(
				parts.sendCrossPSKLedger.mapValues {
					ExportedPskArchive(
						componentID: $0.componentID, pskID: $0.pskID,
						psk: $0.psk)
				}),
			rotationCandidate: parts.rotationCandidate.map {
				RotationCandidateArchive(
					clientID: $0.clientID, signingKey: $0.signingKey,
					signatureKey: $0.signatureKey,
					proposedAtRecvEpoch: $0.proposedAtRecvEpoch)
			},
			spawnToken: parts.spawnToken,
			listenRendezvous: ArchiveIntegerKeyedMap(parts.listenRendezvous),
			recvHeaderKeys: ArchiveIntegerKeyedMap(parts.recvHeaderKeys),
			recvHeaderKeysPQ: ArchiveIntegerKeyedMap(parts.recvHeaderKeysPQ),
			initialTheirKP: parts.initialTheirKP.map {
				CombinerKeyPackageArchive(classical: $0.classical, pq: $0.pq)
			},
			sendAttachmentLedger: ArchiveIntegerKeyedMap(
				parts.sendAttachmentLedger.mapValues {
					SecretField(wrappedValue: $0)
				}),
			recvAttachmentLedger: ArchiveIntegerKeyedMap(
				parts.recvAttachmentLedger.mapValues {
					SecretField(wrappedValue: $0)
				}),
			owesEstablishmentEnvelope: parts.owesEstablishmentEnvelope,
			recvLeafPrincipal: parts.recvLeafPrincipal.map {
				RecvLeafPrincipalArchive(
					clientID: $0.clientID, signingKey: $0.signingKey,
					signatureKey: $0.signatureKey,
					pqSigningKey: $0.pqSigningKey,
					pqSignatureKey: $0.pqSignatureKey)
			},
			leafKeys: LeafKeysArchive(leafKeys, kind: kind),
			sendPQKeysFingerprint: leafKeys.sendPQ.fingerprint,
			recvPQKeysFingerprint: leafKeys.recvPQ.fingerprint,
			deployedCarry: deployedCarry,
			initialAppPayload: parts.initialAppPayload)
		// Decode invariants (the 32-byte rules on the commitment, the three
		// windows and both attachment ledgers) run kind-independently — same
		// reasoning as the derive-checks above; the checkpoint's trial
		// restore would re-run them.
		try TwoMLSSession.validateDecodeInvariants(body)
		let archive: SecretArchive
		do {
			archive = try SecretArchive(encoding: body)
			if kind == .checkpoint {
				// The trial restore absorbs any consuming export into its own
				// throwaway group copies; the archive itself is only decoded.
				_ = try TwoMLSSession.restore(
					core: nil, checkpoint: archive,
					classicalProvider: classicalProvider, pqProvider: pqProvider
				)
			}
		} catch let error as TwoMLSError {
			throw error
		} catch {
			// An `EncodingError` (an integer-keyed map key past `Int.max` —
			// these keys come straight from a migrator's raw dictionaries),
			// or any profile-internal error the trial restore leaks
			// (`restore` folds only its own decode/`ExporterTree` errors) —
			// all folded to the one uniform mint failure.
			throw TwoMLSError.archiveInvalid
		}
		return archive
	}

	/// Mint the own-offer window into its OWN blob — never into the session
	/// archives (`MigratedDeployedState.ownOffers`, consumed here rather
	/// than by `mintArchive`, is what a migrator that also wants the record
	/// on `mintArchive` passes to BOTH calls unchanged, per B.2 #1). Runs
	/// the SAME `OwnOfferWindow.validate` (rule 10) `mintArchive` runs when
	/// `deployedState.ownOffers` is present, so the two calls' ids always
	/// agree given the same window.
	///
	/// - Throws: `TwoMLSError.archiveInvalid` if `parts.recvGroup` is `nil`,
	///   or if `window` fails rule 10 (a hoisted field disagreeing with the
	///   restored recv-classical group, an out-of-range count, a non-32-byte
	///   or duplicate ref, a non-`.update` proposal, a non-32-byte secret, a
	///   duplicate encryption key, or a sampled offer the swift-mls
	///   migration SPI itself rejects).
	public static func mintOwnOfferWindow(
		_ window: MigratedOwnOfferWindow, parts: MigratedSession,
		classicalProvider: any MLS.CipherSuiteProvider
	) throws -> MintedOwnOfferWindow {
		guard let recvGroupParts = parts.recvGroup else { throw TwoMLSError.archiveInvalid }
		let recvClassical = try restoredGroup(recvGroupParts.classical, classicalProvider)
		let (id, _) = try OwnOfferWindow.validate(
			window, recvClassical: recvClassical,
			myLeafIndex: recvClassical.myLeafIndex,
			provider: classicalProvider)
		let sorted = try OwnOfferWindow.canonicalOrder(window.offers)
		let body = try OwnOfferWindowArchive(
			epoch: window.epoch, groupID: window.groupID,
			senderLeafIndex: window.senderLeafIndex, sorted: sorted)
		let archive: SecretArchive
		do {
			archive = try SecretArchive(encoding: body)
		} catch {
			throw TwoMLSError.archiveInvalid
		}
		return MintedOwnOfferWindow(archive: archive, id: id)
	}

	/// `Group.restore` + `makeSnapshot()` per half — the only public path
	/// from snapshot bytes to a `Group.Snapshot` value (`Snapshot`'s members
	/// are internal to swift-mls). Every failure is a part-shaped failure
	/// (an archive that isn't a snapshot, a group-context/suite mismatch, a
	/// missing current-epoch exporter tree), folded to the one uniform
	/// `archiveInvalid` rather than leaking a profile-internal error type.
	private static func restoredGroup(
		_ snapshot: SecretArchive, _ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.RFC9420.Group {
		do {
			return try MLS.RFC9420.Group.restore(from: snapshot, provider)
		} catch {
			throw TwoMLSError.archiveInvalid
		}
	}

	private static func reSnapshot(_ group: MLS.RFC9420.Group) throws
		-> MLS.RFC9420.Group.Snapshot
	{
		do {
			return try group.makeSnapshot()
		} catch {
			throw TwoMLSError.archiveInvalid
		}
	}

	/// KP′'s cross-checks: the `KeyPackage` MLS-decodes (bare, not
	/// MLSMessage-framed) and both HPKE secrets derive to its
	/// `encryptionKey`/`initKey` — the identity pair's checks, applied to the
	/// bootstrap secret. KP′ is the PQ bootstrap key package (§A.3 founds
	/// Group_B.pq out of band), so both secrets are ML-KEM
	/// `integrityCheckedRepresentation`s and the derive helper is the PQ one.
	private static func checkBootstrapKPSecret(
		_ secret: MigratedBootstrapKPSecret
	) throws -> MigratedBootstrapKPSecret {
		let keyPackage: MLS.RFC9420.KeyPackage
		do {
			keyPackage = try MLS.RFC9420.KeyPackage(mlsEncoded: secret.keyPackage)
		} catch is MLS.CodecError {
			throw TwoMLSError.archiveInvalid
		}
		guard
			try InvitationMigration.pqPublic(from: secret.leafSecretKey)
				== keyPackage.leafNode.encryptionKey.data,
			try InvitationMigration.pqPublic(from: secret.initSecretKey)
				== keyPackage.initKey.data
		else {
			throw TwoMLSError.archiveInvalid
		}
		return secret
	}

	/// Rule 1's authoritative path (step 3): `migrated`, derive-checked and
	/// converted 1:1 to the native `LeafKeys` shape — no lookup, no search,
	/// unlike `convertDeployedKeys` below (which this supersedes once every
	/// migrator supplies real per-group keys of its own).
	private static func nativeLeafKeys(_ migrated: MigratedLeafKeys) throws -> LeafKeys {
		func convertKey(_ key: MigratedLeafKey) throws -> LeafKey {
			guard key.signingKey.byteCount == 32, key.signatureKey.count == 32,
				try InvitationMigration.derivedEd25519Public(from: key.signingKey)
					== key.signatureKey
			else {
				throw TwoMLSError.archiveInvalid
			}
			return LeafKey(
				signingKey: try MLS.SignatureSecretKey(key.signingKey),
				signatureKey: MLS.SignaturePublicKey(key.signatureKey))
		}
		func convertSet(_ groupKeys: MigratedGroupKeys) throws -> GroupKeySet {
			var pending: [Data: LeafKey] = [:]
			for entry in groupKeys.pending {
				guard !entry.target.isEmpty, pending[entry.target] == nil else {
					throw TwoMLSError.archiveInvalid
				}
				pending[entry.target] = try convertKey(entry.key)
			}
			return GroupKeySet(
				current: try groupKeys.current.map(convertKey), pending: pending)
		}
		return LeafKeys(
			sendClassical: try convertSet(migrated.sendClassical),
			recvClassical: try convertSet(migrated.recvClassical),
			sendPQ: try convertSet(migrated.sendPQ),
			recvPQ: try convertSet(migrated.recvPQ))
	}

	/// A.2 step 2's lenient decode: does `updMessage` at least parse to an
	/// Update proposal, WITHOUT verifying its framing signature or epoch
	/// (the Upd′ may be exactly the mis-signed one being dropped — that's
	/// why this never calls `verifying`)? Returns the target id it names,
	/// or `nil` on any decode failure.
	private static func decodedUpdateTargetIgnoringSignature(_ updMessage: Data) -> Data? {
		guard
			case .publicMessage(let updatePub) = try? MLS.RFC9420.Message(
				mlsEncoded: updMessage),
			case .proposal(let proposal) = updatePub.content.content,
			case .update(let leafNode) = proposal,
			let id = try? basicIdentifier(leafNode.credential)
		else { return nil }
		return id
	}

	/// The temporary one-time conversion from today's owner-keyed migrated
	/// parts to per-group `leafKeys` — deleted once the migration input
	/// carries per-group keys of its own. Every
	/// lookup miss (a leaf presenting a key none of a half's slots holds) is
	/// `.archiveInvalid` — the exact failure `checkClassicalCustody`/
	/// `checkPQCustody` used to throw for the same condition.
	private static func convertDeployedKeys(
		parts: MigratedSession,
		sendClassical: MLS.RFC9420.Group, sendPQ: MLS.RFC9420.Group?,
		recvClassical: MLS.RFC9420.Group?, recvPQ: MLS.RFC9420.Group?,
		bootstrapKPSecret: MigratedBootstrapKPSecret?,
		// A.2 step 2 (drop at import): the effective PQ inflight, AFTER an
		// unverifiable parked §A.5 Upd′ has already been dropped — never
		// `parts.pqInflight` directly, so a dropped round's target never
		// gets a pending entry from this arm either.
		pqInflight: MigratedPQInflight?,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> LeafKeys {
		// Classical slots: identity, the candidate?, the retained recv-leaf
		// custody's classical pair?.
		func lookupClassical(_ signatureKey: Data) throws -> LeafKey {
			if signatureKey == parts.identity.signatureKey {
				return LeafKey(
					signingKey: try MLS.SignatureSecretKey(
						parts.identity.signingKey),
					signatureKey: MLS.SignaturePublicKey(signatureKey))
			}
			if let candidate = parts.rotationCandidate,
				candidate.signatureKey == signatureKey
			{
				return LeafKey(
					signingKey: try MLS.SignatureSecretKey(
						candidate.signingKey),
					signatureKey: MLS.SignaturePublicKey(signatureKey))
			}
			if let recvLeaf = parts.recvLeafPrincipal,
				recvLeaf.signatureKey == signatureKey
			{
				return LeafKey(
					signingKey: try MLS.SignatureSecretKey(recvLeaf.signingKey),
					signatureKey: MLS.SignaturePublicKey(signatureKey))
			}
			throw TwoMLSError.archiveInvalid
		}
		// PQ slots: identity's own PQ pair, the retained recv-leaf
		// custody's PQ pair? — no candidate arm (rotation only ever touches
		// classical leaves) and no classical arm (D1, independent per-half
		// keys).
		func lookupPQ(_ signatureKey: Data) throws -> LeafKey {
			if signatureKey == parts.identity.pqSignatureKey {
				return LeafKey(
					signingKey: try MLS.SignatureSecretKey(
						parts.identity.pqSigningKey),
					signatureKey: MLS.SignaturePublicKey(signatureKey))
			}
			if let recvLeaf = parts.recvLeafPrincipal,
				recvLeaf.pqSignatureKey == signatureKey
			{
				return LeafKey(
					signingKey: try MLS.SignatureSecretKey(
						recvLeaf.pqSigningKey),
					signatureKey: MLS.SignaturePublicKey(signatureKey))
			}
			throw TwoMLSError.archiveInvalid
		}

		// A.7 (step 3, generalized catch-up): "lags" means the leaf presents
		// an id other than `mineCurrent`. This conversion can only supply a
		// rule-7 `pending[mineCurrent]` entry when it actually holds a key
		// for `mineCurrent` — the rotation candidate's, when outstanding, or
		// `identity`'s own, when `identity.clientID == mineCurrent` (the
		// born-dedicated D case, or any non-rotated session). A lag this
		// conversion cannot explain either way fails `validateLeafKeys`'s
		// check 7 at mint, same as before — an inherent limit of this
		// temporary owner-keyed conversion, not a new gap.
		let mineCurrent = parts.auth.mine.history.last

		let sendOwnLeaf = try TwoMLSSession.ownLeaf(of: sendClassical)
		let sendOwnID = try basicIdentifier(sendOwnLeaf.credential)
		var sendClassicalSet = GroupKeySet(
			current: try lookupClassical(sendOwnLeaf.signatureKey.data))
		var sendHasCandidateEntry = false
		if let candidate = parts.rotationCandidate {
			let sendPresentsCandidate = sendOwnID == candidate.clientID
			if !sendPresentsCandidate {
				sendClassicalSet.pending[candidate.clientID] = try lookupClassical(
					candidate.signatureKey)
				sendHasCandidateEntry = true
			}
		}
		// (b′) rule 4, generalized: a lagging SEND leaf under the identity's
		// own canonical principal, when the candidate arm above doesn't
		// already cover it — new relative to the pre-A.7 conversion, which
		// never gave the send side a rule-4 arm at all.
		if let mineCurrent, parts.identity.clientID == mineCurrent,
			sendOwnID != mineCurrent,
			!sendHasCandidateEntry
		{
			sendClassicalSet.pending[mineCurrent] = try lookupClassical(
				parts.identity.signatureKey)
		}

		var recvClassicalSet: GroupKeySet
		if let recvClassical {
			let recvOwnLeaf = try TwoMLSSession.ownLeaf(of: recvClassical)
			let recvOwnID = try basicIdentifier(recvOwnLeaf.credential)
			recvClassicalSet = GroupKeySet(
				current: try lookupClassical(recvOwnLeaf.signatureKey.data))
			// (a) the candidate, while it is still outstanding (the SAME
			// predicate check 6 and post-apply retention use — canonical-
			// ness via `auth.mine.history`, not a tree-presentation guess).
			if let candidate = parts.rotationCandidate,
				isRotationCandidateOutstanding(
					candidate.clientID, mineHistory: parts.auth.mine.history)
			{
				recvClassicalSet.pending[candidate.clientID] = try lookupClassical(
					candidate.signatureKey)
			}
			// (b) rule 4, generalized (A.7): a lagging RECV leaf under the
			// identity's own canonical principal — subsumes the
			// born-dedicated-only case (`recvLeafPrincipal` stays an unread
			// record until step 5).
			if let mineCurrent, parts.identity.clientID == mineCurrent,
				recvOwnID != mineCurrent
			{
				recvClassicalSet.pending[mineCurrent] =
					try lookupClassical(
						parts.identity.signatureKey)
			}
			// (c) every current-epoch own staged/pending Update naming a
			// leaf key that isn't `current` yet.
			var ownProposals = parts.stagedUpdates.map { $0.message }
			if let pendingProposal = parts.pendingProposal {
				ownProposals.append(pendingProposal.message)
			}
			for message in ownProposals {
				guard
					let target = try? TwoMLSSession.decodedUpdateTarget(
						message, against: recvClassical,
						provider: classicalProvider)
				else { continue }
				guard target.signatureKey != recvClassicalSet.current?.signatureKey,
					recvClassicalSet.pending[target.id] == nil
				else { continue }
				recvClassicalSet.pending[target.id] = try lookupClassical(
					target.signatureKey.data)
			}
		} else {
			// The pre-join initiator's reservation.
			recvClassicalSet = GroupKeySet(
				current: try lookupClassical(parts.identity.signatureKey))
		}

		let sendPQSet: GroupKeySet
		if let sendPQ {
			sendPQSet = GroupKeySet(
				current: try lookupPQ(
					try TwoMLSSession.ownLeaf(of: sendPQ).signatureKey.data)
			)
		} else {
			// The pre-A.3 acceptor's reservation.
			sendPQSet = GroupKeySet(
				current: try lookupPQ(parts.identity.pqSignatureKey))
		}

		var recvPQSet: GroupKeySet
		if let recvPQ {
			let recvPQOwnLeaf = try TwoMLSSession.ownLeaf(of: recvPQ)
			recvPQSet = GroupKeySet(
				current: try lookupPQ(recvPQOwnLeaf.signatureKey.data))
			if case .rekeyInitiated(let updMessage) = pqInflight,
				let target = try? TwoMLSSession.decodedUpdateTarget(
					updMessage, against: recvPQ, provider: pqProvider),
				target.signatureKey != recvPQSet.current?.signatureKey
			{
				recvPQSet.pending[target.id] = try lookupPQ(
					target.signatureKey.data)
			}
		} else if let bootstrapKPSecret {
			// The pre-A.3 initiator's reservation: KP′'s leaf key, looked up
			// in the PQ slots (it is signed under the founder identity's
			// own PQ key, D1's per-half-but-shared-within-a-half model).
			let kpLeaf = try MLS.RFC9420.KeyPackage(
				mlsEncoded: bootstrapKPSecret.keyPackage
			)
			.leafNode
			recvPQSet = GroupKeySet(current: try lookupPQ(kpLeaf.signatureKey.data))
		} else {
			recvPQSet = GroupKeySet(
				current: try lookupPQ(parts.identity.pqSignatureKey))
		}

		return LeafKeys(
			sendClassical: sendClassicalSet, recvClassical: recvClassicalSet,
			sendPQ: sendPQSet, recvPQ: recvPQSet)
	}

	/// `MigratedPQInflight` → native `PQInflight` — the payload shapes are
	/// identical; this only exists because `validateLeafKeys` takes the
	/// native type (it is shared with the live restore path).
	@available(iOS 26, macOS 26, *)
	private static func nativePQInflight(_ migrated: MigratedPQInflight) throws -> PQInflight {
		switch migrated {
		case .bootstrapInitiated: return .bootstrapInitiated
		case .bootstrapResponded: return .bootstrapResponded
		case .initiating(let secretKey, let ek):
			return .initiating(
				PQEphemeral(secretKey: try MLS.HpkeSecretKey(secretKey), ek: ek))
		case .responding(let secret, let wireCT):
			return .responding(secret: secret, wireCT: wireCT)
		case .rekeyInitiated(let updMessage):
			return .rekeyInitiated(updMessage: updMessage)
		case .rekeyResponded: return .rekeyResponded
		}
	}
}

extension PQInflightArchive {
	/// Maps the migrated PQ-inflight parts onto the archive enum — the
	/// mirror-image of `PQInflightArchive.init(_ live:)`'s payload lifting.
	@available(iOS 26, macOS 26, *)
	init(_ migrated: MigratedPQInflight) {
		switch migrated {
		case .bootstrapInitiated: self = .bootstrapInitiated
		case .bootstrapResponded: self = .bootstrapResponded
		case .initiating(let secretKey, let ek):
			self = .initiating(PQEphemeralArchive(secretKey: secretKey, ek: ek))
		case .responding(let secret, let wireCT):
			self = .responding(PQRespondingArchive(secret: secret, wireCT: wireCT))
		case .rekeyInitiated(let updMessage):
			self = .rekeyInitiated(updMessage: updMessage)
		case .rekeyResponded: self = .rekeyResponded
		}
	}
}
