import Crypto
import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import SecretBytes

// MARK: - Session archive
//
// The wire format is a single Codable body (no separate cleartext header —
// version/suite/kind ride as the body's own leading fields, validated by
// `restore` after the app's own `.open`), turned into a `SecretArchive` via
// `SecretArchive(encoding:)`. The library never seals: it hands the app an
// unsealed, zeroizing archive, and the app seals with its own key
// (swift-mls's return-to-app-to-save idiom). Restore/reconcile lives in
// `TwoMLSSession+Restore.swift`.

/// Which of the two archive kinds a `SessionArchive` body encodes. Checkpoint
/// carries both PQ trees (faithful, more expensive); Core omits them
/// (cheap) and leans on a paired Checkpoint to restore the PQ halves. Public:
/// it rides on every `StateUpdate` the app receives, to file the archive
/// under the right slot.
public enum BlobKind: UInt8, Sendable, Equatable, Codable {
	case core = 0
	case checkpoint = 1
}

/// A CBOR **integer**-keyed map for `[UInt64: Value]` session fields — a
/// plain `Dictionary<UInt64, Value>` encodes through `Codable` as an unkeyed
/// array of alternating key/value elements (its key type isn't the stdlib's
/// `String`/`Int` fast path), which is not what a stable archive wants.
/// Mirrors swift-mls's own (module-internal) `IntegerKeyedMap`.
struct ArchiveIntegerKeyedMap<Value> {
	var entries: [UInt64: Value]

	init(_ entries: [UInt64: Value]) { self.entries = entries }

	struct Key: ArchiveIntegerCodingKey {
		let value: UInt64
		init(_ value: UInt64) { self.value = value }
		var intValue: Int? { Int(exactly: value) }
		var stringValue: String { String(value) }
		init?(intValue: Int) {
			guard let value = UInt64(exactly: intValue) else { return nil }
			self.value = value
		}
		init?(stringValue: String) { nil }
	}
}

extension ArchiveIntegerKeyedMap: Encodable where Value: Encodable {
	func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: Key.self)
		for (key, value) in entries {
			// A key past `Int.max` would encode as a *text* key (its
			// `intValue` is nil) and silently vanish as an integer entry on
			// decode — mirrors swift-mls's own `IntegerKeyedMap` guard.
			guard Int(exactly: key) != nil else {
				throw EncodingError.invalidValue(
					key,
					EncodingError.Context(
						codingPath: encoder.codingPath,
						debugDescription:
							"ArchiveIntegerKeyedMap key \(key) exceeds Int.max"
					))
			}
			try container.encode(value, forKey: Key(key))
		}
	}
}

extension ArchiveIntegerKeyedMap: Decodable where Value: Decodable {
	init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: Key.self)
		var entries: [UInt64: Value] = [:]
		for key in container.allKeys {
			entries[key.value] = try container.decode(Value.self, forKey: key)
		}
		self.entries = entries
	}
}

extension ArchiveIntegerKeyedMap: Sendable where Value: Sendable {}
extension ArchiveIntegerKeyedMap: Equatable where Value: Equatable {}

// MARK: - Field archive types

/// `TwoMLSIdentity`'s archived form: the leaf HPKE secrets and the two
/// independent per-half Ed25519 signing keys (`signingKey` classical,
/// `pqSigningKey` PQ — both NON-optional, mirroring the live identity) ride
/// `.data` into `@SecretField`s (the keys themselves aren't
/// `SecretRestorable`); the two `KeyPackage`s ride their own MLS wire
/// encoding.
///
/// The two INIT secrets are archived **conditionally**, gated by
/// `includeInitSecrets` at encode time (not inferred from whether they
/// happen to be `nil`):
///  - A **session** identity uses `includeInitSecrets: recvGroup == nil` —
///    an explicit SEMANTIC condition (pre-establishment), not "infer from
///    runtime nil-ness" of the secrets themselves. For an in-flight
///    INITIATOR (post-`initiate`, before it joins its receive group —
///    `recvGroup == nil`) the classical init secret is still live, kept
///    until `joinGroupBIfNeeded`; the archive now carries it, so a session
///    archived mid-establishment can restore and still complete — the
///    restored initiator's `pendingOutbound()`/`Invitation.openInitial`/
///    `receive`/`processIncoming` round joins Group_B exactly as the live
///    path would have. For an ESTABLISHED session (`recvGroup` set) the flag
///    omits them, which is moot anyway — both are already spent
///    (`TwoMLSIdentity.clearingInitSecrets`). Low blast radius either way:
///    the initiator's identity is per-session, minted fresh, and never
///    published.
///  - An **invitation** identity DOES carry them, when still un-consumed:
///    a published `Invitation` is a durable receiving capability, and its
///    published key package's init secrets are exactly what a later
///    `receive` needs to open a welcome (`TwoMLSIdentity.classicalJoin-
///    Credentials`/`pqJoinCredentials`) — dropping them on restore made a
///    restored invitation permanently unable to `receive`. A spent
///    single-use invitation still never re-archives them: `Invitation`
///    nils its whole `identity` on consume, so there is nothing left to
///    pass `includeInitSecrets: true` over.
/// `SecretField<SecretBytes>?`, not `@SecretField var … : SecretBytes?`:
/// the wrapper's `Value` must be `SecretRestorable`, which `Optional
/// <SecretBytes>` is not (mirrors swift-mls's own `Snapshot.headSecret`
/// idiom).
struct IdentityArchive: Codable, Sendable {
	var clientID: Data
	@SecretField var signingKey: SecretBytes
	var signatureKey: Data
	@SecretField var pqSigningKey: SecretBytes
	var pqSignatureKey: Data
	@SecretField var classicalLeafSecretKey: SecretBytes
	var classicalInitSecretKey: SecretField<SecretBytes>?
	@SecretField var pqLeafSecretKey: SecretBytes
	var pqInitSecretKey: SecretField<SecretBytes>?
	var classicalKeyPackage: Data
	var pqKeyPackage: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case clientID = 0
		case signingKey = 1
		case signatureKey = 2
		case classicalLeafSecretKey = 3
		case classicalInitSecretKey = 4
		case pqLeafSecretKey = 5
		case pqInitSecretKey = 6
		case classicalKeyPackage = 7
		case pqKeyPackage = 8
		case pqSigningKey = 9
		case pqSignatureKey = 10
	}
}

/// Gated because this bridges the plain Codable wire struct to the port's
/// own live `TwoMLSIdentity`, which is itself `@available(iOS 26, macOS 26, *)`
/// (it's built on the ML-KEM-768 provider, which resolves to CryptoKit on
/// Apple — macOS 26/iOS 26+ — and to swift-crypto's BoringSSL off-Apple, where
/// the trailing `*` leaves the type unrestricted). The wire structs stay
/// ungated so the archive's byte shape needs no OS floor to describe or decode.
@available(iOS 26, macOS 26, *)
extension IdentityArchive {
	/// `includeInitSecrets` is an explicit control, never inferred from
	/// whether `identity`'s init secrets happen to be `nil` at the call
	/// site — see the type doc for why. Every caller states its condition:
	/// the session path passes `recvGroup == nil` (carry only for a
	/// pre-establishment initiator), the invitation path passes `true`.
	init(_ identity: TwoMLSIdentity, includeInitSecrets: Bool) throws {
		self.init(
			clientID: identity.clientID,
			signingKey: identity.signingKey.data,
			signatureKey: identity.signatureKey.data,
			pqSigningKey: identity.pqSigningKey.data,
			pqSignatureKey: identity.pqSignatureKey.data,
			classicalLeafSecretKey: identity.classicalLeafSecretKey.data,
			classicalInitSecretKey: includeInitSecrets
				? identity.classicalInitSecretKey.map {
					SecretField(wrappedValue: $0.data)
				}
				: nil,
			pqLeafSecretKey: identity.pqLeafSecretKey.data,
			pqInitSecretKey: includeInitSecrets
				? identity.pqInitSecretKey.map {
					SecretField(wrappedValue: $0.data)
				}
				: nil,
			classicalKeyPackage: try identity.keyPackage.classical.mlsEncoded(),
			pqKeyPackage: try identity.keyPackage.pq.mlsEncoded())
	}

	/// Two independent derive-checks (classical, then PQ — each also
	/// checks that its half's archived `KeyPackage` leaf actually presents the
	/// derived key, so a corrupt-but-authenticated archive fails here at
	/// restore rather than surfacing later as `.credentialUnknown`).
	func restore() throws -> TwoMLSIdentity {
		let derivedSignatureKey = try derivedSignaturePublicKey(from: signingKey)
		guard derivedSignatureKey.data == signatureKey else {
			throw TwoMLSError.archiveInvalid
		}
		let derivedPQSignatureKey = try derivedSignaturePublicKey(from: pqSigningKey)
		guard derivedPQSignatureKey.data == pqSignatureKey else {
			throw TwoMLSError.archiveInvalid
		}
		let classicalKeyPackageDecoded = try MLS.RFC9420.KeyPackage(
			mlsEncoded: classicalKeyPackage)
		let pqKeyPackageDecoded = try MLS.RFC9420.KeyPackage(mlsEncoded: pqKeyPackage)
		guard classicalKeyPackageDecoded.leafNode.signatureKey.data == signatureKey,
			pqKeyPackageDecoded.leafNode.signatureKey.data == pqSignatureKey
		else {
			throw TwoMLSError.archiveInvalid
		}
		return TwoMLSIdentity(
			clientID: clientID,
			signingKey: try MLS.SignatureSecretKey(signingKey),
			signatureKey: derivedSignatureKey,
			pqSigningKey: try MLS.SignatureSecretKey(pqSigningKey),
			pqSignatureKey: derivedPQSignatureKey,
			classicalLeafSecretKey: try MLS.HpkeSecretKey(classicalLeafSecretKey),
			classicalInitSecretKey: try classicalInitSecretKey.map {
				try MLS.HpkeSecretKey($0.wrappedValue)
			},
			pqLeafSecretKey: try MLS.HpkeSecretKey(pqLeafSecretKey),
			pqInitSecretKey: try pqInitSecretKey.map {
				try MLS.HpkeSecretKey($0.wrappedValue)
			},
			keyPackage: CombinerKeyPackage(
				classical: classicalKeyPackageDecoded, pq: pqKeyPackageDecoded))
	}
}

/// One directional `APQGroup`'s archived halves. `pq` is `nil` for a
/// deferred (Group_B pre-A.3) half, and always `nil` in a Core-kind body
/// (which omits PQ trees regardless of whether a half has one) — the two
/// `nil` cases are disambiguated at reconcile time by kind, not by this
/// type. The combiner PSK store rides neither: it is ephemeral (a live
/// `apq_psk` is already folded into the epoch secrets that referenced it),
/// matching swift-mls's own `CombinerGroup.restore`.
struct GroupEntry: Codable, Sendable, Equatable {
	var classical: MLS.RFC9420.Group.Snapshot
	var pq: MLS.RFC9420.Group.Snapshot?

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case classical = 0
		case pq = 1
	}
}

// Gated because it bridges to a live iOS 26 port type — see IdentityArchive in SessionArchive.swift.
@available(iOS 26, macOS 26, *)
extension APQGroup {
	/// `Core` omits every PQ tree (there is no combiner `export_classical()`
	/// for a per-half snapshot — this is the port's own wrinkle);
	/// `Checkpoint` includes `pq` whenever this half has one.
	func makeGroupEntry(kind: BlobKind) throws -> GroupEntry {
		GroupEntry(
			classical: try classical.makeSnapshot(),
			pq: kind == .checkpoint ? try pq?.makeSnapshot() : nil)
	}
}

/// `bootstrapKPSecret`'s archived form — KP′'s leaf/init HPKE secrets plus
/// the `KeyPackage` itself (wire-encoded). The public KP′ is never archived
/// separately; it derives from `keyPackage` on restore
/// (`TwoMLSSession.bootstrapKPBytes()`), same as live.
struct BootstrapKPSecretArchive: Codable, Sendable {
	@SecretField var leafSecretKey: SecretBytes
	@SecretField var initSecretKey: SecretBytes
	var keyPackage: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case leafSecretKey = 0
		case initSecretKey = 1
		case keyPackage = 2
	}
}

extension BootstrapKPSecretArchive {
	init(
		_ secret: (
			leafSecretKey: MLS.HpkeSecretKey, initSecretKey: MLS.HpkeSecretKey,
			keyPackage: MLS.RFC9420.KeyPackage
		)
	) throws {
		try self.init(
			leafSecretKey: secret.leafSecretKey.data,
			initSecretKey: secret.initSecretKey.data,
			keyPackage: secret.keyPackage.mlsEncoded())
	}

	func restore() throws -> (
		leafSecretKey: MLS.HpkeSecretKey, initSecretKey: MLS.HpkeSecretKey,
		keyPackage: MLS.RFC9420.KeyPackage
	) {
		(
			leafSecretKey: try MLS.HpkeSecretKey(leafSecretKey),
			initSecretKey: try MLS.HpkeSecretKey(initSecretKey),
			keyPackage: try MLS.RFC9420.KeyPackage(mlsEncoded: keyPackage)
		)
	}
}

/// `initialTheirKP`'s archived form — the peer's published
/// combiner key package, wire-encoded per half. No secret material (it's
/// the PEER's own published KP), so no `@SecretField`.
struct CombinerKeyPackageArchive: Codable, Sendable, Equatable {
	var classical: Data
	var pq: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case classical = 0
		case pq = 1
	}
}

extension CombinerKeyPackageArchive {
	init(_ keyPackage: CombinerKeyPackage) throws {
		try self.init(
			classical: keyPackage.classical.mlsEncoded(), pq: keyPackage.pq.mlsEncoded()
		)
	}

	func restore() throws -> CombinerKeyPackage {
		CombinerKeyPackage(
			classical: try MLS.RFC9420.KeyPackage(mlsEncoded: classical),
			pq: try MLS.RFC9420.KeyPackage(mlsEncoded: pq))
	}
}

/// The initiator's held §A.4 ephemeral (`PQEphemeral`), archived.
struct PQEphemeralArchive: Codable, Sendable, Equatable {
	@SecretField var secretKey: SecretBytes
	var ek: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case secretKey = 0
		case ek = 1
	}
}

/// The responder's held §A.4 `S`/parked CT (`PQInflight.responding`), archived.
struct PQRespondingArchive: Codable, Sendable, Equatable {
	@SecretField var secret: SecretBytes
	var wireCT: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case secret = 0
		case wireCT = 1
	}
}

/// `PQInflight`, archived whole — every case, including the held KEM
/// secret/`S`/parked wire CT, so a Responding or initiating round survives a
/// restore intact. Hand-written `Codable`: enums with associated values
/// carrying `@SecretField`s can't derive it (a property wrapper needs a
/// stored property to sit on, which an enum's associated value isn't).
enum PQInflightArchive: Sendable, Equatable {
	case bootstrapInitiated
	case bootstrapResponded
	case initiating(PQEphemeralArchive)
	case responding(PQRespondingArchive)
	case rekeyInitiated(updMessage: Data)
	case rekeyResponded
}

extension PQInflightArchive: Codable {
	private enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case tag = 0
		case initiating = 1
		case responding = 2
		case rekeyInitiatedMessage = 3
	}

	private enum Tag: UInt64, Codable {
		case bootstrapInitiated = 0
		case bootstrapResponded = 1
		case initiating = 2
		case responding = 3
		case rekeyInitiated = 4
		case rekeyResponded = 5
	}

	func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		switch self {
		case .bootstrapInitiated:
			try container.encode(Tag.bootstrapInitiated.rawValue, forKey: .tag)
		case .bootstrapResponded:
			try container.encode(Tag.bootstrapResponded.rawValue, forKey: .tag)
		case .initiating(let payload):
			try container.encode(Tag.initiating.rawValue, forKey: .tag)
			try container.encode(payload, forKey: .initiating)
		case .responding(let payload):
			try container.encode(Tag.responding.rawValue, forKey: .tag)
			try container.encode(payload, forKey: .responding)
		case .rekeyInitiated(let updMessage):
			try container.encode(Tag.rekeyInitiated.rawValue, forKey: .tag)
			try container.encode(updMessage, forKey: .rekeyInitiatedMessage)
		case .rekeyResponded:
			try container.encode(Tag.rekeyResponded.rawValue, forKey: .tag)
		}
	}

	init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		let rawTag = try container.decode(UInt64.self, forKey: .tag)
		guard let tag = Tag(rawValue: rawTag) else {
			throw DecodingError.dataCorruptedError(
				forKey: .tag, in: container,
				debugDescription: "unknown PQInflight tag \(rawTag)")
		}
		switch tag {
		case .bootstrapInitiated: self = .bootstrapInitiated
		case .bootstrapResponded: self = .bootstrapResponded
		case .initiating:
			self = .initiating(
				try container.decode(PQEphemeralArchive.self, forKey: .initiating))
		case .responding:
			self = .responding(
				try container.decode(PQRespondingArchive.self, forKey: .responding))
		case .rekeyInitiated:
			self = .rekeyInitiated(
				updMessage: try container.decode(
					Data.self, forKey: .rekeyInitiatedMessage))
		case .rekeyResponded: self = .rekeyResponded
		}
	}
}

extension PQInflightArchive {
	init(_ live: PQInflight) {
		switch live {
		case .bootstrapInitiated: self = .bootstrapInitiated
		case .bootstrapResponded: self = .bootstrapResponded
		case .initiating(let eph):
			self = .initiating(
				PQEphemeralArchive(secretKey: eph.secretKey.data, ek: eph.ek))
		case .responding(let secret, let wireCT):
			self = .responding(PQRespondingArchive(secret: secret, wireCT: wireCT))
		case .rekeyInitiated(let updMessage):
			self = .rekeyInitiated(updMessage: updMessage)
		case .rekeyResponded: self = .rekeyResponded
		}
	}

	func restore() throws -> PQInflight {
		switch self {
		case .bootstrapInitiated: return .bootstrapInitiated
		case .bootstrapResponded: return .bootstrapResponded
		case .initiating(let archive):
			return .initiating(
				PQEphemeral(
					secretKey: try MLS.HpkeSecretKey(archive.secretKey),
					ek: archive.ek))
		case .responding(let archive):
			return .responding(secret: archive.secret, wireCT: archive.wireCT)
		case .rekeyInitiated(let updMessage):
			return .rekeyInitiated(updMessage: updMessage)
		case .rekeyResponded: return .rekeyResponded
		}
	}
}

/// `pendingProposal`'s archived form (Swift tuples aren't `Codable`).
struct PendingProposalArchive: Codable, Sendable, Equatable {
	var proposing: Data
	var message: Data
	var hash: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case proposing = 0
		case message = 1
		case hash = 2
	}

	init(proposing: Data, message: Data, hash: Data) {
		self.proposing = proposing
		self.message = message
		self.hash = hash
	}

	init(_ tuple: (proposing: Data, message: Data, hash: Data)) {
		self.init(proposing: tuple.proposing, message: tuple.message, hash: tuple.hash)
	}

	var asTuple: (proposing: Data, message: Data, hash: Data) {
		(proposing: proposing, message: message, hash: hash)
	}
}

/// `offeredProposal`/`queuedProposal`'s shared archived shape.
struct DigestedProposalArchive: Codable, Sendable, Equatable {
	var digest: Data
	var proposing: Data
	var message: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case digest = 0
		case proposing = 1
		case message = 2
	}

	init(digest: Data, proposing: Data, message: Data) {
		self.digest = digest
		self.proposing = proposing
		self.message = message
	}

	init(_ tuple: (digest: Data, proposing: Data, message: Data)) {
		self.init(digest: tuple.digest, proposing: tuple.proposing, message: tuple.message)
	}

	var asTuple: (digest: Data, proposing: Data, message: Data) {
		(digest: digest, proposing: proposing, message: message)
	}
}

/// One `stagedUpdates` entry, archived.
struct StagedUpdateArchive: Codable, Sendable, Equatable {
	var digest: Data
	var message: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case digest = 0
		case message = 1
	}

	init(digest: Data, message: Data) {
		self.digest = digest
		self.message = message
	}

	init(_ tuple: (digest: Data, message: Data)) {
		self.init(digest: tuple.digest, message: tuple.message)
	}

	var asTuple: (digest: Data, message: Data) {
		(digest: digest, message: message)
	}
}

/// One `sendCrossPSKLedger` entry — `MLS.Combiner.ExportedPsk`'s
/// `storageID` is not archived (it is recomputed from `componentID`/`pskID`
/// by `fromParts`, exactly as swift-mls's own ledger-restore path does).
struct ExportedPskArchive: Codable, Sendable {
	var componentID: UInt16
	var pskID: Data
	@SecretField var psk: SecretBytes

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case componentID = 0
		case pskID = 1
		case psk = 2
	}
}

extension ExportedPskArchive {
	init(_ exported: MLS.Combiner.ExportedPsk) {
		self.init(
			componentID: exported.componentID.rawValue, pskID: exported.pskID,
			psk: exported.psk)
	}

	func restore() throws -> MLS.Combiner.ExportedPsk {
		try MLS.Combiner.ExportedPsk.fromParts(
			componentID: MLS.Extensions.ComponentID(rawValue: componentID),
			pskID: pskID, psk: psk)
	}
}

/// `RotationCandidate`, archived. Keys 1 and 2 (the candidate's own
/// signing/signature key) are retired: the candidate's key now lives only
/// in `leafKeys`, so an older archive that still carries them decodes fine
/// (synthesized `Decodable` ignores unknown integer keys) and a new one
/// simply never writes them.
struct RotationCandidateArchive: Codable, Sendable {
	var clientID: Data
	var proposedAtRecvEpoch: UInt64

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case clientID = 0
		// 1, 2: retired — the candidate's own signing/signature key.
		case proposedAtRecvEpoch = 3
	}
}

extension RotationCandidateArchive {
	init(_ candidate: RotationCandidate) {
		self.init(
			clientID: candidate.clientID,
			proposedAtRecvEpoch: candidate.proposedAtRecvEpoch)
	}

	func restore() -> RotationCandidate {
		RotationCandidate(
			clientID: clientID, proposedAtRecvEpoch: proposedAtRecvEpoch)
	}
}

/// `LeafKey`, archived — one signing keypair.
struct LeafKeyArchive: Codable, Sendable, Equatable {
	@SecretField var signingKey: SecretBytes
	var signatureKey: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case signingKey = 0
		case signatureKey = 1
	}
}

extension LeafKeyArchive {
	init(_ key: LeafKey) {
		self.init(signingKey: key.signingKey.data, signatureKey: key.signatureKey.data)
	}

	/// Derive-checks the secret against its claimed public: every key in
	/// the archive, not just the identity's, must derive.
	func restore() throws -> LeafKey {
		let derived = try derivedSignaturePublicKey(from: signingKey)
		guard derived.data == signatureKey else { throw TwoMLSError.archiveInvalid }
		return LeafKey(
			signingKey: try MLS.SignatureSecretKey(signingKey), signatureKey: derived)
	}
}

/// One `pending` entry, archived — the target credential id plus its staged
/// key.
struct PendingLeafKeyArchive: Codable, Sendable, Equatable {
	var target: Data
	var key: LeafKeyArchive

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case target = 0
		case key = 1
	}
}

/// `GroupKeySet`, archived — `pending` rides as an array (sorted by target
/// at encode, for a stable byte shape), not a `Dictionary`, so decode can
/// reject a duplicate or empty target explicitly rather than silently
/// de-duplicating the way a keyed container would.
struct GroupKeySetArchive: Codable, Sendable, Equatable {
	var current: LeafKeyArchive?
	var pending: [PendingLeafKeyArchive]

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case current = 0
		case pending = 1
	}
}

extension GroupKeySetArchive {
	init(_ set: GroupKeySet) {
		self.init(
			current: set.current.map(LeafKeyArchive.init),
			pending: set.pending.sorted { $0.key.lexicographicallyPrecedes($1.key) }
				.map {
					PendingLeafKeyArchive(
						target: $0.key, key: LeafKeyArchive($0.value))
				}
		)
	}

	func restore() throws -> GroupKeySet {
		var restoredPending: [Data: LeafKey] = [:]
		for entry in pending {
			guard !entry.target.isEmpty, restoredPending[entry.target] == nil else {
				throw TwoMLSError.archiveInvalid
			}
			restoredPending[entry.target] = try entry.key.restore()
		}
		return GroupKeySet(current: try current?.restore(), pending: restoredPending)
	}
}

/// `LeafKeys`, archived — required (archive key 41): v1 never shipped, so
/// there is no legacy read path and no optional fallback for the classical
/// sets. The PQ sets ride only in a Checkpoint — a Core omits them, exactly
/// like `GroupEntry.pq` itself — so `sendPQ`/`recvPQ` are `nil` there; the
/// two manifest-only fingerprint fields on `SessionArchive` itself carry the
/// cheap, kind-independent signal `validateManifestAgreement` needs to
/// cross-check a Core's claimed PQ key state without the trees.
struct LeafKeysArchive: Codable, Sendable, Equatable {
	var sendClassical: GroupKeySetArchive
	var recvClassical: GroupKeySetArchive
	var sendPQ: GroupKeySetArchive?
	var recvPQ: GroupKeySetArchive?

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case sendClassical = 0
		case recvClassical = 1
		case sendPQ = 2
		case recvPQ = 3
	}
}

extension LeafKeysArchive {
	/// `kind` selects whether the PQ sets ride along: `.checkpoint` carries
	/// both, `.core` carries neither — mirroring `GroupEntry`'s own
	/// kind-gated PQ omission.
	init(_ keys: LeafKeys, kind: BlobKind) {
		self.init(
			sendClassical: GroupKeySetArchive(keys.sendClassical),
			recvClassical: GroupKeySetArchive(keys.recvClassical),
			sendPQ: kind == .checkpoint ? GroupKeySetArchive(keys.sendPQ) : nil,
			recvPQ: kind == .checkpoint ? GroupKeySetArchive(keys.recvPQ) : nil)
	}

	/// Called only on the body `restore` actually builds a session from —
	/// by that point (`validateHeader` plus, on the splice path,
	/// `splicingPQ`) the PQ sets are always present, so their absence here
	/// means the caller skipped that validation, not a normal Core shape.
	func restore() throws -> LeafKeys {
		guard let sendPQ, let recvPQ else { throw TwoMLSError.archiveInvalid }
		return LeafKeys(
			sendClassical: try sendClassical.restore(),
			recvClassical: try recvClassical.restore(), sendPQ: try sendPQ.restore(),
			recvPQ: try recvPQ.restore())
	}
}

/// Archive key 44 — the deployed engine's migration carry:
/// omitted when there's nothing to carry; present-but-empty (every
/// sub-field absent/empty) is `.archiveInvalid` — there's never a reason to
/// encode one that way, so one surviving decode is corrupt or adversarial.
/// Both keys 44/45 ride both kinds (`Core` and `Checkpoint` alike) and come
/// from the winning body at restore — never spliced, unlike the PQ-gated
/// fields `splicingPQ` touches.
struct DeployedCarryArchive: Codable, Sendable, Equatable {
	var ownOfferWindow: OwnOfferWindowRecord?
	/// Raw `MigratedPQWedge.rawValue` — an unknown value at restore is
	/// `.archiveInvalid`.
	var pqWedged: UInt8?
	/// Raw `MigratedGroupRole.rawValue`s — sorted, unique, non-empty when
	/// present (an empty set is represented by omitting this field, not by
	/// an empty array).
	var noCustody: [UInt8]?

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case ownOfferWindow = 0
		case pqWedged = 1
		case noCustody = 2
	}

	var isEmpty: Bool { ownOfferWindow == nil && pqWedged == nil && noCustody == nil }
}

// MARK: - The session archive body

/// The `SessionArchive` wire body — one `Codable` struct for both Core and
/// Checkpoint kinds (disambiguated by `kind`), covering every
/// `TwoMLSSession` field. `version`/`classicalSuite`/`pqSuite`/`kind` are
/// the leading fields so `restore` can validate them immediately after
/// decode; `stateSeq` plus the PQ-epoch (and classical-group-id) manifest
/// fields are what reconcile compares WITHOUT first restoring any group —
/// `sendClassicalGroupID`/`recvClassicalGroupID` exist only for that cheap
/// pre-restore comparison, since `MLS.RFC9420.Group.Snapshot`'s own fields
/// are not accessible outside its defining module.
struct SessionArchive: Codable, Sendable {
	var version: UInt64
	var classicalSuite: UInt16
	var pqSuite: UInt16
	var kind: BlobKind
	var stateSeq: UInt64
	var sendPQEpoch: UInt64?
	var recvPQEpoch: UInt64?
	var sendClassicalGroupID: Data?
	var recvClassicalGroupID: Data?
	var identity: IdentityArchive
	var auth: AuthCore
	var sendGroup: GroupEntry?
	var recvGroup: GroupEntry?
	var currentStaple: Data
	var pendingProposal: PendingProposalArchive?
	var joinedWelcomeDigest: Data?
	var initiated: Bool
	var bootstrapKPSecret: BootstrapKPSecretArchive?
	var expectedBootstrapKPCommitment: Data?
	var pqTurnMine: Bool
	var owedBind: OwedBind?
	var pqInflight: PQInflightArchive?
	var pendingSideBand: Data?
	var peerAppliedSendEpoch: UInt64?
	var lastCrossInjected: UInt64?
	var lastCrossInjectedPQ: UInt64?
	var lastSendPQExported: UInt64?
	var offeredProposal: DigestedProposalArchive?
	var queuedProposal: DigestedProposalArchive?
	var stagedUpdates: [StagedUpdateArchive]
	var sendCrossPSKLedger: ArchiveIntegerKeyedMap<ExportedPskArchive>
	var rotationCandidate: RotationCandidateArchive?
	var spawnToken: Data?
	/// `listenRendezvous` — Optional so a pre-existing
	/// v1 archive (encoded before this field existed) still decodes: it
	/// decodes to an empty map, and `restore` re-captures the current
	/// epoch's address at once (restore is itself a capture site).
	var listenRendezvous: ArchiveIntegerKeyedMap<Data>?
	/// `recvHeaderKeys`/`recvHeaderKeysPQ` — same
	/// optional-with-empty-default shape as `listenRendezvous`: absent on a
	/// pre-existing archive, in which case `restore` re-captures the
	/// current epoch's key(s) at once.
	var recvHeaderKeys: ArchiveIntegerKeyedMap<Data>?
	var recvHeaderKeysPQ: ArchiveIntegerKeyedMap<Data>?
	/// `initialTheirKP` — Optional so a pre-existing
	/// archive still decodes; `nil` for every session except a live
	/// pre-Group_B-join initiator (the only state `pendingOutbound()`
	/// applies to).
	var initialTheirKP: CombinerKeyPackageArchive?
	/// `sendAttachmentLedger`/`recvAttachmentLedger` (+Attachment.swift),
	/// added for attachment CEK export — same optional-with-empty-default
	/// shape as `listenRendezvous`/`recvHeaderKeys`: absent on a
	/// pre-existing archive, in which case `restore` re-captures the
	/// current epoch's `0xFF03` component at once (restore is itself a
	/// capture site, same as those windows). Reuses the `@SecretField`
	/// wrapper (`IdentityArchive`'s own pattern) since the raw component —
	/// unlike a ledgered `ExportedPsk` — carries no other archived metadata.
	var sendAttachmentLedger: ArchiveIntegerKeyedMap<SecretField<SecretBytes>>?
	var recvAttachmentLedger: ArchiveIntegerKeyedMap<SecretField<SecretBytes>>?
	/// Optional so a pre-existing archive still decodes
	/// (absent means `false`, matching the live field's own default): the
	/// non-emittable gate's live state, so a RESTORED owed-but-not-installed
	/// Bob still owes.
	var owesEstablishmentEnvelope: Bool?
	/// REQUIRED, unlike every other field added since v1: this format never
	/// shipped before this field existed, so there is no legacy archive to
	/// tolerate its absence for, and no fallback reconstruction path. A
	/// missing key 41 is a `DecodingError`, which `restore`/`decode` fold to
	/// `.archiveInvalid` like any other malformed archive. Its own PQ sets
	/// are kind-gated (present on a Checkpoint, absent on a Core); the two
	/// fields below are not, and are just as required — they ride on every
	/// kind, mirroring `sendPQEpoch`/`recvPQEpoch`'s own always-present
	/// manifest shape, so a Core's claimed PQ key state can be checked
	/// without its trees.
	var leafKeys: LeafKeysArchive
	var sendPQKeysFingerprint: GroupKeySetFingerprint
	var recvPQKeysFingerprint: GroupKeySetFingerprint
	/// Archive key 44 — see `DeployedCarryArchive`'s own doc.
	var deployedCarry: DeployedCarryArchive?
	/// Archive key 45 — core state, not carry: rule 9's stored,
	/// validated-only pre-establishment app payload.
	var initialAppPayload: Data?

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case version = 0
		case classicalSuite = 1
		case pqSuite = 2
		case kind = 3
		case stateSeq = 4
		case sendPQEpoch = 5
		case recvPQEpoch = 6
		case sendClassicalGroupID = 7
		case recvClassicalGroupID = 8
		case identity = 9
		case auth = 10
		case sendGroup = 11
		case recvGroup = 12
		case currentStaple = 13
		case pendingProposal = 14
		case joinedWelcomeDigest = 15
		case initiated = 16
		case bootstrapKPSecret = 17
		case expectedBootstrapKPCommitment = 18
		case pqTurnMine = 19
		case owedBind = 20
		case pqInflight = 21
		case pendingSideBand = 22
		case peerAppliedSendEpoch = 23
		case lastCrossInjected = 24
		case lastCrossInjectedPQ = 25
		case lastSendPQExported = 26
		case offeredProposal = 27
		case queuedProposal = 28
		case stagedUpdates = 29
		case sendCrossPSKLedger = 30
		case rotationCandidate = 31
		case spawnToken = 32
		case listenRendezvous = 33
		case recvHeaderKeys = 34
		case recvHeaderKeysPQ = 35
		case initialTheirKP = 36
		case sendAttachmentLedger = 37
		case recvAttachmentLedger = 38
		case owesEstablishmentEnvelope = 39
		// 40: retired — the born-dedicated recv-leaf catch-up custody.
		case leafKeys = 41
		case sendPQKeysFingerprint = 42
		case recvPQKeysFingerprint = 43
		case deployedCarry = 44
		case initialAppPayload = 45
	}
}

/// Derives Ed25519's public key from a raw private-key secret — the same
/// primitive `TwoMLSIdentity.mintSignatureKeypair()` uses in the other
/// direction. Not a suite-generic operation (the `CipherSuiteProvider` seam
/// has no "derive the public half" method), but the port's classical suite
/// pins Ed25519 signing, and a restore-time cross-check against a
/// corrupt-but-authenticated archive is worth the one hardcoded primitive.
/// Any failure (including a wrong-length secret) is `archiveInvalid`, not a
/// raw `CryptoKitError`.
private func derivedSignaturePublicKey(from signingKey: SecretBytes) throws
	-> MLS
	.SignaturePublicKey
{
	guard let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: signingKey)
	else {
		throw TwoMLSError.archiveInvalid
	}
	return MLS.SignaturePublicKey(privateKey.publicKey.rawRepresentation)
}

/// The current, and so far only, archive format version. Internal (not
/// `private`) so `restore`'s header check references it directly instead of
/// repeating the literal.
let sessionArchiveVersion: UInt64 = 1

// MARK: - Encode

// Gated because it bridges to a live iOS 26 port type — see IdentityArchive in SessionArchive.swift.
@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Builds this session's archive: `kind` selects whether the PQ trees
	/// ride along (Checkpoint) or are omitted (Core; the manifest fields
	/// still carry the current PQ epochs either way). `stateSeq` is this
	/// session's own live persistence sequence number (the return cadence's
	/// `StateUpdate`/`advanceStateSeq()` is what bumps it).
	/// State is total: this never refuses to encode. Returns an UNSEALED,
	/// zeroizing `SecretArchive` — the app seals it with its own key before
	/// writing it out; this library never holds a sealing key.
	func makeSessionArchive(kind: BlobKind) throws -> SecretArchive {
		// (DEBUG only): a fault point genuinely INSIDE encode, not merely
		// near the caller's own call site, so it fires exactly at the
		// boundary between `stateUpdate(kind:)`'s stamp and this call's own
		// encode — a fault armed only nearby would miss any reordering
		// between the two.
		#if DEBUG
			if TwoMLSSessionTestHooks.shouldFault("stateUpdate.beforeEncode") {
				throw InjectedTestFault(name: "stateUpdate.beforeEncode")
			}
		#endif
		// The port is `.deployed`-only (no caller ever constructs a session
		// under different codepoints); `restore` hard-codes `.deployed`
		// rather than archiving this field, on that same assumption.
		assert(
			codepoints == .deployed,
			"session archive encoding assumes the deployed codepoints")
		let body = SessionArchive(
			version: sessionArchiveVersion,
			classicalSuite: TwoMLSSuite.classical.id,
			pqSuite: TwoMLSSuite.pq.id,
			kind: kind,
			stateSeq: stateSeq,
			sendPQEpoch: sendGroup?.pq?.context.epoch,
			recvPQEpoch: recvGroup?.pq?.context.epoch,
			sendClassicalGroupID: sendGroup?.classical.context.groupID,
			recvClassicalGroupID: recvGroup?.classical.context.groupID,
			identity: try IdentityArchive(
				identity, includeInitSecrets: recvGroup == nil),
			// `stateUpdate(kind:)` already normalizes `auth` before ever
			// calling this — production archives come only from there. This
			// recompute is cheap and covers the direct-archive path (tests,
			// injected-fault probes) that calls this method without going
			// through that choke point first.
			auth: pqPinnedAuth(),
			sendGroup: try sendGroup?.makeGroupEntry(kind: kind),
			recvGroup: try recvGroup?.makeGroupEntry(kind: kind),
			currentStaple: currentStaple,
			pendingProposal: pendingProposal.map(PendingProposalArchive.init),
			joinedWelcomeDigest: joinedWelcomeDigest,
			initiated: initiated,
			bootstrapKPSecret: try bootstrapKPSecret.map(BootstrapKPSecretArchive.init),
			expectedBootstrapKPCommitment: expectedBootstrapKPCommitment,
			pqTurnMine: pqTurnMine,
			owedBind: owedBind,
			pqInflight: pqInflight.map(PQInflightArchive.init),
			pendingSideBand: pendingSideBand,
			peerAppliedSendEpoch: peerAppliedSendEpoch,
			lastCrossInjected: lastCrossInjected,
			lastCrossInjectedPQ: lastCrossInjectedPQ,
			lastSendPQExported: lastSendPQExported,
			offeredProposal: offeredProposal.map(DigestedProposalArchive.init),
			queuedProposal: queuedProposal.map(DigestedProposalArchive.init),
			stagedUpdates: stagedUpdates.map(StagedUpdateArchive.init),
			sendCrossPSKLedger: ArchiveIntegerKeyedMap(
				sendCrossPSKLedger.mapValues(ExportedPskArchive.init)),
			rotationCandidate: rotationCandidate.map(RotationCandidateArchive.init),
			spawnToken: spawnToken,
			listenRendezvous: ArchiveIntegerKeyedMap(listenRendezvous),
			recvHeaderKeys: ArchiveIntegerKeyedMap(recvHeaderKeys),
			recvHeaderKeysPQ: ArchiveIntegerKeyedMap(recvHeaderKeysPQ),
			initialTheirKP: try initialTheirKP.map(CombinerKeyPackageArchive.init),
			sendAttachmentLedger: ArchiveIntegerKeyedMap(
				sendAttachmentLedger.mapValues { SecretField(wrappedValue: $0) }),
			recvAttachmentLedger: ArchiveIntegerKeyedMap(
				recvAttachmentLedger.mapValues { SecretField(wrappedValue: $0) }),
			owesEstablishmentEnvelope: owesEstablishmentEnvelope,
			leafKeys: LeafKeysArchive(leafKeys, kind: kind),
			sendPQKeysFingerprint: leafKeys.sendPQ.fingerprint,
			recvPQKeysFingerprint: leafKeys.recvPQ.fingerprint,
			deployedCarry: makeDeployedCarryArchive(),
			initialAppPayload: initialAppPayload)
		return try SecretArchive(encoding: body)
	}

	/// Archive key 44's live encode — `O(1)`, the record only, never
	/// the window blob itself (which the host owns separately). `nil` when
	/// there's nothing to carry, matching the archive's own "omitted when
	/// empty" contract.
	private func makeDeployedCarryArchive() -> DeployedCarryArchive? {
		let carry = DeployedCarryArchive(
			ownOfferWindow: ownOfferWindow,
			pqWedged: pqWedge?.rawValue,
			noCustody: noCustody.isEmpty ? nil : noCustody.map { $0.rawValue }.sorted())
		return carry.isEmpty ? nil : carry
	}
}
