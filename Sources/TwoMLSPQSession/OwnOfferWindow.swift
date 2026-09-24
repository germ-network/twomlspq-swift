import Crypto
import Foundation
import MLSCodec
@_spi(Migration) import MLSProfileRFC9420
import SecretBytes

// MARK: - The own-offer window: id, blob and rule-10 validation (step 3)
//
// A `MigratedOwnOfferWindow` is minted into its OWN blob (`SessionMigration.
// mintOwnOfferWindow`), never into the session archives — this file owns the
// ONE shared window-id function both mints call (so they agree given the
// same input), the blob's own columnar wire shape (O(1) `SecretArchive`
// nodes regardless of offer count — §A.9 scale), and rule 10's validation
// (including the full swift-mls SPI trial on a bounded sample).

@available(iOS 26, macOS 26, *)
enum OwnOfferWindow {
	/// One canonically-ordered offer.
	struct SortedOffer {
		let ref: Data
		let proposal: Data
		let leafSecret: SecretBytes
	}

	/// Sorts `offers` by ref (ascending), after rejecting a non-32-byte or
	/// duplicate ref. An empty `offers` sorts to `[]` — callers reject that
	/// shape themselves (rule 10: 1 ≤ count).
	static func canonicalOrder(_ offers: [MigratedOwnOffer]) throws -> [SortedOffer] {
		var seen = Set<Data>()
		for offer in offers {
			guard offer.ref.count == 32 else { throw TwoMLSError.archiveInvalid }
			guard seen.insert(offer.ref).inserted else {
				throw TwoMLSError.archiveInvalid
			}
		}
		return
			offers
			.map {
				SortedOffer(
					ref: $0.ref, proposal: $0.proposal,
					leafSecret: $0.leafSecret)
			}
			.sorted { $0.ref.lexicographicallyPrecedes($1.ref) }
	}

	/// The ONE window-id function both mints call — SHA-256 (not the
	/// cipher-suite hash: the id must not depend on the classical suite)
	/// over a canonical, framed encoding of exactly the fields the shapes
	/// doc names:
	/// `"twomlspq-swift own-offer window v1" ‖ u64be(epoch) ‖
	/// u32be(|groupID|) ‖ groupID ‖ u32be(senderLeafIndex) ‖ u32be(count) ‖
	/// for each offer in ascending ref order: ref(32) ‖ u32be(|proposal|) ‖
	/// proposal`. Order-independent over the caller's INPUT `offers` (both
	/// mints sort via `canonicalOrder` first); the domain label and length
	/// prefixes frame only the named fields — nothing is dropped, and a
	/// duplicate ref must already have been rejected by `canonicalOrder`.
	static func id(epoch: UInt64, groupID: Data, senderLeafIndex: UInt32, sorted: [SortedOffer])
		-> Data
	{
		var hasher = SHA256()
		hasher.update(data: Data("twomlspq-swift own-offer window v1".utf8))
		hasher.update(data: beBytes(epoch))
		hasher.update(data: beBytes(UInt32(groupID.count)))
		hasher.update(data: groupID)
		hasher.update(data: beBytes(senderLeafIndex))
		hasher.update(data: beBytes(UInt32(sorted.count)))
		for offer in sorted {
			hasher.update(data: offer.ref)
			hasher.update(data: beBytes(UInt32(offer.proposal.count)))
			hasher.update(data: offer.proposal)
		}
		return Data(hasher.finalize())
	}

	private static func beBytes(_ value: UInt64) -> Data {
		withUnsafeBytes(of: value.bigEndian) { Data($0) }
	}
	private static func beBytes(_ value: UInt32) -> Data {
		withUnsafeBytes(of: value.bigEndian) { Data($0) }
	}

	/// Rule 10's SPI-trial sample: the first `min(64, N)` offer indices IN
	/// INPUT ORDER, plus up to 64 more drawn WITHOUT REPLACEMENT from the
	/// rest, picked by a `SplitMix64` seeded on the window id's first 8
	/// bytes (big-endian) — deterministic given the same `offers` array and
	/// id, which is exactly what B.2 requires of both mints (N-5).
	static func sampledOfferIndices(count: Int, idSeed: Data) -> [Int] {
		let firstCount = min(64, count)
		var indices = Array(0..<firstCount)
		var pool = Array(firstCount..<count)
		guard !pool.isEmpty else { return indices }
		var rng = SplitMix64(seed: idSeed)
		let extra = min(64, pool.count)
		for _ in 0..<extra {
			let pick = Int(rng.next() % UInt64(pool.count))
			indices.append(pool[pick])
			pool.remove(at: pick)
		}
		return indices
	}

	/// Rule 10: `window` matches the recv-classical group's current epoch/
	/// group/own-leaf, holds 1...`cap` offers with 32-byte unique refs,
	/// 32-byte secrets and unique encryption keys, and every proposal
	/// decodes (under deployed wire conventions) to `.update`. The full
	/// swift-mls SPI trial (`insertMigratedOwnUpdate`, on a throwaway
	/// `ProposalStore`) then runs over `sampledOfferIndices`'s bounded
	/// sample — not every offer, so mint stays O(1) in expectation over N
	/// past the light per-offer shape checks above. Returns the shared id
	/// and, for rule 6, each offer's (target id, signature key) — the same
	/// pair `decodedUpdateTarget` returns for a framed staged Update.
	static func validate(
		_ window: MigratedOwnOfferWindow,
		recvClassical: MLS.RFC9420.Group,
		myLeafIndex: MLS.LeafIndex,
		cap: Int = MigratedOwnOfferWindow.maximumOfferCount,
		provider: any MLS.CipherSuiteProvider
	) throws -> (id: Data, targets: [(id: Data, signatureKey: MLS.SignaturePublicKey)]) {
		guard window.epoch == recvClassical.context.epoch,
			window.groupID == recvClassical.context.groupID,
			window.senderLeafIndex == myLeafIndex.value
		else { throw TwoMLSError.archiveInvalid }
		guard !window.offers.isEmpty, window.offers.count <= cap else {
			throw TwoMLSError.archiveInvalid
		}

		let sorted = try canonicalOrder(window.offers)
		var seenEncryptionKeys = Set<Data>()
		var targets: [(id: Data, signatureKey: MLS.SignaturePublicKey)] = []
		targets.reserveCapacity(window.offers.count)
		for offer in window.offers {
			guard offer.leafSecret.byteCount == 32 else {
				throw TwoMLSError.archiveInvalid
			}
			let proposal: MLS.RFC9420.Proposal
			do {
				proposal = try withDeployedWireConventions {
					try MLS.RFC9420.Proposal(mlsEncoded: offer.proposal)
				}
			} catch {
				throw TwoMLSError.archiveInvalid
			}
			guard case .update(let leafNode) = proposal else {
				throw TwoMLSError.archiveInvalid
			}
			guard seenEncryptionKeys.insert(leafNode.encryptionKey.data).inserted else {
				throw TwoMLSError.archiveInvalid
			}
			targets.append(
				(
					id: try basicIdentifier(leafNode.credential),
					signatureKey: leafNode.signatureKey
				)
			)
		}

		let id = Self.id(
			epoch: window.epoch, groupID: window.groupID,
			senderLeafIndex: window.senderLeafIndex, sorted: sorted)

		var scratch = MLS.RFC9420.ProposalStore()
		for index in sampledOfferIndices(count: window.offers.count, idSeed: id) {
			let offer = window.offers[index]
			let proposal: MLS.RFC9420.Proposal
			do {
				proposal = try withDeployedWireConventions {
					try MLS.RFC9420.Proposal(mlsEncoded: offer.proposal)
				}
			} catch {
				throw TwoMLSError.archiveInvalid
			}
			guard case .update(let leafNode) = proposal else {
				throw TwoMLSError.archiveInvalid
			}
			do {
				try recvClassical.insertMigratedOwnUpdate(
					as: myLeafIndex, provider, into: &scratch,
					ref: MLS.HashReference(offer.ref), leafNode: leafNode,
					epoch: window.epoch, groupID: window.groupID,
					leafSecret: try MLS.HpkeSecretKey(offer.leafSecret))
			} catch {
				throw TwoMLSError.archiveInvalid
			}
		}

		return (id, targets)
	}
}

/// A tiny, deterministic, non-cryptographic PRNG (Vigna's SplitMix64) — used
/// only to pick the "seeded random 64" sample in `validate` above, never for
/// anything security-sensitive.
private struct SplitMix64 {
	private var state: UInt64

	init(seed: Data) {
		var value: UInt64 = 0
		for byte in seed.prefix(8) {
			value = (value << 8) | UInt64(byte)
		}
		state = value
	}

	mutating func next() -> UInt64 {
		state = state &+ 0x9E37_79B9_7F4A_7C15
		var z = state
		z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
		z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
		return z ^ (z >> 31)
	}
}

// MARK: - The blob wire shape (`MintedOwnOfferWindow.archive`'s body)

/// Columnar so the number of `SecretArchive` nodes stays O(1) regardless of
/// offer count (§A.9): four flat fields instead of about one struct — and
/// four `SecretArchive` nodes — per offer.
struct OwnOfferWindowArchive: Codable, Sendable {
	static let currentFormat: UInt64 = 1

	var format: UInt64
	var epoch: UInt64
	var groupID: Data
	var senderLeafIndex: UInt32
	/// `count` × 32 bytes, strictly ascending.
	var refs: Data
	/// `count` × `u32be`, same order as `refs`.
	var proposalLengths: Data
	/// Concatenated, same order as `refs`.
	var proposals: Data
	/// `count` × 32 bytes, same order as `refs` — the offers' HPKE secrets,
	/// columnar rather than one `SecretField` per offer.
	@SecretField var leafSecrets: SecretBytes

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case format = 0
		case epoch = 1
		case groupID = 2
		case senderLeafIndex = 3
		case refs = 4
		case proposalLengths = 5
		case proposals = 6
		case leafSecrets = 7
	}
}

@available(iOS 26, macOS 26, *)
extension OwnOfferWindowArchive {
	init(
		epoch: UInt64, groupID: Data, senderLeafIndex: UInt32,
		sorted: [OwnOfferWindow.SortedOffer]
	) throws {
		var refs = Data()
		var lengths = Data()
		var proposals = Data()
		var secretBytes = Data()
		refs.reserveCapacity(sorted.count * 32)
		secretBytes.reserveCapacity(sorted.count * 32)
		for offer in sorted {
			refs.append(offer.ref)
			let length = UInt32(offer.proposal.count)
			withUnsafeBytes(of: length.bigEndian) { lengths.append(contentsOf: $0) }
			proposals.append(offer.proposal)
			offer.leafSecret.withUnsafeBytes { secretBytes.append(contentsOf: $0) }
		}
		self.init(
			format: Self.currentFormat, epoch: epoch, groupID: groupID,
			senderLeafIndex: senderLeafIndex, refs: refs, proposalLengths: lengths,
			proposals: proposals, leafSecrets: try SecretBytes(bytes: secretBytes))
	}
}
