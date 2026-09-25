import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Invitation archive
//
// Swift-native v1, monolithic — an invitation carries no ML-KEM trees, so
// it only ever pushes one kind of blob (book concepts.md). Same
// return-based, sealing-external shape as the session archive: the library
// hands the app an unsealed, zeroizing `SecretArchive`; the app seals with
// its own key.

/// One `Invitation` table entry: an opaque key (a spawn token, a welcome
/// digest, or a bootstrap commitment) mapped to the spawned session's
/// recv-group classical group id. Reused for all three keyed tables; the
/// consumed-remotes set archives as a bare `[Data]` instead (no value to
/// pair).
struct InvitationTableEntry: Codable, Sendable, Equatable {
	var key: Data
	var classicalGroupID: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case key = 0
		case classicalGroupID = 1
	}
}

extension InvitationTableEntry {
	init(_ pair: (key: Data, value: Data)) {
		self.init(key: pair.key, classicalGroupID: pair.value)
	}
}

/// The `InvitationArchive` wire body — one `Codable` struct, always the
/// invitation's complete state (there is no Core/Checkpoint split, since it
/// carries no ML-KEM trees). `version`/`classicalSuite`/`pqSuite` lead so
/// `restore` can validate them immediately after decode, mirroring
/// `SessionArchive`.
struct InvitationArchive: Codable, Sendable {
	var version: UInt64
	var classicalSuite: UInt16
	var pqSuite: UInt16
	var stateSeq: UInt64
	var lastResort: Bool
	var clientID: Data
	/// `nil` once a single-use invitation's key package has been consumed.
	var identity: IdentityArchive?
	var forwardTable: [InvitationTableEntry]
	var processedWelcomes: [InvitationTableEntry]
	var bootstrapRouting: [InvitationTableEntry]
	var consumedRemotes: [Data]

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case version = 0
		case classicalSuite = 1
		case pqSuite = 2
		case stateSeq = 3
		case lastResort = 4
		case identity = 5
		case forwardTable = 6
		case processedWelcomes = 7
		case bootstrapRouting = 8
		case consumedRemotes = 9
		case clientID = 10
	}
}

/// The current, and so far only, invitation archive format version —
/// distinct from `sessionArchiveVersion` (each object versions
/// independently, book concepts.md's per-object persistence).
let invitationArchiveVersion: UInt64 = 1

// MARK: - Encode

@available(iOS 26, macOS 26, *)
extension Invitation {
	/// Builds this invitation's archive. State is total: this never refuses
	/// to encode. Returns an UNSEALED, zeroizing `SecretArchive` — the app
	/// seals it with its own key before writing it out.
	///
	/// `includeInitSecrets: true` — unlike `TwoMLSSession.makeSessionArchive`
	/// — because an un-consumed invitation's identity is a durable
	/// receiving capability: its published key package's init secrets are
	/// still live (not yet spent by any join) and are exactly what a
	/// restored invitation needs to `receive` a welcome. `identity` is
	/// already `nil` for a spent single-use invitation, so there is nothing
	/// for this flag to apply to in that case.
	func makeInvitationArchive() throws -> SecretArchive {
		let body = InvitationArchive(
			version: invitationArchiveVersion,
			classicalSuite: TwoMLSSuite.classical.id,
			pqSuite: TwoMLSSuite.pq.id,
			stateSeq: stateSeq,
			lastResort: lastResort,
			clientID: clientID,
			identity: try identity.map {
				try IdentityArchive($0, includeInitSecrets: true)
			},
			forwardTable: forwardTable.map(InvitationTableEntry.init),
			processedWelcomes: processedWelcomes.map(InvitationTableEntry.init),
			bootstrapRouting: bootstrapRouting.map(InvitationTableEntry.init),
			consumedRemotes: Array(consumedRemotes))
		return try SecretArchive(encoding: body)
	}
}

// MARK: - Restore

@available(iOS 26, macOS 26, *)
extension Invitation {
	/// Restores an invitation from `generateInvitation`'s archive, or a
	/// later pushed one — the four tables (and, unless single-use consumed,
	/// the captured KP private material) all survive. Providers are
	/// supplied by the caller, exactly as `TwoMLSSession.restore` does: they
	/// are runtime objects, not archived state.
	public static func restore(
		archive: SecretArchive,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> Invitation {
		let body = try decodeInvitationArchive(archive)
		guard body.version == invitationArchiveVersion,
			body.classicalSuite == TwoMLSSuite.classical.id,
			body.pqSuite == TwoMLSSuite.pq.id
		else {
			throw TwoMLSError.archiveInvalid
		}

		var invitation = Invitation(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, clientID: body.clientID,
			identity: try body.identity?.restore(), lastResort: body.lastResort)
		invitation.stateSeq = body.stateSeq
		invitation.forwardTable = try dedupedTable(body.forwardTable)
		invitation.processedWelcomes = try dedupedTable(body.processedWelcomes)
		invitation.bootstrapRouting = try dedupedTable(body.bootstrapRouting)
		invitation.consumedRemotes = Set(body.consumedRemotes)
		return invitation
	}

	/// Mirrors `TwoMLSSession.restore`'s `decodeArchive`: fold every decode
	/// failure this format doesn't distinguish into `archiveInvalid`.
	private static func decodeInvitationArchive(_ archive: SecretArchive) throws
		-> InvitationArchive
	{
		do {
			return try archive.decode(InvitationArchive.self)
		} catch is DecodingError {
			throw TwoMLSError.archiveInvalid
		} catch is SecretArchiveError {
			throw TwoMLSError.archiveInvalid
		}
	}

	/// `Dictionary(uniqueKeysWithValues:)` TRAPS on a duplicate key — never
	/// acceptable on a decoded archive. `restore` is documented fail-closed
	/// (`archiveInvalid` on anything it cannot fully trust), so a corrupt or
	/// adversarial blob with a repeated table key must be rejected, not
	/// crash the process.
	private static func dedupedTable(_ entries: [InvitationTableEntry]) throws -> [Data:
		Data]
	{
		var table: [Data: Data] = [:]
		for entry in entries {
			guard table.updateValue(entry.classicalGroupID, forKey: entry.key) == nil
			else {
				throw TwoMLSError.archiveInvalid
			}
		}
		return table
	}
}
