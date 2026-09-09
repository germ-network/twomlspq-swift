import Foundation
import MLSCodec
import MLSProfileRFC9420

/// Session-layer 2-party enforcement. The profile has no `MlsRules`-style
/// filter seam (explicit proposal-list `committing`/`validating` instead), so
/// this is (a) construction discipline over the proposal lists this module
/// builds and (b) ingest validation on joins. The fold-side clauses (≤1 peer
/// Update, custom-only-AppDataUpdate, epoch discipline) apply only once the
/// peer's routine staged proposal can be folded, which is a slice ≥3
/// concern.
enum TwoPartyRules {
	/// Every non-blank leaf count must be exactly two — run after every join
	/// (both halves) and, from slice 2, after every applied commit.
	static func ensureTwoParty(_ group: MLS.RFC9420.Group) throws {
		let count = group.tree.nonBlankLeaves().count
		guard count == 2 else { throw TwoMLSError.notTwoParty(count: count) }
	}

	/// A creation commit (roster 1 → 2) may carry exactly one `Add`, no
	/// `Update`, only `application`/`external` PSKs, and — for a full pair —
	/// the `AppDataUpdate` attestation; every other proposal type is
	/// forbidden. This module never emits anything else, so this asserts the
	/// construction discipline rather than filtering caller input.
	static func validateCreationProposals(_ proposals: [MLS.RFC9420.ProposalOrRef]) throws {
		var addCount = 0
		var updateCount = 0
		for entry in proposals {
			guard case .proposal(let proposal) = entry else {
				throw TwoMLSError.invalidCreationProposals
			}
			switch proposal {
			case .add:
				addCount += 1
			case .update:
				updateCount += 1
			case .preSharedKey(let identifier):
				switch identifier {
				case .application, .external: break
				case .resumption: throw TwoMLSError.invalidCreationProposals
				}
			case .appDataUpdate:
				break
			case .remove, .reInit, .externalInit, .groupContextExtensions:
				throw TwoMLSError.invalidCreationProposals
			}
		}
		guard addCount == 1, updateCount == 0 else {
			throw TwoMLSError.invalidCreationProposals
		}
	}

	/// The PQ-half bind commit's (`owePQBind`, a pathless PARTIAL) applied
	/// `CommitEffects` must be exactly `[epochAdvanced, appDataUpdate]` — no
	/// membership or credential change, and no path-leaf refresh (pathless).
	/// PSK proposals leave no `CommitEffect`, so this is silent on the
	/// injected external PSK; the resumption-ban §12.2 clause is unenforceable
	/// from this seam (resumption ids never reach `CommitEffects`).
	static func validateBindPQEffects(_ effects: MLS.RFC9420.CommitEffects) throws {
		var sawEpochAdvanced = false
		var sawAppDataUpdate = false
		for event in effects.events {
			switch event {
			case .epochAdvanced: sawEpochAdvanced = true
			case .appDataUpdate: sawAppDataUpdate = true
			case .added, .removed, .credentialReplaced, .updated, .membershipRemoved:
				throw TwoMLSError.invalidBindEffects
			}
		}
		guard sawEpochAdvanced, sawAppDataUpdate else {
			throw TwoMLSError.invalidBindEffects
		}
	}

	/// The classical-half bind commit's (`dischargeOwedBindIfLicensed`, a
	/// FULL discharge) applied `CommitEffects` must be exactly `[epochAdvanced,
	/// updated(committer), appDataUpdate]` — the committer's own path-leaf
	/// refresh is expected (`includePath: true`), but no membership or
	/// credential change. Same resumption-ban caveat as `validateBindPQEffects`.
	static func validateBindClassicalEffects(_ effects: MLS.RFC9420.CommitEffects) throws {
		var sawEpochAdvanced = false
		var sawUpdated = false
		var sawAppDataUpdate = false
		for event in effects.events {
			switch event {
			case .epochAdvanced: sawEpochAdvanced = true
			case .updated: sawUpdated = true
			case .appDataUpdate: sawAppDataUpdate = true
			case .added, .removed, .credentialReplaced, .membershipRemoved:
				throw TwoMLSError.invalidBindEffects
			}
		}
		guard sawEpochAdvanced, sawUpdated, sawAppDataUpdate else {
			throw TwoMLSError.invalidBindEffects
		}
	}

	/// The §A.5 mechanical rekey Commit's (`pqRekeyRespond`, an `includePath:
	/// true` commit folding exactly one peer Update) applied `CommitEffects`
	/// must be exactly `[epochAdvanced, updated(proposer), updated(committer)]`
	/// — two DISTINCT `.updated` leaves, one of them the committer's own
	/// path-refresh (`epochAdvanced`'s `committer`). No membership or
	/// credential change: a rotating Upd′ (`.credentialReplaced`) is Chunk 2
	/// (§15), out of scope here. Mirrors `validateBindPQEffects`/
	/// `validateBindClassicalEffects`.
	static func validateRekeyCommitEffects(_ effects: MLS.RFC9420.CommitEffects) throws {
		var committerLeaf: MLS.LeafIndex?
		var updatedLeaves: [MLS.LeafIndex] = []
		for event in effects.events {
			switch event {
			case .epochAdvanced(_, _, let committer): committerLeaf = committer
			case .updated(let leaf): updatedLeaves.append(leaf)
			case .added, .removed, .credentialReplaced, .membershipRemoved,
				.appDataUpdate:
				throw TwoMLSError.invalidRekeyEffects
			}
		}
		guard let committerLeaf, updatedLeaves.count == 2,
			updatedLeaves[0] != updatedLeaves[1],
			updatedLeaves.contains(committerLeaf)
		else {
			throw TwoMLSError.invalidRekeyEffects
		}
	}
}
