import Foundation
import MLSCodec
import MLSProfileRFC9420

/// Session-layer 2-party enforcement. The profile has no `MlsRules`-style
/// filter seam (explicit proposal-list `committing`/`validating` instead), so
/// this is (a) construction discipline over the proposal lists this module
/// builds and (b) ingest validation on joins. The fold-side clauses (≤1 peer
/// Update, custom-only-AppDataUpdate, epoch discipline) apply only once a
/// commit can be applied, which is a slice ≥2 concern.
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
}
