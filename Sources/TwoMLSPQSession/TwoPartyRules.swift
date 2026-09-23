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
			case .custom:
				// A creation commit never carries a wrapped attestation (or any
				// other non-default proposal) — fail closed rather than silently
				// accepting an unvetted custom proposal on group formation.
				throw TwoMLSError.invalidCreationProposals
			}
		}
		guard addCount == 1, updateCount == 0 else {
			throw TwoMLSError.invalidCreationProposals
		}
	}

	/// Assert that an applied commit's INLINE proposals are EXACTLY the
	/// permitted set for the receive apply path calling this — every
	/// `.application`/`.external` PSK id not in the caller's expected sets,
	/// every `.resumption` PSK, and every proposal type/shape the path does
	/// not name is rejected, never silently ignored. Runs over the commit's
	/// raw `proposals` list (a `.reference` entry is skipped: it names a
	/// proposal already bounded by this session's own staged/registered
	/// store, not attacker-controlled content riding the commit itself), so
	/// callers can and should run it BEFORE the commit is handed to
	/// `validating` — it fires ahead of signature/membership-tag
	/// verification, not after. `expectedApplicationStorageIDs` compares the
	/// width-pinned storage id (`PreSharedKeyIdentifier.applicationStorageID`
	/// — the same key `PSKStore`/`recordingResolver` key by), not the raw
	/// `(componentID, pskID)` pair, so it agrees with what the resolver
	/// actually bound.
	static func validateInlineProposals(
		_ proposals: [MLS.RFC9420.ProposalOrRef],
		expectedApplicationStorageIDs: Set<Data>,
		expectedExternalPSKIDs: Set<Data>,
		allowAttestation: Bool
	) throws {
		for entry in proposals {
			guard case .proposal(let proposal) = entry else { continue }
			switch proposal {
			case .preSharedKey(.application(let componentID, let pskID, _)):
				let identifier = MLS.RFC9420.PreSharedKeyIdentifier.application(
					componentID: componentID, pskID: pskID, nonce: Data())
				guard let id = try identifier.applicationStorageID(),
					expectedApplicationStorageIDs.contains(id)
				else {
					throw TwoMLSError.unexpectedProposal
				}
			case .preSharedKey(.external(let pskID, _)):
				guard expectedExternalPSKIDs.contains(pskID) else {
					throw TwoMLSError.unexpectedProposal
				}
			case .preSharedKey(.resumption):
				throw TwoMLSError.unexpectedProposal
			case .custom(let type, _) where type == .init(.appDataUpdate):
				guard allowAttestation else { throw TwoMLSError.unexpectedProposal }
			case .add, .update, .remove, .reInit, .externalInit,
				.groupContextExtensions, .appDataUpdate, .custom:
				throw TwoMLSError.unexpectedProposal
			}
		}
	}

	/// The PQ-half bind commit's (`owePQBind`, a pathless PARTIAL) applied
	/// `CommitEffects` must be exactly `[epochAdvanced, appDataUpdate]` — no
	/// membership or credential change, and no path-leaf refresh (pathless).
	/// PSK proposals leave no `CommitEffect`, so this is silent on the
	/// injected external PSK; the resumption-ban §12.2 clause is unenforceable
	/// from this seam (resumption ids never reach `CommitEffects`). STAYS
	/// strict — unlike `validateRekeyCommitEffects` below — because a bind is
	/// pathless: no leaf ever moves in a pathless commit, so any
	/// `.credentialReplaced` here is malformed regardless of AS legality,
	/// never a legitimate catch-up.
	static func validateBindPQEffects(_ effects: MLS.RFC9420.CommitEffects) throws {
		var sawEpochAdvanced = false
		var sawAppDataUpdate = false
		for event in effects.events {
			switch event {
			case .epochAdvanced: sawEpochAdvanced = true
			case .appDataUpdate: sawAppDataUpdate = true
			case .customProposal(let type, _) where type == .init(.appDataUpdate):
				sawAppDataUpdate = true
			case .added, .removed, .credentialReplaced, .updated, .membershipRemoved,
				.customProposal:
				throw TwoMLSError.invalidBindEffects
			}
		}
		guard sawEpochAdvanced, sawAppDataUpdate else {
			throw TwoMLSError.invalidBindEffects
		}
	}

	/// The general two-party update-commit shape (§11 MF2; reshaped for
	/// slice 6's classical principal rotation): exactly `foldedPeerUpdate ? 2
	/// : 1` DISTINCT MOVED leaves — `moved = leaves(.updated) ∪
	/// leaves(.credentialReplaced)` — one of them the committer's own
	/// path-refresh (`epochAdvanced`'s `committer`), plus `.appDataUpdate`
	/// present iff `allowAppDataUpdate` — and never an Add/Remove/
	/// `membershipRemoved`. Before slice 6 every leaf move was an `.updated`
	/// (a rotation never rode this shape); now a moved leaf is `.updated`
	/// XOR `.credentialReplaced` — the committer's own leaf reports the
	/// latter when `committingRound`'s own-leaf catch-up threads a
	/// `newIdentity` (`CommitProcessing.swift`'s `old == new` emission rule),
	/// and a folded peer rotation reports it for the peer's leaf — so this
	/// treats the two as equivalent leaf-move signals rather than asserting
	/// `.updated` specifically. `foldedPeerUpdate: false` is a bind-only
	/// discharge or a solo own-leaf catch-up (the committer's own refresh
	/// only); `foldedPeerUpdate: true` additionally folds one peer Update/
	/// rotation — the §A.5 mechanical rekey and the classical fold are the
	/// same shape. Up to two `.credentialReplaced` events can co-occur (a
	/// folded peer rotation AND an own-leaf catch-up on one commit) — both
	/// land in `moved` and count normally. This validates SHAPE only, never
	/// credential semantics — `AuthCore.adjudicate` is the seam that
	/// validates a `.credentialReplaced`'s succession. `allowAppDataUpdate`
	/// is really "required": every commit this module builds that carries
	/// the bind's attestation proposal has exactly one `.appDataUpdate`
	/// event, never zero. `error` is what a caller wants thrown for its own
	/// call site (bind vs. rekey vs. fold each keep a distinct identity).
	static func validateTwoPartyUpdateCommit(
		_ effects: MLS.RFC9420.CommitEffects,
		foldedPeerUpdate: Bool,
		allowAppDataUpdate: Bool,
		orThrow error: TwoMLSError
	) throws {
		var committerLeaf: MLS.LeafIndex?
		var movedLeaves: [MLS.LeafIndex] = []
		var sawAppDataUpdate = false
		for event in effects.events {
			switch event {
			case .epochAdvanced(_, _, let committer): committerLeaf = committer
			case .updated(let leaf): movedLeaves.append(leaf)
			case .credentialReplaced(let leaf, _, _): movedLeaves.append(leaf)
			case .appDataUpdate: sawAppDataUpdate = true
			case .customProposal(let type, _) where type == .init(.appDataUpdate):
				sawAppDataUpdate = true
			case .added, .removed, .membershipRemoved, .customProposal:
				throw error
			}
		}
		let expectedMoved = foldedPeerUpdate ? 2 : 1
		guard let committerLeaf,
			movedLeaves.count == expectedMoved,
			Set(movedLeaves).count == expectedMoved,
			movedLeaves.contains(committerLeaf),
			sawAppDataUpdate == allowAppDataUpdate
		else {
			throw error
		}
	}

	/// The classical-half bind commit's (`committingRound`, a FULL discharge
	/// carrying the `apq_psk`/attestation chain) applied `CommitEffects` must
	/// be exactly `[epochAdvanced, updated(committer), appDataUpdate]` when no
	/// fold rides alongside it, or the same plus a second `updated(proposer)`
	/// when one does (§11 MF1/MF2 — a fold+bind `0x05` folds the peer's Upd by
	/// reference on the SAME commit that discharges the bind). Either way the
	/// committer's own path-leaf refresh is expected (`includePath: true`),
	/// but no membership or credential change. Same resumption-ban caveat as
	/// `validateBindPQEffects`. A thin `validateTwoPartyUpdateCommit` wrapper
	/// preserving this call site's own error identity regardless of
	/// `foldedPeerUpdate`.
	static func validateBindClassicalEffects(
		_ effects: MLS.RFC9420.CommitEffects, foldedPeerUpdate: Bool
	) throws {
		try validateTwoPartyUpdateCommit(
			effects, foldedPeerUpdate: foldedPeerUpdate, allowAppDataUpdate: true,
			orThrow: .invalidBindEffects)
	}

	/// The §A.5 mechanical rekey Commit's (`pqRekeyRespond`, an `includePath:
	/// true` commit folding exactly one peer Update) applied `CommitEffects`
	/// must be exactly `[epochAdvanced, moved(proposer), moved(committer)]` —
	/// two DISTINCT moved leaves, one of them the committer's own path-refresh
	/// (`epochAdvanced`'s `committer`) — where a moved leaf is `.updated` XOR
	/// `.credentialReplaced`. A leaf move now legitimately carries a PQ id
	/// change (the proposer catching up to an already-canonical credential, or
	/// a same-id signature-key change — group-rules rule 4 / `valid_successor`'s
	/// same-id arm, protocol doc §1/§3/D6), so `.credentialReplaced` is no
	/// longer refused outright here; this validates SHAPE only. The succession
	/// itself — same-id, or landing on an id already canonical — is the
	/// session call sites' own job (`pqRekeyRespond`/`pqRekeyApply`, via
	/// id-based `validatePQLeafMove`, `CredentialAuthentication.swift`): the PQ
	/// arms still run no `AuthCore.adjudicate` (the AS lives on the classical
	/// half), so `validatePQLeafMove` is its PQ-side counterpart rather than a
	/// blanket refusal. Mirrors `validateBindPQEffects`/
	/// `validateBindClassicalEffects` — and, per §11 MF2, is the exact same
	/// shape the classical fold-only commit validates, just over the PQ
	/// group. A thin `validateTwoPartyUpdateCommit` wrapper preserving this
	/// call site's own error identity.
	static func validateRekeyCommitEffects(_ effects: MLS.RFC9420.CommitEffects) throws {
		try validateTwoPartyUpdateCommit(
			effects, foldedPeerUpdate: true, allowAppDataUpdate: false,
			orThrow: .invalidRekeyEffects)
	}
}
