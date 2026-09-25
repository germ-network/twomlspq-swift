import Foundation
import MLSCodec
import MLSProfileRFC9420
import SecretBytes

// MARK: - Credential Authentication Service (AS)
//
// Started from the Rust `apq::authentication` credential-sequence AS (a peer
// resource — logic ported, text not copied), then adapted to this protocol's
// rules; fidelity to the reference is NOT a goal (and wire-compat does not
// apply — this is in-memory state). Notably, rollback is a hard error here
// (identities are always freshly generated keys), which the reference's
// move-to-newest `commit` did not enforce. This is Germ/TwoMLS
// policy, not RFC 9420- or draft-defined behavior: swift-mls has no
// Authentication Service (`NewSigningIdentity.swift`) and instead surfaces the
// credential change (its `CommitEffect.credentialReplaced` seam, RFC 9420
// §5.3.1-motivated) for the application to adjudicate — this file is that
// application.
//
// Value types, not the Rust reference's `Arc<Mutex>` + rebindable view: that
// indirection exists only because mls-rs bakes an `IdentityProvider` into
// immutable client config while one session drives several clients over its
// life. `TwoMLSSession` is a single-owner, non-forkable value-type state
// machine that owns its groups directly, so `PartySequence`/`AuthCore` are
// held directly as session state instead.

/// Extract a Basic credential's identifier, else `.unsupportedCredential` —
/// the only credential type this session layer's leaves ever advertise
/// (`TwoMLSIdentity.leafCapabilities`).
func basicIdentifier(_ credential: MLS.RFC9420.Credential) throws -> Data {
	guard case .basic(let identity) = credential else {
		throw TwoMLSError.unsupportedCredential
	}
	return identity
}

/// The Basic credential ids each party's leaves presently present across a
/// session's two live PQ trees (book group-rules.md rule 4's pin
/// invariant): `mine` — my leaf in `sendPQ` and in `recvPQ`; `theirs` — the
/// peer's leaf in each. Classical leaves are never included. Either half may
/// be `nil` (deferred, or not yet founded) — that tree simply contributes
/// nothing. A non-`.basic` credential on any occupied leaf throws (never
/// reachable for a leaf this module mints or accepts, which advertises only
/// `.basic`).
func livePQPresentedIDs(
	sendPQ: MLS.RFC9420.Group?, recvPQ: MLS.RFC9420.Group?
) throws -> (mine: Set<Data>, theirs: Set<Data>) {
	var mine: Set<Data> = []
	var theirs: Set<Data> = []
	for group in [sendPQ, recvPQ] {
		guard let group else { continue }
		for entry in group.tree.nonBlankLeaves() {
			let leaf = try MLS.RFC9420.LeafNode(mlsEncoded: entry.record.encoded)
			let id = try basicIdentifier(leaf.credential)
			if entry.index == group.myLeafIndex {
				mine.insert(id)
			} else {
				theirs.insert(id)
			}
		}
	}
	return (mine, theirs)
}

/// One party's app-defined credential sequence (TwoMLS design, not RFC
/// 9420): the canonical `history` (oldest → newest, trimmed to
/// `credentialHistoryWindow`), the app-`authorize`d in-flight successors —
/// several candidates may be proposed, the one the peer commits becomes
/// canonical and the rest expire — and `pinned`: the normal-form set of ids
/// a live PQ leaf of this party currently presents, excluding a
/// not-yet-canonical candidate (`pins(forPresented:)`'s own doc). Not
/// "evicted but held" — an in-history presented id is included too
/// (behavior-neutral for every caller), and a presented id is pinned
/// whether or not it has ever been evicted from `history`.
struct PartySequence: Sendable, Equatable, Codable {
	/// How many canonical credentials are retained for the catch-up rule —
	/// a lagging leaf may fast-forward to any already-canonical element
	/// within this many steps. Sessions rotate rarely; 8 is ample (matches
	/// the Rust reference's `CREDENTIAL_HISTORY_WINDOW`).
	static let credentialHistoryWindow = 8

	var history: [Data] = []
	var authorizedNext: [Data] = []
	var pinned: [Data] = []

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case history = 0
		case authorizedNext = 1
		case pinned = 2
	}

	static func seeded(_ id: Data) -> PartySequence {
		var sequence = PartySequence()
		sequence.history = [id]
		return sequence
	}

	/// The canonical current credential (newest committed element).
	var current: Data? { history.last }

	func contains(_ id: Data) -> Bool { history.contains(id) }

	private func position(_ id: Data) -> Int? { history.firstIndex(of: id) }

	/// App-authorize `id` as a permitted next credential (idempotent).
	mutating func authorize(_ id: Data) {
		if !authorizedNext.contains(id) { authorizedNext.append(id) }
	}

	/// Withdraw a still-outstanding (not yet canonical) authorization —
	/// approval and authorization are one unit (book `group-rules.md:127-133`
	/// rule 2: "the app's approval is the authorization ... so a rejected
	/// approval is a no-op"): when the
	/// commit that would have folded an approved offer fails to build,
	/// the approval must not sit silently re-triable forever with no
	/// compensating withdrawal. A no-op if `id` isn't currently
	/// authorized. Callers only ever revoke an id NOT already in
	/// `history` — removing a canonical id here would be wrong, but
	/// `commit` itself already clears `authorizedNext` on canonicalizing,
	/// so this never needs to check that itself. The peer re-offers every
	/// frame regardless, so losing an authorization this way costs at
	/// most one extra round.
	mutating func revoke(_ id: Data) {
		authorizedNext.removeAll { $0 == id }
	}

	/// Hold `id` admissible past window eviction (idempotent): widens
	/// `knownIDs` and lets an evicted `id` still serve as a successor
	/// `pred`, but it is never itself a valid `succ` (see `validSuccessor`),
	/// so a pin can never authorize a downgrade back onto it. Test-only: the
	/// live session never calls this directly — `pinned` is maintained by
	/// `pins(forPresented:)`/`AuthCore.withPQPins`, recomputed from what a
	/// session's live PQ leaves actually present. Kept for unit tests that
	/// exercise `PartySequence`'s own pinned-predecessor mechanics in
	/// isolation.
	mutating func pin(_ id: Data) {
		if !pinned.contains(id) { pinned.append(id) }
	}

	/// Retire a pin once nothing still carries it (idempotent). Test-only,
	/// same reasoning as `pin(_:)` above.
	mutating func unpin(_ id: Data) {
		pinned.removeAll { $0 == id }
	}

	var pinnedIDs: [Data] { pinned }

	var knownIDs: [Data] { history + authorizedNext + pinned }

	/// The normal-form pin set (book group-rules.md rule 4: "a credential
	/// that a live PQ leaf still presents stays admissible past window
	/// eviction until that leaf catches up"), given the ids this party's
	/// live PQ leaves currently present (`livePQPresentedIDs`): every
	/// presented id EXCEPT a candidate — an `authorizedNext` id not yet in
	/// `history` — since pinning a candidate would block its own
	/// canonicalization (`commit` rejects a pinned id as a rollback). An
	/// in-history presented id is included but behavior-neutral (`commit`
	/// already checks `current == id` first; `validSuccessor`'s shortcut
	/// already excludes a `history` successor). Sorted (lexicographic
	/// bytes), deduplicated by construction (`Set`).
	func pins(forPresented presented: Set<Data>) -> [Data] {
		let candidates = Set(authorizedNext).subtracting(history)
		return presented.subtracting(candidates).sorted { $0.lexicographicallyPrecedes($1) }
	}

	/// Canonicalize `id` as the newest `history` element, expiring every
	/// in-flight authorization. In this protocol every identity is a freshly
	/// generated key, so a recurrence is never legitimate convergence — it is a
	/// rollback, and rejected: `id == current` is an idempotent no-op (kept
	/// BEFORE clearing `authorizedNext`, so re-committing the head does not drop
	/// an authorization already in flight for the NEXT step); an `id` already
	/// known — still in `history`, or `pinned` (a live PQ leaf of this party
	/// currently presents it) — throws `.credentialRollback`; a brand-new
	/// `id` is appended (oldest evicted past
	/// the window). Fail-closed: the throw happens before any mutation. The
	/// recurrence check is bounded to `history` + `pinned`; an id evicted past
	/// the window AND unpinned is no longer remembered, so the always-fresh-key
	/// invariant (not this check) is what rules out a deep recurrence.
	mutating func commit(_ id: Data) throws {
		if current == id { return }
		if history.contains(id) || pinned.contains(id) {
			throw TwoMLSError.credentialRollback
		}
		authorizedNext.removeAll()
		history.append(id)
		while history.count > Self.credentialHistoryWindow {
			history.removeFirst()
		}
	}

	/// May a leaf currently bearing `pred` move to `succ`? The gate order is
	/// load-bearing: an unknown `pred` (neither in `history` nor `pinned`)
	/// is rejected BEFORE the authorized-`succ` check, so an authorized
	/// candidate can never smuggle in a `pred` this sequence never held. A
	/// `pred` that is only `pinned` (evicted from `history`) counts as known
	/// and OLDEST — older than every `history` element — so a leaf still
	/// bearing an evicted credential can catch up to any current one;
	/// `pinned` is never itself a valid `succ` — the authorization shortcut
	/// below admits only a `succ` absent from both `history` and `pinned` — so
	/// this can never authorize a downgrade onto a retired credential.
	func validSuccessor(pred: Data, succ: Data) -> Bool {
		if pred == succ { return true }
		let predPosition = position(pred)
		if predPosition == nil && !pinned.contains(pred) { return false }
		// An authorization admits only a genuinely NEW id: an authorized id that
		// is already retired (in `history`, or `pinned` and evicted) falls
		// through to the ordering check below, which rejects it — a rollback
		// dressed as an authorization is still a rollback.
		if authorizedNext.contains(succ), !history.contains(succ),
			!pinned.contains(succ)
		{
			return true
		}
		switch (predPosition, position(succ)) {
		case (_, nil): return false
		case (let pp?, let sp?): return sp > pp
		case (nil, _?): return true  // pred pinned+evicted (oldest) < any history succ
		}
	}

	/// API 1 — "succeeding current" (force-with-lease): is `succ` a valid
	/// successor of THIS party's canonical head? The predecessor is pinned to
	/// `current`, so a caller building on a stale view is rejected. `false` when
	/// there is no current credential.
	func validSuccessorOfCurrent(_ succ: Data) -> Bool {
		guard let current else { return false }
		return validSuccessor(pred: current, succ: succ)
	}
}

/// §A.5 mechanical rekey / catch-up (protocol doc §1/§3): may a PQ leaf
/// currently presenting `oldID` move to `newID`, per `seq`? group-rules rule
/// 4 — "a lagging leaf may only fast-forward to an already-canonical
/// credential" — plus the same-id arm of `valid_successor`
/// (`group-rules.md:152-153`): a same-id move (any signature-key change) is
/// always accepted; an id-changing move must land on an id already canonical
/// in `seq.history` AND a valid successor of `oldID`. Pure: never mutates
/// `seq`, never calls `commit` — this is a check, not a canonicalization. Not
/// D6's own gate (that flag lives in `TwoMLSSession+Messaging.swift` and
/// never calls this) — this is `pqRekeyRespond`/`pqRekeyApply`'s own PQ-side
/// id check, run against the classical `AuthCore` (D2) since the PQ arms
/// track no canonical sequence of their own.
func validatePQLeafMove(oldID: Data, newID: Data, in seq: PartySequence) throws {
	if oldID == newID { return }
	guard seq.history.contains(newID), seq.validSuccessor(pred: oldID, succ: newID) else {
		throw TwoMLSError.invalidSuccession
	}
}

/// The session-canonical 2-party AS state (TwoMLS design): both parties'
/// sequences. 2-party `mine`/`theirs` is correct here (unlike a general
/// swift-mls seam would be) — this is the Germ P2P layer, and
/// `TwoPartyRules` etc. already bake 2-party throughout this module.
///
/// No `adopting` flag (a deviation from the Rust reference, which opens a
/// one-shot admission window around a join whose creator it cannot yet
/// know): that flag is an mls-rs push-model artifact. swift-mls is
/// pull-model — `TwoMLSSession.receive` reads the creator straight off the
/// just-joined roster before this AS is ever consulted — so there is no
/// window during which membership must be admitted without a known
/// identity, and a stored `adopting` on a value struct would be fail-open
/// across any interleaved `throw`.
struct AuthCore: Sendable, Equatable, Codable {
	var mine: PartySequence = PartySequence()
	var theirs: PartySequence = PartySequence()

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case mine = 0
		case theirs = 1
	}

	func knows(_ id: Data) -> Bool {
		mine.knownIDs.contains(id) || theirs.knownIDs.contains(id)
	}

	/// This `AuthCore` with both sequences' `pinned` recomputed to the
	/// normal form (`PartySequence.pins(forPresented:)`) for the given
	/// live-PQ-presented sets — `TwoMLSSession.pqPinnedAuth()`'s pure
	/// underlying step, shared by the live session's state-update choke
	/// point and the migration mint's one-shot derivation.
	func withPQPins(mine minePresented: Set<Data>, theirs theirsPresented: Set<Data>)
		-> AuthCore
	{
		var updated = self
		updated.mine.pinned = mine.pins(forPresented: minePresented)
		updated.theirs.pinned = theirs.pins(forPresented: theirsPresented)
		return updated
	}

	/// `MLS.RFC9420.CredentialPresentation`'s memberwise initializer is
	/// `internal` to `MLSProfileRFC9420`, so this session layer can never
	/// construct one itself — only receive one already built (a commit's
	/// `CommitEffect`, a join's `RosterEntry`). Establishment, which only
	/// ever has a raw `LeafNode.credential` to check, calls this overload
	/// directly; `adjudicate` calls the presentation overload below, which
	/// forwards here. (A two-overload form rather than a single signature,
	/// forced by that access level — no information is lost, since identity
	/// admission never inspects `signatureKey`.)
	func validateMember(_ credential: MLS.RFC9420.Credential) throws {
		let id = try basicIdentifier(credential)
		guard knows(id) else { throw TwoMLSError.unknownIdentity }
	}

	func validateMember(_ presentation: MLS.RFC9420.CredentialPresentation) throws {
		try validateMember(presentation.credential)
	}

	/// API 2 — "A succeeding B": validate `new` as a successor of the predecessor
	/// the effect NAMES (`old`), which may be a known but non-current credential,
	/// so a direct handoff that skips intermediates (a forward gap) is accepted.
	/// RFC 9420 §5.3.1: "the AS MUST also verify that the set of presented
	/// identifiers in the new credential is valid as a successor to the set
	/// of presented identifiers in the old credential, according to the
	/// application's policy." Checked against `party` — the SPECIFIC
	/// sequence whose leaf this replacement effect names (`adjudicate`'s own
	/// `myLeaf` split), never both sequences OR'd together: a replacement on
	/// one party's leaf must be judged against that party's OWN history/
	/// authorization, not the other party's. Fail-closed: an unsupported
	/// credential throws rather than passing.
	func validateSuccession(
		old: MLS.RFC9420.CredentialPresentation, new: MLS.RFC9420.CredentialPresentation,
		party: PartySequence
	) throws {
		let oldID = try basicIdentifier(old.credential)
		let newID = try basicIdentifier(new.credential)
		guard party.validSuccessor(pred: oldID, succ: newID) else {
			throw TwoMLSError.invalidSuccession
		}
	}

	/// API 1 — "succeeding current" (force-with-lease): like `validateSuccession`,
	/// but the presented `old` MUST be a party's current canonical head — a
	/// rotation built on a stale predecessor is rejected even when `old` is still
	/// a known past credential. Use this where the receiver expects to be up to
	/// date; use `validateSuccession` for a handoff that may span a gap.
	func validateSuccessionAgainstCurrent(
		old: MLS.RFC9420.CredentialPresentation, new: MLS.RFC9420.CredentialPresentation
	) throws {
		let oldID = try basicIdentifier(old.credential)
		let newID = try basicIdentifier(new.credential)
		let ok =
			(mine.current == oldID && mine.validSuccessorOfCurrent(newID))
			|| (theirs.current == oldID && theirs.validSuccessorOfCurrent(newID))
		guard ok else { throw TwoMLSError.invalidSuccession }
	}

	/// The consult point `applyFoldCommit`/`applyBind` call at the
	/// `.credentialReplaced` seam, once a rotation's commit has already
	/// passed the shape allow-list
	/// (`TwoPartyRules.validateTwoPartyUpdateCommit`). The engine wires the
	/// three sibling consult points this method does NOT itself perform:
	/// `theirs.authorize` at peer-proposal approval (`validateOfferedUpdate`,
	/// a 2nd reject site alongside `TwoMLSSession.queueProposal`, both in
	/// `TwoMLSSession+ClassicalCommit.swift`); `theirs.commit` at our own
	/// fold commit (`committingRound`); and `theirs.commit`/`mine.commit` at
	/// peer-commit apply (`applyFoldCommit`/`applyBind`'s own
	/// `canonicalize`, run immediately after this `adjudicate` call
	/// succeeds). Since `commit` throws on a rollback, each of those sites
	/// runs its own succession check (this `adjudicate`, or `commit` itself)
	/// BEFORE the commit applies to the group — a throw after the group has
	/// advanced would desync the group from the AS. The classical join-roster
	/// seam, by contrast, is WIRED: `joinClassicalOnly` (+Messaging) requires
	/// the Welcome to name the cross-party `0xFF02` PSK and pins the joined
	/// creator leaf against a mode-supplied expectation (`.missingCrossPartyPSK`
	/// / `.establishmentEnvelopeRequired` for a `.bare` join, `.establishmentCreatorMismatch`
	/// for an `.approved` one — `APQGroup.JoinCreatorMode`), so the
	/// AS needs no separate roster admission there. `joinPQHalf` remains
	/// credential-unadjudicated — it
	/// discards `PendingJoin.roster` without checking the creator against
	/// `theirs` — but is pinned instead by the KP′ hash commitment (`H(KP′)`)
	/// checked at `receive` / `pqBootstrapRespond`.
	///
	/// External senders need no seam here: the profile already rejects
	/// every external sender with `unsupportedSender` before any credential
	/// reaches this AS (this protocol is strictly 2-party and P2P — there is
	/// no external-sender path to begin with).
	func adjudicate(_ effects: MLS.RFC9420.CommitEffects, myLeaf: MLS.LeafIndex) throws {
		for event in effects.events {
			switch event {
			case .added(_, let presentation):
				try validateMember(presentation)
			case .credentialReplaced(let leaf, let old, let new):
				try validateSuccession(
					old: old, new: new, party: leaf == myLeaf ? mine : theirs)
			case .epochAdvanced, .updated, .removed, .membershipRemoved, .appDataUpdate,
				.customProposal:
				break
			}
		}
	}
}

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// `stateUpdate`'s pin-maintenance choke point (book group-rules.md rule
	/// 4): `auth` with both sequences' `pinned` recomputed to the normal
	/// form of what this session's live PQ leaves presently present
	/// (`livePQPresentedIDs`) — re-derived at every state-advancing call
	/// rather than tracked incrementally at each of the several sites that
	/// can move a PQ leaf. Total, not throwing: a leaf presenting a
	/// non-`.basic` credential is unreachable (every leaf this module mints
	/// or accepts advertises only `.basic`) — if it ever happened anyway,
	/// this leaves `pinned` at its PREVIOUS value rather than throwing from
	/// inside `stateUpdate`'s sticky-manifest section (`StateUpdate.swift`),
	/// where a throw after a PQ write-back has already landed on `self`
	/// would strand that move un-checkpointed.
	func pqPinnedAuth() -> AuthCore {
		guard
			let presented = try? livePQPresentedIDs(
				sendPQ: sendGroup?.pq, recvPQ: recvGroup?.pq)
		else { return auth }
		return auth.withPQPins(mine: presented.mine, theirs: presented.theirs)
	}
}
