import Foundation
import MLSCodec
import MLSProfileRFC9420

// MARK: - Credential Authentication Service (AS)
//
// A faithful port of the Rust `apq::authentication` credential-sequence AS
// (peer resource — logic ported, text not copied). This is Germ/TwoMLS
// policy, not RFC 9420- or draft-defined behavior: swift-mls has no
// Authentication Service (`NewSigningIdentity.swift`) and instead surfaces the
// credential change (its D17 `CommitEffect.credentialReplaced` seam, RFC 9420
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

/// One party's app-defined credential sequence (TwoMLS design, not RFC
/// 9420): the canonical `history` (oldest → newest, trimmed to
/// `credentialHistoryWindow`), the app-`authorize`d in-flight successors —
/// several candidates may be proposed, the one the peer commits becomes
/// canonical and the rest expire — and `pinned` ids held admissible past
/// window eviction (e.g. a leaf that still carries an otherwise-evicted
/// credential).
struct PartySequence: Sendable, Equatable {
	/// How many canonical credentials are retained for the catch-up rule —
	/// a lagging leaf may fast-forward to any already-canonical element
	/// within this many steps. Sessions rotate rarely; 8 is ample (matches
	/// the Rust reference's `CREDENTIAL_HISTORY_WINDOW`).
	static let credentialHistoryWindow = 8

	var history: [Data] = []
	var authorizedNext: [Data] = []
	var pinned: [Data] = []

	static func seeded(_ id: Data) -> PartySequence {
		var sequence = PartySequence()
		sequence.commit(id)
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

	/// Hold `id` admissible past window eviction (idempotent): widens
	/// `knownIDs` and lets an evicted `id` still serve as a successor
	/// `pred`, but it is never itself a valid `succ` (see `validSuccessor`),
	/// so a pin can never authorize a downgrade back onto it.
	mutating func pin(_ id: Data) {
		if !pinned.contains(id) { pinned.append(id) }
	}

	/// Retire a pin once nothing still carries it (idempotent).
	mutating func unpin(_ id: Data) {
		pinned.removeAll { $0 == id }
	}

	var pinnedIDs: [Data] { pinned }

	var knownIDs: [Data] { history + authorizedNext + pinned }

	/// Canonicalize `id`: it becomes the newest `history` element and every
	/// other in-flight authorization expires. The no-op check runs BEFORE
	/// clearing `authorizedNext` — a re-commit of the already-current id
	/// must not discard an authorization already in flight for the NEXT
	/// step.
	mutating func commit(_ id: Data) {
		if current == id { return }
		authorizedNext.removeAll()
		history.removeAll { $0 == id }
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
	/// `pinned` is never itself a valid `succ` (never in `history` or
	/// `authorizedNext`), so this can never authorize a downgrade onto it.
	func validSuccessor(pred: Data, succ: Data) -> Bool {
		if pred == succ { return true }
		let predPosition = position(pred)
		if predPosition == nil && !pinned.contains(pred) { return false }
		if authorizedNext.contains(succ) { return true }
		switch (predPosition, position(succ)) {
		case (_, nil): return false
		case (let pp?, let sp?): return sp > pp
		case (nil, _?): return true  // pred pinned+evicted (oldest) < any history succ
		}
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
struct AuthCore: Sendable, Equatable {
	var mine: PartySequence = PartySequence()
	var theirs: PartySequence = PartySequence()

	func knows(_ id: Data) -> Bool {
		mine.knownIDs.contains(id) || theirs.knownIDs.contains(id)
	}

	func validSuccessor(pred: Data, succ: Data) -> Bool {
		pred == succ || mine.validSuccessor(pred: pred, succ: succ)
			|| theirs.validSuccessor(pred: pred, succ: succ)
	}

	/// `MLS.RFC9420.CredentialPresentation`'s memberwise initializer is
	/// `internal` to `MLSProfileRFC9420`, so this session layer can never
	/// construct one itself — only receive one already built (a commit's
	/// `CommitEffect`, a join's `RosterEntry`). Establishment, which only
	/// ever has a raw `LeafNode.credential` to check, calls this overload
	/// directly; `adjudicate` calls the presentation overload below, which
	/// forwards here. (Deviation from the plan's single-signature form,
	/// forced by that access level — no information is lost, since identity
	/// admission never inspects `signatureKey`.)
	func validateMember(_ credential: MLS.RFC9420.Credential) throws {
		let id = try basicIdentifier(credential)
		guard knows(id) else { throw TwoMLSError.unknownIdentity }
	}

	func validateMember(_ presentation: MLS.RFC9420.CredentialPresentation) throws {
		try validateMember(presentation.credential)
	}

	/// RFC 9420 §5.3.1: "the AS MUST also verify that the set of presented
	/// identifiers in the new credential is valid as a successor to the set
	/// of presented identifiers in the old credential, according to the
	/// application's policy." `validSuccessor` above is that policy (TwoMLS
	/// design, not RFC-defined). Fail-closed: an unsupported credential
	/// throws rather than passing.
	func validateSuccession(
		old: MLS.RFC9420.CredentialPresentation, new: MLS.RFC9420.CredentialPresentation
	) throws {
		let oldID = try basicIdentifier(old.credential)
		let newID = try basicIdentifier(new.credential)
		guard validSuccessor(pred: oldID, succ: newID) else {
			throw TwoMLSError.invalidSuccession
		}
	}

	/// The consult point a future rotation slice calls at the
	/// `.credentialReplaced` seam. That slice also needs three consult
	/// points this method does NOT perform — documented here so it is not
	/// reinvented, but NOT wired: `theirs.authorize` at peer-proposal
	/// approval (`validateOfferedUpdate`, a 2nd reject site alongside
	/// `TwoMLSSession.queueProposal`, `TwoMLSSession+ClassicalCommit.swift`);
	/// `theirs.commit` at our fold commit (`committingRound`);
	/// `theirs.commit`/`mine.commit` at peer-commit apply
	/// (`applyFoldCommit`/`applyBind`). Nor is the join-roster seam wired: a
	/// later join (`joinClassicalOnly` in +Messaging, `joinPQHalf` in APQGroup)
	/// discards `PendingJoin.roster` without checking the creator against
	/// `theirs` — fail-closed today via the 0xFF02 cross-party PSK, so this is
	/// defense-in-depth for that slice.
	///
	/// External senders need no seam here: the profile already rejects
	/// every external sender with `unsupportedSender` before any credential
	/// reaches this AS (this protocol is strictly 2-party and P2P — there is
	/// no external-sender path to begin with).
	func adjudicate(_ effects: MLS.RFC9420.CommitEffects) throws {
		for event in effects.events {
			switch event {
			case .added(_, let presentation):
				try validateMember(presentation)
			case .credentialReplaced(_, let old, let new):
				try validateSuccession(old: old, new: new)
			case .epochAdvanced, .updated, .removed, .membershipRemoved, .appDataUpdate:
				break
			}
		}
	}
}
