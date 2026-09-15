import Foundation

/// The session layer's own error surface — wire-codec failures and the
/// deferred-half / two-party checks the combiner and profile have no seam
/// for. Combiner (`MLS.Combiner.Error`) and profile (`MLS.RFC9420.GroupError`)
/// errors are not wrapped here; they propagate as thrown.
public enum TwoMLSError: Error, Sendable, Equatable {
	// MARK: Cipher suite

	/// A `classicalProvider`/`pqProvider` passed to `TwoMLSIdentity.generate`,
	/// `TwoMLSSession.initiate`, or `TwoMLSSession.receive` did not match
	/// `TwoMLSSuite.classical`/`TwoMLSSuite.pq` — checked up front, before any
	/// state is claimed. Mirrors the Rust reference's own early
	/// `CipherSuiteMismatch` check (`session/mod.rs`), rather than surfacing a
	/// deep, opaque mls-rs error once construction is already underway.
	case cipherSuiteMismatch

	// MARK: Frame codec

	/// A length-prefixed section was empty where the wire format requires
	/// content (every `0x03` frame section; a message frame's proposal body).
	case emptySection
	/// A length prefix ran past the end of the buffer.
	case truncatedSection
	/// Bytes remained after every declared section was consumed.
	case trailingBytes
	/// The staple's leading tag byte matched none of this module's
	/// supported staple kinds.
	case unsupportedStapleTag(UInt8)
	/// The frame's leading tag byte was not `MESSAGE_FRAME_TAG`.
	case unsupportedFrameTag(UInt8)

	// MARK: Establishment / deferred-half verification

	/// `verifyAPQInfoDeferred` found Group_B's `APQInfo` inconsistent with a
	/// deferred (pq-less) pair — a wrong mode/suite, a bound `pqEpoch`, or an
	/// identity field that does not match the group it rides in.
	case deferredApqInfoMismatch
	/// A staple welcome not already joined carried a non-empty pq slot — a
	/// full (Group_A-shaped) welcome. Slice 1 only ever joins one of those via
	/// the explicit `receive()` entry point, never through `processIncoming`.
	case fullEstablishmentStapleUnsupported
	/// The Group_B welcome did not name the `0xFF02` cross-party PSK derived
	/// off this session's Group_A: the establishment PSK is the join's
	/// authenticity gate (`psk-binding.md`), so a welcome that does not bind it
	/// is refused rather than joined.
	case missingCrossPartyPSK
	/// A welcome staple's digest did not match the one already joined for
	/// this receive group — a different Group_B than the one this session is
	/// established against. The matching-digest case is an idempotent no-op,
	/// not this error.
	case unexpectedWelcome
	/// The frame's app section did not decode to `.privateMessage`.
	case appSectionNotPrivateMessage
	/// A decrypted app-section message was not `.application` content.
	case unprotectedContentNotApplication
	/// A PQ bootstrap side-band frame's leading tag byte matched neither
	/// `PQ_BOOTSTRAP_KP_TAG` (`0x13`) nor `PQ_BOOTSTRAP_WELCOME_TAG` (`0x15`).
	case unsupportedSideBandTag(UInt8)
	/// A decoded PQ bootstrap side-band frame's `MLS.RFC9420.Message` was not
	/// the case its tag promised (`.keyPackage` for `0x13`, `.welcome` for
	/// `0x15`).
	case malformedSideBandMessage

	// MARK: §A.3 PQ bootstrap

	/// `pqBootstrapRespond`'s `H(KP′)` did not match the commitment pinned at
	/// `receive`, or an incoming commitment was not the required 32 bytes.
	case bootstrapKPMismatch
	/// `pqBootstrapRespond` was called again after `sendGroup.pq` was already
	/// founded, and no retained `0x15` was available to idempotently
	/// re-return — a re-delivered `0x13` must never found a second
	/// Group_B.pq.
	case duplicateSideBand
	/// `verifyDeferredPQMirrorInfo` found the joined PQ half's mirror
	/// `APQInfo` inconsistent with Group_B's classical half — a wrong
	/// mode/suite, an unbound `pqEpoch`, a bound `tEpoch`, or an identity
	/// field the two halves disagree on.
	case deferredPQMirrorMismatch
	/// A host method requiring specific turn/establishment state
	/// (`pqBootstrapBegin`, `pqBootstrapRespond`, `pqBootstrapJoin`) was
	/// called outside that state.
	case sessionNotReady

	// MARK: §A.3 bind

	/// A `0x05` bind staple classified ahead of the receive group's live
	/// epoch (`applyBind`), or a licensed discharge's own re-check found its
	/// parked `owedBind` epochs no longer matching the live send groups
	/// (`prepareToEncrypt`).
	case epochDesync
	/// `applyBind`'s applied `CommitEffects` were not the bind's exact
	/// allow-listed shape — PQ-half `[epochAdvanced, appDataUpdate]` or
	/// classical-half `[epochAdvanced, updated(committer), appDataUpdate]` —
	/// an unexpected Add/Remove/credential replacement rode the bind.
	case invalidBindEffects
	/// A FULL bind commit applied without naming the PSK its half is bound to:
	/// the classical half must carry the `apq_psk` (`0xFF01`) exported off the
	/// post-commit PQ epoch, and the PQ half the injected external `S`
	/// (`LE64(epoch)‖group_id‖0x52`). draft-ietf-mls-combiner-02 makes the
	/// sender's inclusion a MUST; a commit that applies without it silently
	/// skips the fresh PQ entropy while its attestation claims a FULL commit
	/// (`psk-binding.md`, `protocol-flows.md`).
	case missingBindPSK

	// MARK: Two-party rules

	/// A group's non-blank leaf count was not exactly two.
	case notTwoParty(count: Int)
	/// A creation commit's proposal list was not exactly `[Add, PreSharedKey]`
	/// (classical-only) or `[Add, PreSharedKey, AppDataUpdate]` (full).
	case invalidCreationProposals
	/// A receive apply path's applied commit carried an inline proposal
	/// outside that path's exact permitted set
	/// (`TwoPartyRules.validateInlineProposals`) — an application or
	/// external PSK naming an id other than the ones that path expects, a
	/// resumption PSK (never permitted), or any proposal type/shape that
	/// path does not allow at all. Checked against the commit's raw
	/// proposal list before its effects are trusted.
	case unexpectedProposal

	// MARK: Session state

	/// `encrypt` was called with no proposal staged by `prepareToEncrypt`.
	case noPendingProposal
	/// `prepareToEncrypt`/`encrypt` requires both the send and receive groups
	/// (i.e. `isEstablished`).
	case notEstablished

	// MARK: §A.4 ratchet

	/// An inbound §A.4 leg's epoch was strictly below the receiver's classical
	/// epoch — a stale re-delivery, rejected by the epoch floor rather than
	/// processed.
	case staleFrame
	/// `CTSeal.open` failed to recover `S` — a bounds-checked `wireCT` decode
	/// failure, or the AEAD open itself. The AEAD open is the explicit reject
	/// for a stale/misdirected CT: ML-KEM decapsulation alone never throws on a
	/// mismatched ciphertext, it just returns the wrong bytes. Also
	/// `Invitation.openInitial`'s HPKE-open failure, same reasoning: a wrong
	/// key, tampered ciphertext, or downgrade-mismatched `envelopeFramingAAD`
	/// only ever surfaces at the AEAD (wire-format.md, "The seal binds the
	/// declared suite via untransmitted AAD").
	case decryptionFailed

	// MARK: §A.5 PQ re-key (mechanical)

	/// A `0x1B` Upd′ did not verify as a peer `.update` proposal
	/// (`pqRekeyRespond`) — a different proposal type, a commit smuggled
	/// behind the tag, or one framed by this session's own leaf.
	case rekeyProposalRejected
	/// `pqRekeyApply`'s applied `CommitEffects` were not the mechanical rekey
	/// Commit's exact allow-listed shape — `[epochAdvanced, updated(proposer),
	/// updated(committer)]` with the two leaves distinct — an unexpected
	/// Add/Remove/credential replacement/membership removal/`AppDataUpdate`
	/// rode the Commit′. A `.credentialReplaced` is part of this rejection
	/// (enforced by `validateRekeyCommitEffects`): the PQ arms run no AS
	/// adjudication, so an unadjudicated presentation change is refused
	/// outright. When the PQ catch-up (Chunk 2) lands, replace the throw with
	/// `auth.adjudicate` on both PQ arms and admit a `.credentialReplaced`.
	case invalidRekeyEffects

	// MARK: §5 classical FOLD (slice 5, no credential rotation)

	/// `queueProposal` found no matching/valid offer: no `offeredProposal` was
	/// outstanding, the supplied digest did not match it, the offered message
	/// did not verify as a peer `.update` proposal (`.member` sender, not this
	/// session's own leaf), its leaf's credential/signature key differed from
	/// the current one (slice 5 rejects any `.credentialReplaced` fold —
	/// rotation is a later slice), or its verified leaf's `.basic` identity
	/// did not match the frame's unauthenticated `proposing` claim (§11 MF5).
	/// A digest mismatch is this error too, never a silent no-op.
	case proposalRejected
	/// A fold-carrying commit's applied `CommitEffects` were not its exact
	/// allow-listed shape — bare fold `[epochAdvanced, updated(proposer),
	/// updated(committer)]`, or the same plus `appDataUpdate` when a bind rode
	/// the same commit — an unexpected Add/Remove/`.credentialReplaced`/
	/// `membershipRemoved` rode it.
	case invalidFoldEffects

	// MARK: Credential authentication (AS)

	/// A credential's `CredentialType` was not `.basic` — the only type this
	/// session layer's leaves ever advertise
	/// (`TwoMLSIdentity.leafCapabilities`).
	case unsupportedCredential
	/// A credential's Basic identifier is not known to either party's
	/// `PartySequence` — absent from `history`, `authorizedNext`, and
	/// `pinned` alike (the Authentication Service's admission check, RFC
	/// 9420 §5.3.1).
	case unknownIdentity
	/// A credential succession failed the Authentication Service's successor
	/// check (RFC 9420 §5.3.1): the new identifier is not a valid successor
	/// to the old one under either party's sequence. Fail-closed. No
	/// `.externalSender` case here: the profile already rejects every
	/// external sender with `unsupportedSender` before a credential ever
	/// reaches this AS (this protocol is strictly 2-party and P2P, with no
	/// external-sender path).
	case invalidSuccession
	/// The peer's presented identity does not match the party actually bound
	/// at establishment: at `receive`, the caller-supplied
	/// `theirClassicalKeyPackage` names a different party than the creator leaf
	/// the Welcome actually joined; at `initiate`, the peer's classical and PQ
	/// `KeyPackage` halves present different identities. Rust's
	/// `RemoteIdentityMismatch`. Distinct from `.unknownIdentity` (the AS's
	/// membership-admission check) — this is the establishment identity binding.
	case remoteIdentityMismatch
	/// `commit` was asked to canonicalize a credential already retired for the
	/// party — still in its `history` (but not the current head) or `pinned` — a
	/// rollback to a retired identity. In this protocol every identity is a
	/// freshly generated key, so a recurrence is never legitimate; `commit`
	/// rejects it (fail-closed, before any state change) rather than re-promoting
	/// it. The check is bounded to `history` + `pinned`: an id evicted past the
	/// window AND unpinned is no longer remembered, so a deep recurrence is ruled
	/// out by the always-fresh-key invariant, not by this check.
	case credentialRollback

	// MARK: Classical principal rotation (slice 6)

	/// The custody resolver (`classicalSigningKey(presenting:)`) found no
	/// principal — founding identity or the single in-flight
	/// `rotationCandidate` — whose `signatureKey` matches what a classical
	/// leaf currently presents; fail-closed rather than sign with the wrong
	/// key. Also thrown by `prepareToEncrypt(rotating:)` for an empty
	/// candidate id, or for a `rotating` that names this session's OWN
	/// recv-leaf CURRENT id: that "rotation" could never canonicalize
	/// (`PartySequence.commit`'s own `current == id` early return is a
	/// no-op), so admitting it would leave the offer `.pending` forever.
	case credentialUnknown
	/// `prepareToEncrypt(rotating:)` was asked to author a SECOND classical
	/// rotation while the outstanding `rotationCandidate` is either still
	/// foldable by the peer OR has already canonicalized (F2's
	/// one-generation cap). The wedge relaxation
	/// (`recvGroup.classical`'s epoch has moved past the epoch the
	/// outstanding candidate's `Upd` was staged at) only ever lets a DEAD
	/// candidate — one that never canonicalized (absent from
	/// `auth.mine.history`) — be replaced; once a rotation HAS
	/// canonicalized, a second one must wait for a later slice's PQ
	/// catch-up rather than silently dropping the converged candidate's
	/// key (which both classical leaves may already present). Naming the
	/// SAME candidate again is idempotent, not this error.
	case rotationInFlight

	// MARK: Session archive (slice 8a)

	/// `TwoMLSSession.restore`'s decoded input failed validation: a leading
	/// field (`version`/`classicalSuite`/`pqSuite`/`kind`) didn't match what
	/// was expected of it; a Core and Checkpoint pair disagreed on session
	/// identity (client id, signature key, or either classical group id) or,
	/// when the Core is newer, on the PQ-epoch manifest; or a decode-time
	/// invariant (the pinned bootstrap commitment's 32-byte length) failed.
	/// Fail-closed: `restore` never partially reconstructs a session off a
	/// blob it cannot fully trust.
	case archiveInvalid

	// MARK: Invitations (slice 8b)

	/// `Invitation.receive` rejected a welcome its processed-welcome ledger
	/// or consumed-remote set already recorded: a re-delivery of the exact
	/// same welcome (`SHA-256(welcome)` already keys the processed-welcome
	/// table), or a second, different welcome from an already-consumed
	/// remote. Raised before any table insert or consume, so a rejected
	/// welcome claims nothing (book session-lifecycle.md, "Invitations &
	/// replayed initial frames").
	case duplicateWelcome
	/// `Invitation.receive` was called on a single-use invitation whose
	/// combiner key package's private material was already dropped by an
	/// earlier accepted welcome (book concepts.md's single-use/last-resort
	/// distinction).
	case invitationSpent
	/// `Session.forwarded(spawnToken:)` was called with a token that does
	/// not match the one this session was actually spawned under — a
	/// mis-route (book session-lifecycle.md, "Invitations & replayed initial
	/// frames").
	case misroutedSpawnToken

	// MARK: §A.1 HPKE establishment envelope (slice 9, PR3b)

	/// `EstablishmentEnvelope.decodePlaintext` found an establishment
	/// vector (`ESTABLISHMENT_VECTOR_TAG`) carrying neither `appPayload` nor
	/// `welcome` — the either/or wire rule requires at least one
	/// (protocol-flows.md, "one envelope, two shapes (either/or)").
	case neitherAppPayloadNorWelcomePresent
	/// An HPKE-opened §A.1 plaintext's leading tag matched neither
	/// `ESTABLISHMENT_VECTOR_TAG` (`0x07`) nor the parallel bootstrap-KP tag
	/// (`0x13`, `Frames.pqBootstrapKPTag`).
	case unsupportedEstablishmentTag(UInt8)
	/// `TwoMLSSession.pendingOutbound()` was called with no retained peer
	/// key package to re-seal against: the initiator has already joined
	/// Group_B (`initialTheirKP` cleared at `joinGroupBIfNeeded`), or this
	/// session is a responder (which never retains one).
	case noPendingEstablishmentEnvelope
}
