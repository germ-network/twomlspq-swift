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
	/// A §A.1 Welcome/KeyPackage slot (the `0x01` welcome halves, the return
	/// key package) held bytes that did not decode as the RFC 9420
	/// `MLSMessage` wrapper its slot promised, or decoded to the wrong case —
	/// including a bare (unwrapped) struct, since every deployed peer emits
	/// the wrapped form. Folds swift-mls's `MLS.CodecError`/
	/// `MLS.RFC9420.WireError` at these decode sites.
	case malformedEstablishmentMessage

	// MARK: §A.3 PQ bootstrap

	/// `pqBootstrapRespond`'s `H(KP′)` did not match the commitment pinned at
	/// `receive`, or an incoming commitment was not the required 32 bytes.
	case bootstrapKPMismatch
	/// `pqBootstrapRespond` was called again after `sendGroup.pq` was already
	/// founded, and its own §A.3 round was no longer open (`pqInflight` had
	/// moved past `.bootstrapResponded`, or was never that round to begin
	/// with) — it re-serves the retained `0x15` only while that round is
	/// still outstanding; a re-delivered `0x13` must never found a second
	/// Group_B.pq, and once the round has closed nothing is re-emitted for
	/// any inbound bytes at all.
	case duplicateSideBand
	/// `verifyDeferredPQMirrorInfo` found the joined PQ half's mirror
	/// `APQInfo` inconsistent with Group_B's classical half — a wrong
	/// mode/suite, an unbound `pqEpoch`, a bound `tEpoch`, or an identity
	/// field the two halves disagree on.
	case deferredPQMirrorMismatch
	/// A host method requiring specific turn/establishment state
	/// (`pqBootstrapBegin`, `pqBootstrapRespond`, `pqBootstrapJoin`) was
	/// called outside that state. Also `installEstablishmentEnvelope`'s
	/// fail-closed catch-all (slice 11): not owed, and `currentStaple` is
	/// not the bare `0x01` shape either — an envelope installed onto a
	/// session that never owed one, or one whose staple already moved past
	/// establishment.
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
	/// behind the tag, or one framed by this session's own leaf. Also the
	/// respond-side id gate's own failures, all before any commit is spent:
	/// the proposed leaf's id is not already-canonical (or is a rollback)
	/// per `validatePQLeafMove`; either leaf's credential is not `.basic`;
	/// or a present C1 announced id (the Upd′'s authenticated data)
	/// disagrees with the proposed leaf's id.
	case rekeyProposalRejected
	/// `pqRekeyApply`'s applied `CommitEffects` were not the mechanical rekey
	/// Commit's exact allow-listed shape — `[epochAdvanced, moved(proposer),
	/// moved(committer)]`, two DISTINCT moved leaves (each `.updated` XOR
	/// `.credentialReplaced`) — an unexpected Add/Remove/membership
	/// removal/`AppDataUpdate` rode the Commit′ (`validateRekeyCommitEffects`,
	/// shape only). A `.credentialReplaced` moving a leaf to a non-canonical
	/// id is a DIFFERENT error — `.invalidSuccession`, from the id-based
	/// backstop (`adjudicatePQRekeyEffects`/`validatePQLeafMove`,
	/// `CredentialAuthentication.swift`) — since the PQ arms still run no
	/// `AuthCore.adjudicate` of their own; that backstop checks the id
	/// against the classical `AuthCore` (D2) instead.
	case invalidRekeyEffects

	// MARK: §5 classical FOLD (slice 5, no credential rotation)

	/// `queueProposal` found no matching/valid offer: no `offeredProposal` was
	/// outstanding, the supplied digest did not match it, the offered message
	/// did not verify as a peer `.update` proposal (`.member` sender, not this
	/// session's own leaf), or its verified leaf's `.basic` identity did not
	/// match the frame's unauthenticated `proposing` claim (§11 MF5). Also
	/// thrown by `validateOfferedUpdate`'s own leaf checks, run against every
	/// current member (mirroring the roster a real commit validates against):
	/// the embedded replacement leaf's own RFC 9420 section 7.3 signature
	/// (`LeafNode.verifySignature`) and policy (`LeafNode.validatePolicy` —
	/// capabilities, credential-type mutual support, `required_capabilities`,
	/// an unchanged encryption key). A digest mismatch is this error too,
	/// never a silent no-op.
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
	/// to the old one under the moved leaf's OWN party's sequence — `mine`
	/// for the committer's own leaf, `theirs` for the peer's, never checked
	/// against the other party's. Fail-closed. No
	/// `.externalSender` case here: the profile already rejects every
	/// external sender with `unsupportedSender` before a credential ever
	/// reaches this AS (this protocol is strictly 2-party and P2P, with no
	/// external-sender path). Also thrown by `joinGroupB`'s (slice 11)
	/// defense-in-depth adoption screen: a joined creator id that is already
	/// one of MY OWN known ids (`auth.mine.knownIDs`) is never adopted, even
	/// if a host blunder handed it back as the dedicated principal — a
	/// same-id "succession" onto myself can never be legitimate. Also thrown
	/// by the §A.5 PQ rekey's id-based counterpart
	/// (`validatePQLeafMove`/`adjudicatePQRekeyEffects`, +Rekey.swift): a PQ
	/// leaf move to a non-canonical id, caught at `pqRekeyApply` (or, as a
	/// backstop, at `pqRekeyRespond` after the Commit′ is built) — the PQ arms
	/// have no persisted sequence of their own, so this checks the id against
	/// the classical `AuthCore` (D2) rather than calling `AuthCore.adjudicate`.
	case invalidSuccession
	/// The peer's presented identity does not match the party actually bound
	/// at establishment: at `receive`, the caller-supplied
	/// `theirClassicalKeyPackage` names a different party than the creator leaf
	/// the Welcome actually joined; at `initiate`, the peer's classical and PQ
	/// `KeyPackage` halves present different identities. Also thrown when the
	/// named peer is this device's OWN identity — Germ AS policy (two
	/// distinct principals), not RFC 9420- or book-mandated: `initiate`
	/// rejects "their" naming the initiator's own id before any group is
	/// built; `receive` rejects a joined Group_A creator whose credential
	/// names the receiving identity's own id, read off the joined tree
	/// itself, not a claim. Rust's `RemoteIdentityMismatch`. Distinct from
	/// `.unknownIdentity` (the AS's membership-admission check) — this is
	/// the establishment identity binding.
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

	/// A group's own stored key set (`GroupKeySet` — `current` plus
	/// `pending`, one per group) has no key for a leaf presentation this
	/// session needs to sign with or promote: the live choke point
	/// (`assertLeafKeysPresented`) finds a group whose leaf doesn't match
	/// its `current`, one of the four per-group signing accessors finds no
	/// `current` at all, or `GroupKeySet.promoted(presenting:id:)` is asked
	/// to promote a presentation that isn't held at either `current` or
	/// `pending[id]`. Fail-closed rather than sign with the wrong key, or
	/// promote to one this session never staged. Also thrown by
	/// `prepareToEncrypt(rotating:)` for an empty candidate id, or for a
	/// `rotating` that names this session's OWN recv-leaf CURRENT id: that
	/// "rotation" could never canonicalize (`PartySequence.commit`'s own
	/// `current == id` early return is a no-op), so admitting it would
	/// leave the offer `.pending` forever.
	case credentialUnknown
	/// `prepareToEncrypt(rotating:)` was asked to author a SECOND classical
	/// rotation while the outstanding `rotationCandidate` is either still
	/// foldable by the peer OR has already canonicalized (F2's
	/// one-generation cap). The wedge relaxation
	/// (`recvGroup.classical`'s epoch has moved past the epoch the
	/// outstanding candidate's `Upd` was staged at) only ever lets a DEAD
	/// candidate — one that never canonicalized (absent from
	/// `auth.mine.history`) — be replaced; once a rotation HAS canonicalized,
	/// a second one must still wait, rather than silently dropping the
	/// converged candidate's key (which both classical leaves may already
	/// present). The §A.5 id-based catch-up this module now accepts
	/// (`validatePQLeafMove`) lets a lagging RECV-PQ leaf fast-forward to an
	/// already-canonical id when a round is opened for it — but that is a
	/// PQ-leaf move, not a second classical rotation's sync point: the
	/// classical AS tracks no per-generation PQ state of its own to wait on.
	/// Naming the SAME candidate again is idempotent, not this error: it
	/// re-stages under the SAME key and unconditionally refreshes
	/// `proposedAtRecvEpoch` to the CURRENT recv epoch, so a further
	/// same-candidate attempt keeps throwing this error until the peer's
	/// fold actually moves that epoch on. Also thrown directly by
	/// `GroupKeySet.stage(_:for:)` whenever a target already holds a
	/// `pending` entry and the newly offered key is a DIFFERENT one — a
	/// key a proposal already on the wire may still name is never
	/// silently overwritten, independent of the classical-rotation-cap
	/// path above.
	case rotationInFlight

	// MARK: Session archive (slice 8a)

	/// `TwoMLSSession.restore`'s decoded input failed validation: a leading
	/// field (`version`/`classicalSuite`/`pqSuite`/`kind`) didn't match what
	/// was expected of it; a Core and Checkpoint pair disagreed on session
	/// identity (client id, signature key, or either classical group id) or,
	/// when the Core is newer, on the PQ-epoch manifest — either PQ epoch,
	/// or either PQ key set's own fingerprint, which can diverge even when
	/// the epoch alone still agrees (`PQEpochManifest`'s own doc explains
	/// why); a decode-time invariant (the pinned bootstrap commitment's
	/// 32-byte length) failed; or the restored `leafKeys` failed
	/// `validateLeafKeys`'s semantic checks against the rest of the
	/// restored state — an existing group's own leaf not presenting its
	/// stored `current`, a reservation not matching `identity`, a
	/// staged/pending/parked Update naming a key `leafKeys` doesn't hold,
	/// or an outstanding rotation candidate / rule-4 catch-up target
	/// missing its expected `pending` entry. Fail-closed: `restore` never
	/// partially reconstructs a session off a blob it cannot fully trust.
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

	// MARK: App binding (0xF0A2, group-rules.md rule 8)

	/// `AppBinding.read` found more than one `0xF0A2` extension, or one
	/// present but undecodable (truncation or trailing bytes — a corrupt
	/// binding must never read back as "unbound", mirroring `APQInfo.read`'s
	/// same rule); `verifyAppBinding` found a group's binding did not match
	/// the caller's exact expectation (`Some` requires byte-equality, `None`
	/// requires the group to carry none); `verifyPQHalfUnbound` found a PQ
	/// half carrying one (the binding lives on the classical halves only);
	/// or an EMPTY binding was supplied to `initiate`/`establishClassicalOnly`
	/// or as an expectation to `receive`/`Invitation.receive` (empty is
	/// reserved-invalid — `None` is the deliberate unbound state).
	case appBindingMismatch
	/// Port-side defense-in-depth: swift-mls does not enforce mls-rs's
	/// per-client GroupContext-extension leaf-capability requirement, so this
	/// module checks it itself whenever a group is about to carry (or was
	/// joined carrying) an `AppBinding` — a founder leaf, an added peer leaf,
	/// or a joined creator leaf that does not advertise the `AppBinding`
	/// extension type (`0xF0A2`) in its `Capabilities.extensions`. An
	/// old-capability key package cannot be added to (or trusted as creator
	/// of) a binding-carrying group.
	case appBindingLeafUnadvertised
	/// A peer leaf entering, or found as creator of, one of this session's
	/// groups does not advertise the `APQInfo` extension type (`0xF0A1`) in
	/// `Capabilities.extensions` and the `AppDataUpdate` proposal type
	/// (`0x0008`) in `Capabilities.proposals` (book `wire-format.md`: "Every
	/// occupied leaf must advertise the `APQInfo` extension... and the
	/// `AppDataUpdate` proposal... a leaf that cannot support them is
	/// rejected rather than silently degraded"). Rejected before any state
	/// changes; the peer is non-conforming. Also thrown by the migration
	/// mint for any occupied leaf of the four restored trees (or either half
	/// of a retained `initialTheirKP`) that fails the same check — and, for
	/// a session profile (book group-rules.md rule 9), by a founder, peer or
	/// replacement leaf that does not keep advertising a recorded profile's
	/// extension type.
	case leafCapabilityUnadvertised

	// MARK: Session profile (book group-rules.md rule 9)

	/// A welcome's recorded session profile is not the one both classical
	/// key packages advertise, a return welcome does not carry the
	/// initiator's recorded profile back unchanged, a PQ half records one,
	/// or a `GroupContext` profile record is duplicated or carries
	/// non-empty contents. Raised before any invitation state is claimed.
	case sessionProfileMismatch

	// MARK: Attachment CEK export (value-engine parity)

	/// `exportAttachmentCEKSend`/`exportAttachmentCEKRecv` found no `0xFF03`
	/// attachment component ledgered at the epoch asked for. Recv-side: an
	/// epoch outside `attachmentLedgerWindow`'s retention, or one that was
	/// simply never captured. Send-side reaching this at all would mean a
	/// gap in the send-capture sites — every send-classical commit and
	/// group-creation site ledgers the current epoch before this could ever
	/// be asked for it.
	case attachmentComponentUnavailable

	// MARK: Born-dedicated principal + contract-26 handoff (slice 11)

	/// `Invitation.receive`/`TwoMLSSession.receive` was called with a
	/// non-nil, empty `newClientID` — the reserved slot the dedicated
	/// principal is minted under. Empty is reserved-invalid, matching every
	/// other identity/binding field this module rejects that way. Also
	/// thrown when a non-nil `newClientID` equals the remote/initiator's own
	/// id (`peerID`, read off the just-joined Group_A creator leaf) —
	/// defense-in-depth: a dedicated principal can never legitimately be
	/// the very party it is meant to be dedicated FOR.
	case invalidClientID
	/// A frame-producing method was called while the acceptor still owes
	/// the contract-26 signed handoff envelope (`owesEstablishmentEnvelope`)
	/// — the non-emittable gate. Also `installEstablishmentEnvelope`'s
	/// own empty-argument case, and a `.bare`-mode Group_B join whose
	/// creator differs from the invitation identity (protocol-flows.md:428
	/// — the join needs the envelope before it can trust a different
	/// creator).
	case establishmentEnvelopeRequired
	/// `installEstablishmentEnvelope` was handed envelope bytes different
	/// from the one already installed — a corrupt or conflicting caller,
	/// never a legitimate re-send (an idempotent re-install of the SAME
	/// bytes is a no-op, not this error).
	case establishmentEnvelopeConflict
	/// `processIncomingApproved`'s approved Group_B join landed on a
	/// creator different from the `expectedCreator` the caller pinned — the
	/// approval names a specific dedicated principal, and a join that
	/// disagrees with it is discarded whole, never partially trusted.
	case establishmentCreatorMismatch

	// MARK: Migration inputs on stored per-group signing keys

	/// A staple's commit referenced an own-offer ref not in the framed
	/// store, and no `ownOfferWindow` blob was supplied to resolve it.
	/// Retryable: nothing changed, and this is thrown only AFTER the
	/// staple's framing signature and membership tag have verified — never
	/// for a forged commit. Load the blob and retry; an NSE may defer
	/// without ever loading it.
	case ownOfferWindowRequired
	/// A supplied `ownOfferWindow` blob lacked a ref the staple's commit
	/// named. Terminal for the session's receive path: the peer re-staples
	/// that commit until its next one, which builds on it. Thrown only
	/// after authentication, same as `.ownOfferWindowRequired`.
	case ownOfferUnavailable
	/// A PQ side-band door (`pqBootstrapJoin`, `pqRatchetBind`,
	/// `pqRekeyApply`) was called while the migrated deployed engine's own
	/// trigger had already wedged past its point of no return
	/// (`pqSideBandWedged`). Never blocks owed-bind discharge or classical
	/// messaging; the book's exit is re-establishment.
	case pqSideBandWedged
	/// A signing site's group is in the migrated deployed engine's
	/// no-custody set (`noCustody`) — this session presently holds no
	/// signing key for that group. A no-custody classical group can only
	/// receive; a no-custody PQ group's own driver stops that door.
	case leafCustodyUnavailable
}
