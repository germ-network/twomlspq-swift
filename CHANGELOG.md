# @germ-network/twomlspq-swift

## 0.3.0

### Minor Changes

- [#85](https://github.com/germ-network/twomlspq-swift/pull/85) [`5fd25e6`](https://github.com/germ-network/twomlspq-swift/commit/5fd25e6b9548ffe945d3eda7d3cc216e88b0ecc4) Thanks [@germ-mark](https://github.com/germ-mark)! - `initiate` now registers the §A.3 round itself, around the pre-committed KP′. A new public `pqBootstrapEnvelope()` returns that parked KP′ sealed as its own §A.1 envelope — a fresh ephemeral on every call, going `nil` once the Group_B join hands off and `pqPendingOutbound()` carries it instead. Calling `pqBootstrapJoin` before that join now throws `.sessionNotReady` (retriable) rather than `.notEstablished`. Restore now accepts a pre-join initiator archive that carries the registered round, and allows only no round or that same round for such an archive.

- [#66](https://github.com/germ-network/twomlspq-swift/pull/66) [`ef9c996`](https://github.com/germ-network/twomlspq-swift/commit/ef9c996f7a9acec4742fe87db510c9d64add6ab6) Thanks [@germ-mark](https://github.com/germ-mark)! - `Invitation.receive`'s return tuple gains a `baseline` element — the spawned session's baseline checkpoint `StateUpdate`, so an acceptor is restorable before its first PQ round (source-breaking for positional two-element destructuring). Add `TwoMLSSession.proposalContext()` and `QueuedProposal.context` — the raw proposal-context digests a host binds proposals to, matching the reference implementation. No wire or behavior change.

- [#81](https://github.com/germ-network/twomlspq-swift/pull/81) [`8f79737`](https://github.com/germ-network/twomlspq-swift/commit/8f797376351c6776941c1b18ef2bd4b2cf99af17) Thanks [@germ-mark](https://github.com/germ-mark)! - An id-changing §A.5 `Upd′` now carries the handed-off id in its authenticated data (C1), matching the deployed Rust engine's own trigger. A session with no recorded profile runs deployed-compatible. A key-only `Upd′` still carries none. Receive already cross-checked a present value against the proposed leaf's id; that is unchanged.

- [#79](https://github.com/germ-network/twomlspq-swift/pull/79) [`90cc5b1`](https://github.com/germ-network/twomlspq-swift/commit/90cc5b1e31142ff4a0c8b996f9d23a17e27aeda8) Thanks [@germ-mark](https://github.com/germ-mark)! - Every group a party founds — `initiate`'s two Group_A halves, `receive`'s Group_B classical half, and `pqBootstrapRespond`'s Group_B.pq half at §A.3 — now founds on a freshly minted leaf, never a reused KeyPackage leaf. A born-dedicated acceptor's rule-4 catch-up key is likewise minted independently of its founding leaf. `pqBootstrapRespond` now founds under the acceptor's then-canonical credential id rather than its founding one.

  A pre-A.3 acceptor's send-PQ no longer carries a reservation: `LeafKeys`/`MigratedLeafKeys` restore and mint now require the canonical present-but-empty shape (`current: nil, pending: []`) for it, and the migration mint drops a supplied non-nil reservation there rather than requiring or rejecting one. A migrator should stop emitting that reservation once this ships.

  Archives from this version are one-way: a pre-A.3 acceptor's archive written under this shape fails an earlier build's restore, and an earlier build's archive in that state fails this build's restore.

- [#81](https://github.com/germ-network/twomlspq-swift/pull/81) [`eec40e7`](https://github.com/germ-network/twomlspq-swift/commit/eec40e7ae7946bc500f98aaddbab720685926d0f) Thanks [@germ-mark](https://github.com/germ-mark)! - Both §A.5 PQ legs now mint a fresh signature key for their own leaf: `pqRekeyBegin` stages one in recv-PQ, promoted on apply; `pqRekeyRespond` presents a fresh send-PQ key directly, under the SAME credential id it already presents. No wire-format change and no archive shape change.

- [#81](https://github.com/germ-network/twomlspq-swift/pull/81) [`bc3ac35`](https://github.com/germ-network/twomlspq-swift/commit/bc3ac35768a50acb174fded51288ccaa778dd45b) Thanks [@germ-mark](https://github.com/germ-mark)! - Every send-classical committing round — a fold, a bind discharge, or a catch-up — now mints a fresh signature key and applies it immediately; the group never holds a pending catch-up key. Restore rejects a non-empty send-classical `pending`, and the migration mint drops any supplied entries there rather than carrying them through. Archives are one-way: an earlier build mid-rotation, with a send-classical `pending` entry, no longer restores under this build.

- [#81](https://github.com/germ-network/twomlspq-swift/pull/81) [`7548616`](https://github.com/germ-network/twomlspq-swift/commit/754861688606e355aec644ba933613b29b0ed54e) Thanks [@germ-mark](https://github.com/germ-mark)! - Every own-leaf Update offer — routine or catch-up — now mints a fresh signature key and signs under it, instead of repeating the leaf's current key. `DecryptResult.newSender` and `ownCredentialCanonicalized` fire only when a leaf's credential id actually changes; a same-id key-only move is accepted and surfaces neither flag.

- [#86](https://github.com/germ-network/twomlspq-swift/pull/86) [`3deec8e`](https://github.com/germ-network/twomlspq-swift/commit/3deec8e7cc0cfa6002e5b049d06e04567f854710) Thanks [@germ-mark](https://github.com/germ-mark)! - A pre-join initiator can now attach a host app payload with the new `setInitialAppPayload`, making the establishment envelope self-sufficient: once set, `pendingOutbound()` seals the payload alone instead of the bare welcome and return key package, and a later call replaces an earlier payload. The engine does not interpret the payload; the host is responsible for making it carry everything the acceptor needs.

- [#78](https://github.com/germ-network/twomlspq-swift/pull/78) [`b44fc35`](https://github.com/germ-network/twomlspq-swift/commit/b44fc35dca0771fb8a336816c5f4e4548cbbf2d0) Thanks [@germ-mark](https://github.com/germ-mark)! - Every peer leaf a session admits — folded, offered, joined, or found as creator, on either the classical or the PQ half — must now advertise both the `APQInfo` extension and the `AppDataUpdate` proposal (book `wire-format.md`), or it is rejected with the new `TwoMLSError.leafCapabilityUnadvertised` before any state changes. A migrated session's mint applies the same check to every occupied leaf of the restored trees and to a retained `initialTheirKP`, refusing to mint a session around a capability-less peer leaf.

- [#75](https://github.com/germ-network/twomlspq-swift/pull/75) [`d130bb4`](https://github.com/germ-network/twomlspq-swift/commit/d130bb4cfe2359e57a0faf8f2eaac682038ee89f) Thanks [@germ-mark](https://github.com/germ-mark)! - Migration inputs on stored per-group signing keys: `MigratedLeafKeys` (authoritative per-group keys, superseding the temporary owner-keyed conversion when supplied), `MigratedOwnOfferWindow`/`SessionMigration.mintOwnOfferWindow` (an on-demand own-Update-offer blob, never the session archives), and `MigratedDeployedState` (the deployed engine's PQ-wedge and no-custody flags), all wired into `SessionMigration.mintArchive(deployedState:)`. `processIncoming`/`processIncomingApproved` gain a defaulted `ownOfferWindow:` blob parameter to resolve a staple that names an offer outside the framed store. `TwoMLSSession` gains the read-only `pqSideBandWedged`, `noCustody`, `canSend`, and `ownOfferWindowID` queries.

  The own-leaf catch-up generalizes beyond rotation and born-dedicated custody: any own leaf lagging behind its party's current canonical credential catches up via that group's own `pending[current id]`, in every group, not just the ones native code used to cover — fixing a latent brick where a migrated or otherwise-lagging session that won a rotation and then rotated again natively could lose its catch-up key.

  Mint now drops an unverifiable parked §A.5 `Upd'` at import rather than minting a session that can never apply its own re-key round.

  Four new `TwoMLSError` cases — `ownOfferWindowRequired`, `ownOfferUnavailable`, `pqSideBandWedged`, `leafCustodyUnavailable` — source-breaking for an exhaustive switch over `TwoMLSError`.

  Requires swift-mls 0.1.6.

- [#81](https://github.com/germ-network/twomlspq-swift/pull/81) [`6676cca`](https://github.com/germ-network/twomlspq-swift/commit/6676cca458a1c2a9fe430a2c269bd976a3c4438b) Thanks [@germ-mark](https://github.com/germ-mark)! - `prepareToEncrypt` now proposes at most one Update offer per (recv epoch, target) pair, repeating the identical proposal bytes on every frame of that epoch instead of minting or staging a new one each call. A routine offer and an outstanding rotation candidate's offer coexist as two independent targets; a plain frame after a rotation offer keeps re-sending the routine offer, not the candidate's. `stagedUpdates` and the underlying archive stay bounded by the number of distinct targets used in the epoch rather than the number of `prepareToEncrypt` calls.

- [#81](https://github.com/germ-network/twomlspq-swift/pull/81) [`2c0f629`](https://github.com/germ-network/twomlspq-swift/commit/2c0f629026ccb4bb49b8673058557cf2af71d0b8) Thanks [@germ-mark](https://github.com/germ-mark)! - `pqRekeyBegin`'s Upd′ now carries our current canonical recv-PQ id whenever that leaf lags, staging a freshly minted key under `recvPQ.pending[that id]` until the peer's Commit′ applies it. A held migration-supplied catch-up key for the same target is replaced, never consumed. A non-lagging leaf still proposes key-only, as before.

- [#79](https://github.com/germ-network/twomlspq-swift/pull/79) [`05b9e84`](https://github.com/germ-network/twomlspq-swift/commit/05b9e84cdd3d19a43f92aed6c566fb4ea29f6684) Thanks [@germ-mark](https://github.com/germ-mark)! - **Breaking:** removed `TwoMLSIdentity.generate(clientID:signingKey:signatureKey:pqSigningKey:pqSignatureKey:classicalProvider:pqProvider:)` and `TwoMLSIdentity.freshPQKeyPackage(pqProvider:)`. Neither has any known caller.

  `Principal` no longer holds or shares a signing key across the invitations and sessions it mints: every `TwoMLSIdentity` `Principal.generateInvitation`/`TwoMLSSession.initiate(principal:)` produces now gets its own fresh, independent classical and PQ signing pair. KP′ (the §A.3 bootstrap KeyPackage) is now `identity`'s own PQ half directly, rather than a separately minted key package — one fewer key in play, and `EstablishResult.returnKeyPackage` on a born-dedicated acceptor is now the invitation's classical KeyPackage rather than the dedicated principal's (documented as initiator-only; no known caller reads it on the acceptor path).

- [#71](https://github.com/germ-network/twomlspq-swift/pull/71) [`13d1e10`](https://github.com/germ-network/twomlspq-swift/commit/13d1e102bd97212de14d976a70fa28ff97e46f31) Thanks [@germ-mark](https://github.com/germ-mark)! - A PQ re-key now accepts a peer's PQ leaf moving to an already-canonical credential, or changing only its signature key. `SideBandResult` gains `rotatedCredential`. `QueuedProposal` gains `isCatchUp`. A PQ leaf may not move to a non-canonical id: `pqRekeyApply` now throws `.invalidSuccession` for that case, not `.invalidRekeyEffects`.

- [#64](https://github.com/germ-network/twomlspq-swift/pull/64) [`680a9ee`](https://github.com/germ-network/twomlspq-swift/commit/680a9ee39b90112d100dce4b2ed911ee4da1cdd8) Thanks [@germ-mark](https://github.com/germ-mark)! - Expose a `GroupEpochs` pair (`pqEpoch`/`classicalEpoch`) via `TwoMLSSession.epochs` — the send group's epoch pair, mirroring the reference implementation's `epochs()` — purely additive, no behavior change. Add a from-cold, full-lifecycle test that drives establishment through the bootstrap, ratchet, re-key, fold, and rotation steps the way a host would, asserting the PQ epochs advance at each step.

- [#86](https://github.com/germ-network/twomlspq-swift/pull/86) [`9313709`](https://github.com/germ-network/twomlspq-swift/commit/9313709f20ed1ba3498ff324d39ad8d7470d7c5a) Thanks [@germ-mark](https://github.com/germ-mark)! - Acceptors can now open a pre-join initiator's app message: `processIncoming`/`processIncomingApproved` gain a new `IncomingResult.preEstablishment(PreEstablishmentMessage)` case for a `0x09` §A.1 staple, which decrypts in the receive group with no accompanying offer. This is source-breaking for any exhaustive switch over `IncomingResult`.

- [#86](https://github.com/germ-network/twomlspq-swift/pull/86) [`61e84c1`](https://github.com/germ-network/twomlspq-swift/commit/61e84c1ab0cd74c8939d6a1153e8d27943a0fba9) Thanks [@germ-mark](https://github.com/germ-mark)! - A pre-join initiator can now send app messages before joining the acceptor's group: `prepareToEncrypt`/`encrypt` succeed instead of throwing, returning an HPKE §A.1 envelope for the invitation channel rather than a header-sealed frame for the rendezvous channel. `EncryptResult` gains `isEstablishmentEnvelope` to tell the two apart, and `canSend` is now true for a pre-join initiator that can send this way.

- [#84](https://github.com/germ-network/twomlspq-swift/pull/84) [`437fdcb`](https://github.com/germ-network/twomlspq-swift/commit/437fdcbc6d685eb9db64a8c4debb03d814c77f71) Thanks [@germ-mark](https://github.com/germ-mark)! - `encrypt` now also self-drives the reciprocal §A.5 catch-up when the peer's recv-PQ leaf lags — deferred until the peer's own A.5 has already landed (observed as its leaf in our send-PQ presenting its current canonical id), so the turn opens a plain A.4 instead until then. A rotated pair now converges both PQ leaves over two self-driven rounds, plus at most one deferred A.4.

- [#85](https://github.com/germ-network/twomlspq-swift/pull/85) [`abd9de1`](https://github.com/germ-network/twomlspq-swift/commit/abd9de18a1861b341d5f1ec7bd662392ff8ce5a3) Thanks [@germ-mark](https://github.com/germ-mark)! - `pqBootstrapRespond` now re-serves the parked Welcome′ only while its own §A.3 round is still open. Once that round has closed, a stale bootstrap KP now answers `.duplicateSideBand` with no state change, rather than re-founding or re-serving anything; an initiator handed her own reflected KP′ is refused the same way. The re-serve itself no longer reads as a group-level move — it now returns a Core-kind update.

- [#81](https://github.com/germ-network/twomlspq-swift/pull/81) [`9171352`](https://github.com/germ-network/twomlspq-swift/commit/917135283a279d6fad00ea6155a1e43a38881995) Thanks [@germ-mark](https://github.com/germ-mark)! - `pqRekeyRespond`'s committer `Commit′` now moves our own send-PQ path leaf onto our current canonical credential id whenever it lags, with a freshly minted key going straight to `current` — no `pending` catch-up key is retained afterward, since our own commit applies immediately. When the leaf doesn't lag, the move stays key-only, as before.

- [#81](https://github.com/germ-network/twomlspq-swift/pull/81) [`4d639cc`](https://github.com/germ-network/twomlspq-swift/commit/4d639cc0b09e23cb94a599bda9c66eecab35ff66) Thanks [@germ-mark](https://github.com/germ-mark)! - Drops the unread principal-scoped key copies: the born-dedicated recv-leaf custody record and a rotation candidate's own signing/signature key are no longer stored on `TwoMLSSession` or archived — every signing site already read the per-group stored key sets exclusively (`LeafKeys`), never these copies. `RotationCandidate` keeps only its credential id and staged epoch; the migration inputs (`MigratedRotationCandidate`, `MigratedRecvLeafPrincipal`) are unchanged.

  Archives from this version are one-way: a new archive no longer carries a rotation candidate's own key material or the recv-leaf custody record, so an earlier build's decoder — which expects those fields — cannot restore one. An earlier archive that still carries them decodes fine under this version (the retired keys are simply ignored).

- [#84](https://github.com/germ-network/twomlspq-swift/pull/84) [`0388101`](https://github.com/germ-network/twomlspq-swift/commit/0388101a71670a503144dcecc894bc9d616d7819) Thanks [@germ-mark](https://github.com/germ-mark)! - `encrypt` now self-drives the §A.5 credential catch-up (instead of a plain A.4 ratchet) whenever a recv-PQ leaf lags its owner's current canonical id. Our own catch-up opens only once the peer has already folded the target — otherwise the turn keeps ratcheting A.4 rather than opening a round it cannot complete. A session with no recv-PQ key falls through to A.4 the same way. The `encrypt` that stages a catch-up now returns a `.checkpoint` update instead of `.core`.

- [#89](https://github.com/germ-network/twomlspq-swift/pull/89) [`c673aaf`](https://github.com/germ-network/twomlspq-swift/commit/c673aafe23dcc261574ee2e5c673f7cb12eef821) Thanks [@germ-mark](https://github.com/germ-mark)! - `Principal.generate` gains `advertisesCorrectProfile: Bool`, default off, so a host can opt in to advertising the correct session profile on every KeyPackage that principal mints. Off by default, behavior and wire bytes are byte-identical to a build with no profile mechanism at all. Opted in, the classical key package leaf, its published blob, the return key package, and the host-signed `keyPackageData` each grow by 2 bytes.

- [#89](https://github.com/germ-network/twomlspq-swift/pull/89) [`ea6ed5c`](https://github.com/germ-network/twomlspq-swift/commit/ea6ed5c36154262a6cf429bb00b50dedbfcee9d6) Thanks [@germ-mark](https://github.com/germ-mark)! - At establishment, a session now negotiates the newest session profile both classical key packages advertise and records it as an empty GroupContext extension on the classical half only (book group-rules.md rule 9). The acceptor checks the record against its own computation before claiming any invitation state, mirrors it onto its return group, and the initiator requires the return welcome to carry it back unchanged; a leaf that enters or stays in a profile-carrying group must keep advertising its type. New public error case: `TwoMLSError.sessionProfileMismatch` — exhaustive switches over `TwoMLSError` gain an arm. Between two key packages that both advertise, the wire now carries this extra, empty GroupContext extension; nothing changes between key packages that don't.

- [#89](https://github.com/germ-network/twomlspq-swift/pull/89) [`334d6fe`](https://github.com/germ-network/twomlspq-swift/commit/334d6fe8d888072a66b95de14106632a52f76529) Thanks [@germ-mark](https://github.com/germ-mark)! - C1 (the §A.5 `Upd′`'s authenticated data) and C2 (deferring the reciprocal §A.5) now follow the session profile actually recorded in the group, instead of always running deployed-compatible. A session with no recorded profile is unaffected and stays deployed-compatible.

- [#73](https://github.com/germ-network/twomlspq-swift/pull/73) [`3a5d1de`](https://github.com/germ-network/twomlspq-swift/commit/3a5d1de7f7f913e5ab820cc6397703a41d9a044d) Thanks [@germ-mark](https://github.com/germ-mark)! - Sessions now store each group's own signing keys by role in the session archive, and signing reads the stored key directly; every message is signed with the same keys as before and nothing changes on the wire. Every state update, restore, and migration mint checks that each group's own leaf presents its stored key: a failing state update throws `.credentialUnknown` and returns nothing to persist, and a failing restore or mint throws `.archiveInvalid`. Session archives written by earlier versions no longer restore. A second rotation to a different id is now refused with `.rotationInFlight` until the receive group's epoch moves past the candidate's latest proposal.

- [#86](https://github.com/germ-network/twomlspq-swift/pull/86) [`eeff445`](https://github.com/germ-network/twomlspq-swift/commit/eeff4454b4c66f9b99d9c3d4c3be3c55e662d97e) Thanks [@germ-mark](https://github.com/germ-mark)! - The §A.1 establishment vector's Welcome halves (Group_A's classical/pq pair, Group_B's classical half) and its return key package now travel as RFC 9420 `MLSMessage`s on the wire, matching every deployed peer. Receive accepts the wrapped form only; a bare struct is refused with a new `TwoMLSError.malformedEstablishmentMessage`.

  A pre-fix native archive re-stapling a bare welcome, or holding a pre-fix acceptor's bare `APQWelcome_B`, no longer establishes against a post-fix peer — dev/test state only, since this engine is not yet deployed.

### Patch Changes

- [#78](https://github.com/germ-network/twomlspq-swift/pull/78) [`1fb3303`](https://github.com/germ-network/twomlspq-swift/commit/1fb33030f0f7d3a90fca0611abb9ee4b25576351) Thanks [@germ-mark](https://github.com/germ-mark)! - Approving a peer's offered Update (`queueProposal`) now validates the replacement leaf itself — its own signature and RFC 9420 section 7.3 policy (capabilities, credential-type mutual support, `required_capabilities`, and that its encryption key actually changed) — not only the enclosing proposal's framing signature. A folded approval whose commit then fails to build for any reason is dropped rather than left silently re-triable, and a still-outstanding (not yet canonical) authorization for it is withdrawn.

- [#78](https://github.com/germ-network/twomlspq-swift/pull/78) [`6bb5c34`](https://github.com/germ-network/twomlspq-swift/commit/6bb5c343f319393d4b919096dcf6dbcf3732ffeb) Thanks [@germ-mark](https://github.com/germ-mark)! - Applying a commit that moves a leaf to a credential already known to that party's sequence — a same-id signing-key refresh on a leaf whose canonical head has since moved on, or a fast-forward to an already-canonical, non-head id — no longer fails with `.credentialRollback`. Canonicalization now only ever runs for a credential genuinely new to the sequence; a leaf landing on a known id canonicalizes nothing, and `DecryptResult.newSender`/`ownCredentialCanonicalized` are documented accordingly.

- [#86](https://github.com/germ-network/twomlspq-swift/pull/86) [`f2811d6`](https://github.com/germ-network/twomlspq-swift/commit/f2811d668158d84730932801461efde51345f0d0) Thanks [@germ-mark](https://github.com/germ-mark)! - A migrated pre-join initiator carrying a host app payload no longer fails to restore after it joins the acceptor's group: the payload now drains alongside the peer's key package the moment the join completes. A payload with no retained key package to re-seal to is now rejected at migration mint and at restore.

- [#84](https://github.com/germ-network/twomlspq-swift/pull/84) [`a60b55e`](https://github.com/germ-network/twomlspq-swift/commit/a60b55e22e20a61e55a9b2d1959ef880f091198e) Thanks [@germ-mark](https://github.com/germ-mark)! - The migration mint also drops a parked §A.5 `Upd'` whose target has already left the party's own canonical history, alongside its existing drop of one that fails to verify.

- [#78](https://github.com/germ-network/twomlspq-swift/pull/78) [`be48cbb`](https://github.com/germ-network/twomlspq-swift/commit/be48cbbc16babfd53585e3b142598e9c24be63a1) Thanks [@germ-mark](https://github.com/germ-mark)! - `initiate` and `receive` now reject a peer naming this device's own identity, with `.remoteIdentityMismatch`, before any state changes. `prepareToEncrypt(rotating:)` now rejects a rotation target naming an id the peer already uses, with `.invalidSuccession`.

  `AuthCore.adjudicate` now checks each `.credentialReplaced` commit effect against the specific party whose leaf actually moved, rather than accepting it if either party's sequence would. `adjudicate` gains a `myLeaf` parameter; `validateSuccession` gains a `party` parameter.

- [#78](https://github.com/germ-network/twomlspq-swift/pull/78) [`1f25a20`](https://github.com/germ-network/twomlspq-swift/commit/1f25a200b548e27fe0625f70ecb360cd01d21386) Thanks [@germ-mark](https://github.com/germ-mark)! - A credential that a live PQ leaf still presents now stays admissible past classical history-window eviction until that leaf catches up (book `group-rules.md` rule 4), maintained automatically at every state update rather than left to per-site pinning. Restore now validates the archived pin state against what the rebuilt PQ trees actually present, rejecting a stale or otherwise inconsistent pin with `.archiveInvalid`; a migrated session's minted pins are derived the same way, from the restored PQ trees, rather than carried over from the deployed engine's own (narrower) pinning.

  Compatibility: an archive from an unreleased build that holds a presented id evicted from history with no corresponding pin now fails restore with `.archiveInvalid`. Released v0.2.1 archives already fail to decode on this branch for an unrelated reason, so this affects only unreleased-main archives.

- [#80](https://github.com/germ-network/twomlspq-swift/pull/80) [`be443a3`](https://github.com/germ-network/twomlspq-swift/commit/be443a31eb01a4bf0584419d417fd959e120660d) Thanks [@germ-mark](https://github.com/germ-mark)! - `TwoMLSSession.restore` now throws `.archiveInvalid` when an archive is missing a group its recorded state implies. That covers a missing send group, a missing recv group (only an initiator that has not yet joined may lack one), and a missing Group_B PQ half once §A.3 has reached that side. It also rejects an archive whose classical group ids don't match the groups it restores.

- [#89](https://github.com/germ-network/twomlspq-swift/pull/89) [`7ce2669`](https://github.com/germ-network/twomlspq-swift/commit/7ce2669419344bd44a33d2be2ecbb22a159acc57) Thanks [@germ-mark](https://github.com/germ-mark)! - A classical key package's leaf can now list a session profile's extension type in its capabilities, and a founding leaf copies whatever its owner's own classical key package advertises (book group-rules.md rule 9). No behavior change: nothing advertises anything yet.

- [#89](https://github.com/germ-network/twomlspq-swift/pull/89) [`e76aee6`](https://github.com/germ-network/twomlspq-swift/commit/e76aee671fa8982bf74842aac3420dc458e9c1f9) Thanks [@germ-mark](https://github.com/germ-mark)! - The migration mint now refuses to mint a session around any of the four restored groups recording a session profile: the deployed engine never advertises, so it never records one either.

- [#72](https://github.com/germ-network/twomlspq-swift/pull/72) [`ea02313`](https://github.com/germ-network/twomlspq-swift/commit/ea023130f73ade9a79149c14877f12b6f2d12169) Thanks [@germ-mark](https://github.com/germ-mark)! - Require swift-mls 0.1.5, which adds authenticated data on self-Update proposals and a migration-only way to restore a member's own outstanding Update proposal.

- [#77](https://github.com/germ-network/twomlspq-swift/pull/77) [`6b621f4`](https://github.com/germ-network/twomlspq-swift/commit/6b621f43f3407efc61554deb523143cbd04c8051) Thanks [@germ-mark](https://github.com/germ-mark)! - Require swift-secret-bytes 0.7.1, whose keyed-container decode is linear. Restoring a group snapshot that holds many pending self-Updates in one epoch was quadratic before.

## 0.2.1

### Patch Changes

- [#62](https://github.com/germ-network/twomlspq-swift/pull/62) [`31676fa`](https://github.com/germ-network/twomlspq-swift/commit/31676fa9d0ff9c96e2243217a800c6400501ab76) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the `swift-secret-bytes` pin from `.upToNextMinor(from: "0.5.0")` to
  `from: "0.5.0"`.

  `.upToNextMinor` on a 0.x version fences the range at `0.5.x`, so this package
  capped the whole graph below swift-secret-bytes 0.6.0 — the release that carries
  the shared `SecretBytes`↔`String` text bridge. `from:` keeps the 0.5.0 floor and
  admits 0.6.0 when it cuts. No source changes.

## 0.2.0

### Minor Changes

- [#60](https://github.com/germ-network/twomlspq-swift/pull/60) [`34c0a3a`](https://github.com/germ-network/twomlspq-swift/commit/34c0a3a42595430fca8707c4b97e49c523144b5a) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the `swift-crypto` dependency to `from: "5.0.0"` and move
  `swift-secret-bytes` to its 0.5.0 (swift-crypto 5) release, as part of the
  org-wide swift-crypto 5 migration.

  **Breaking — platform floor rises to macOS 15 / iOS 18**, matching swift-mls
  (which now floors there via swift-secret-bytes 0.5.0).

  Two dependencies are revision-pinned pending their own releases: swift-mls
  (germ-network/swift-mls#103, the swift-crypto 5 move). GermConvenience is its
  released 0.10.0 (the swift-crypto-5 release).

  No source changes were required, and secret custody is already complete — the
  session/identity secrets ride `SecretBytes` and the persisted archives ride
  `SecretArchive`.

## 0.1.7

### Patch Changes

- [#58](https://github.com/germ-network/twomlspq-swift/pull/58) [`3402d17`](https://github.com/germ-network/twomlspq-swift/commit/3402d17f3c431da23ae50702da7c5768e4f1c217) Thanks [@germ-mark](https://github.com/germ-mark)! - Funnel every Transition read-group-then-takeOutput() handoff through one @\_optimize(none) @inline(never) helper, dodging the Swift 6.4.0 Android release-mode SIL verifier crash at every call site.

## 0.1.6

### Patch Changes

- [#56](https://github.com/germ-network/twomlspq-swift/pull/56) [`5554b65`](https://github.com/germ-network/twomlspq-swift/commit/5554b65549f8c7cbae76505d3767aac53b1dfbd9) Thanks [@germ-mark](https://github.com/germ-mark)! - Opt `APQGroup.establishClassicalOnly` out of optimization (`@_optimize(none)`). Same Android release-build SIL verifier crash swift-mls 0.1.2 fixed in `CombinerGroup.createAndAdd` — the read-`group`-then-`takeOutput()` handoff on `Transition` trips a Swift 6.4.0 optimizer bug cross-compiling for Android; this package's own orchestration path hit the same pattern.

## 0.1.5

### Patch Changes

- [#54](https://github.com/germ-network/twomlspq-swift/pull/54) [`a96b817`](https://github.com/germ-network/twomlspq-swift/commit/a96b817c46fb55ba4e837d05af5c9ea560dc914b) Thanks [@germ-mark](https://github.com/germ-mark)! - Bump the swift-mls exact pin from 0.1.1 to 0.1.2. 0.1.2 fixes an Android release-build compiler crash (`@_optimize(none)` on `MLSCombiner.createAndAdd`); this package's exact-pin discipline means consumers can't take that fix until this bump ships.

## 0.1.4

### Patch Changes

- [#52](https://github.com/germ-network/twomlspq-swift/pull/52) [`a72435f`](https://github.com/germ-network/twomlspq-swift/commit/a72435f7a044dcd407e99f91a481e18c93b5d28f) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the GermConvenience requirement from `.upToNextMinor(from: "0.8.0")` to `from: "0.8.0"`. Consumers pin this package exactly, so the minor ceiling capped their whole graph below GermConvenience 0.9.0 — that is what made 0.9.0 unreachable for CoreAppLogic (GER-2495). This package imports only the base `GermConvenience` product, which 0.9.0 leaves untouched (its change is in `GermConvenienceHTTP`).

## 0.1.3

### Patch Changes

- [#49](https://github.com/germ-network/twomlspq-swift/pull/49) [`32427db`](https://github.com/germ-network/twomlspq-swift/commit/32427db45f3950a3abd8e68a98ad42eefa1c6443) Thanks [@germ-mark](https://github.com/germ-mark)! - Add the deployed Germ opaque combiner-blob wire codec to `TwoMLSPQSession`: `CombinerKeyPackage(publishedBlob:)` and `publishedBlob()` — byte-compatible with the Rust engine's `encode_combiner_key_package` / `decode_combiner_key_package` (`[version byte][opaque classical][opaque pq]`, RFC 9420 §2.1.2 varint vectors of full `MLSMessage` KeyPackages; v3 = the AppBinding capability cut). The Germ version-byte prefix is a Germ addition on top of draft-02 §7 (whose TLS framing stays in swift-mls, spec-only); this gives the Rust-free host (the reduced Android build) read AND write access to the same published key-package wire.

## 0.1.2

### Patch Changes

- [#47](https://github.com/germ-network/twomlspq-swift/pull/47) [`0b0a619`](https://github.com/germ-network/twomlspq-swift/commit/0b0a6190ba80fb5fd093c0cfa223d235a264c456) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `EstablishResult.returnKeyPackage`, carrying the established session's own classical KeyPackage so an initiator/replier can put it into the welcome's keyMaterial (the value the Rust `PQClient.reply` returns as `myKeyPackage`).

## 0.1.1

### Patch Changes

- [#46](https://github.com/germ-network/twomlspq-swift/pull/46) [`198723c`](https://github.com/germ-network/twomlspq-swift/commit/198723c24c9da33b7a8b95fdccb9d7dc0701204f) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `MLKEM768CipherSuiteProvider.hpkeSecretKeySize` (96, the CryptoKit `integrityCheckedRepresentation` length) so snapshot restore can length-check ML-KEM-768 HPKE secret keys against `Nsk` (spec/snapshot.md §3.1).

- [#44](https://github.com/germ-network/twomlspq-swift/pull/44) [`672ad80`](https://github.com/germ-network/twomlspq-swift/commit/672ad80b94a703b3cbad246fb33da4e65be27dcd) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `SessionMigration.mintArchive` — a public session-level parts→`SecretArchive` minter (the session analog of `InvitationMigration.mintArchive`). Builds a native `SessionArchive` from a legacy Rust session's raw parts, restoring each group half through `Group.restore`/`makeSnapshot`, with mint-time cross-checks shared with the invitation minter.

## 0.1.0

### Minor Changes

- [#42](https://github.com/germ-network/twomlspq-swift/pull/42) [`7ad2560`](https://github.com/germ-network/twomlspq-swift/commit/7ad256039ef684c00bafbcbe543a22844d52c048) Thanks [@germ-mark](https://github.com/germ-mark)! - First pre-release.

  twomlspq-swift is a Swift-native **Two-MLS-PQ** (post-quantum MLS) implementation built on
  [swift-mls](https://github.com/germ-network/swift-mls). This release includes the
  **`0xFDEA` ML-KEM-768 cipher-suite provider** — a conformer to swift-mls's
  `MLS.CipherSuiteProvider` for the private-range suite
  `MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519` — supplying the ML-KEM-768 KEM and RFC 9180
  base-mode HPKE over it, and reusing swift-mls suite-1's symmetric stack (HKDF-SHA256 /
  AES-128-GCM / SHA-256 / Ed25519) unchanged.
