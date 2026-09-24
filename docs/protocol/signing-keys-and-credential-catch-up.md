# Signing keys and the §A.5 credential catch-up

Status: decided; implementation in progress.

This document covers how this engine handles leaf signing keys, and how it runs the §A.5 credential catch-up. It
separates five things:

1. what the TwoMLSPQ book specifies;
2. where the book is silent, and what we decided;
3. what we accept from a peer versus what we do ourselves;
4. what we do only for compatibility with the deployed Rust engine;
5. how a session chooses between the correct behavior and the deployed-compatible variant.

**Sources.**
- **The book:** TwoMLSPQ `book/src/`, at commit `69a9f0e`. It is the specification for this engine, and every "the book
  says" below quotes it.
- **RFC 9420:** a normative reference of the book.
- **The deployed Rust engine:** TwoMLSPQ `rust/`, at the same commit. It is a *peer*, cited for interop facts and never as
  an authority.

**Terms.** A session has four MLS groups: send-classical, send-PQ, recv-classical, recv-PQ. A party's *send* group is
the one it founded. Its *recv* group is its membership in the peer's send group. A *leaf move* is any change to a
party's own leaf: an Update proposal that gets folded, or a commit with an update path.

## 1. What the book specifies

- **Who opens a round.** The session opens PQ rounds itself, never the host. On our turn, when the side-band is idle
  and not wedged, it opens "an **A.5 re-key** if either leaf in the PQ half of our receive group (the group our A.5
  re-keys) lags, else an **A.4 ratchet**". "A leaf *lags* when it presents a credential id other than its owner's
  *current* canonical … id; a same-id key refresh is not a lag." If the lagging leaf is ours, our `Upd'` announces our
  identity; if it is the peer's, the peer's responder `Commit'` carries theirs — the reciprocal catch-up. A rotation
  landing while an A.4 is staged, or while an A.5 `Upd'` is in flight, does not re-mint that round, and a responder
  whose own rotation staple has not yet applied answers with a no-move `Commit'` — either way the leaf still lags and
  the next turn's trigger opens the catch-up: a race costs one extra round, never a stall. Sources:
  `protocol-flows.md:56`, `api-reference.md:237-241`, `session-lifecycle.md:49-55`.
- **Which leaves an A.5 moves, and why a catch-up takes two rounds.** "The proposal replaces the *proposer's* leaf …
  the full commit replaces the *committer's* leaf … the pathless ack signals receipt" (`protocol-flows.md:696-701`;
  also `:48-51` and `session-lifecycle.md:81-97`).
  - Consequence: after a rotation, the rotated party's own next A.5 moves its leaf in the PEER's send group (the
    round it opens). Its leaf in its OWN send group still lags, so the peer's next turn opens the reciprocal A.5
    there instead, with a same-id `Upd'` and the rotated party's responder `Commit'` carrying its credential onto
    that leaf. "A credential catch-up therefore takes two rounds" (`protocol-flows.md:704-708`).
- **Every frame carries a proposal, and it is the peer's ack.**
  - The message frame is `[0x03][staple][proposal][app]` "with **no optional sections**" (`wire-format.md:187-188`).
  - "The evidence is the peer's stapled proposal": the peer builds its `Upd(self)` in our send group, so an offer bound
    to our current epoch proves it applied our commits through that epoch. "The peer re-proposes at the new epoch on
    its next frame — so the license is re-earned exactly once per round trip" (`protocol-flows.md:88-93`).
  - That license keeps a sender at most one commit ahead of its peer (`protocol-flows.md:78-81`).
- **Proposed candidates stay live.** "A candidate that has been proposed on the wire is **never evicted** — the peer
  may commit any of them" (`group-rules.md:119-121`). The receiver may drop an offer, because "the proposer re-sends
  every round" (`group-rules.md:136`).
- **Catch-up is canonical-only, and a live leaf's credential is pinned past eviction (rule 4).** "a lagging leaf may
  only fast-forward to an already-canonical credential; candidates are proposed and canonicalized exclusively in the
  classical ratchet" (`group-rules.md:149-152`). "A credential that a live PQ leaf still presents stays admissible
  past window eviction until that leaf catches up; the A.3 founding pins are one instance of this rule"
  (`group-rules.md:152-154`).
- **Successor rule.** "`valid_successor` implements same-id / authorized-step / catch-up" (`group-rules.md:160-161`).
  A same-id leaf move is always a valid successor, whatever the signature key.
- **The join-key rule.** "Until a leaf moves, its owner signs in that group with the key the leaf presents. A group
  joined from a KeyPackage (the A.3 KP′) is signed with that KeyPackage's key, even if the owner has rotated since
  it was minted. Moving one group's leaf never retires a key that another group's leaf still presents"
  (`group-rules.md:154-158`; the A.3 step itself, `protocol-flows.md:142`: "Alice joins via the Welcome — signing in
  that group with KP′'s key, which her leaf there presents, until her own A.5 moves it").
- **The A.5 ack is pathless.** It is "a pathless partial commit on her own send group" (`protocol-flows.md:51`), so it
  moves no leaf.
- **Signature algorithm.** "both halves sign Ed25519 (the PQ suite is confidentiality-only)" (`protocol-flows.md:598-602`).
- **Capability signaling.** The book already signals an optional extension through leaf capabilities: "Leaves
  advertise the extension type, so a binding-carrying group can only ever contain capability-bearing leaves"
  (`group-rules.md:77-78`, for the AppBinding extension).
- **From RFC 9420:**
  - Every commit-path leaf gets a fresh encryption key: "Set the encryption_key to the public key of a freshly sampled
    key pair". A new signature key is optional: "The application MAY specify other changes to the leaf node, e.g.,
    providing a new signature key" (§7.5).
  - A LeafNode always carries its `signature_key` (§7.2), so replacing it on a move costs no extra bytes on the wire.
  - Leaf keys "MUST be distinct from one another" within one ratchet tree (§16.7). That rule is per group; nothing in
    the RFC relates the keys of two different groups.
  - Post-compromise security comes from updating the leaf's encryption key (§16.6).

> **Shipped anomaly (deployed Rust engine).** Its trigger loop reads its own *send*-PQ leaf, not either leaf of its
> receive group, and it never opens the reciprocal A.5 for the peer — so after a one-sided rotation, "its own round
> can only move its receive-PQ leaf, so the trigger never clears itself," and the rotated party re-sends a same-id
> A.5 on every later PQ turn. A conforming peer heals it: the deployed responder `Commit'` does carry its current
> credential, so a conforming peer's reciprocal A.5 completes the catch-up. Against a deployed peer, a conforming
> rotated party's own send-PQ leaf stays behind for the mirror-image reason — the deployed peer never opens the
> reciprocal round — so that party must keep signing that group with the key its leaf presents; rule 4 already
> covers this, so it needs no separate accommodation (`session-lifecycle.md:263-273`, anomaly #1). The deployed AS
> also pins only the A.3 founding ids, not every id a live leaf still presents — a conforming validator still keeps
> such a leaf admissible (rule 4), but a *deployed* validator refuses one left behind for longer than the history
> window, and nothing heals that specific case (`session-lifecycle.md:286-290`, anomaly #4). Against a peer whose
> host never sends side-band frames at all, later A.4/A.5 rounds "stay open, without error, until it upgrades" —
> never a stall, just indefinitely deferred (`session-lifecycle.md:303-319`, anomaly #6).

**The wedge.** The trigger's "not wedged" gate (`protocol-flows.md:56`) guards every PQ side-band door
(`pqBootstrapJoin`, `pqRatchetBind`, `pqRekeyApply`) and the self-drive trigger — never an owed-bind discharge, a
respond door, a begin door, or classical messaging, matching the deployed engine's own `check_not_wedged` call
sites. A migrated session's own wedge, when supplied, rides this engine's `pqSideBandWedged` query
(`api-reference.md:304-309`'s "queryable `pq_side_band_wedged()`"); this engine's own bind triggers do not yet latch
one themselves on failure (a separate, later change) — the exit from a wedged state is re-establishment either way.

**The own-arm gate.** The trigger opens our own catch-up only once the peer has already canonicalized our target —
observed as our own leaf in `recvGroup.classical` (the peer's view of us, which we mirror) already presenting
`mine.current`. Until then, our turn keeps ratcheting A.4 instead. This matters for a born-dedicated acceptor: its
recv-PQ leaf is seeded at birth under the invitation identity, well before the peer has necessarily folded the
dedicated handoff, and a peer that never folds a catch-up offer would otherwise leave the round permanently
unanswerable (the same "Unchecked join" shape C2 guards against on the reciprocal side, `session-lifecycle.md:291-302`
anomaly #5) — without the gate, the PQ side would stall on an A.5 it can never complete where today it ratchets A.4
for life. The gate applies in both profiles; see C2 (§4), whose own condition is this gate's mirror on the reciprocal
side.

## 2. Where the book is silent, and what we decided

The book does not say whether the classical and PQ halves, or a party's two groups, may share signing keys. Its object
model implies they do: a session "holds the client backing its groups (plus the successor client staged by a principal
rotation)" (`concepts.md:45-48`). A restored session's archives also "carry the session's signing identity"
(`api-reference.md:174-175`).

The deployed engine follows that model:
- Each client holds one classical and one PQ signing key, and uses them in all of its groups
  (`rust/apq/src/client.rs:212-243`).
- A classical rotation stages a whole successor client, so the PQ key changes in lockstep with the classical one. The
  A.5 then moves the PQ leaf onto that successor's PQ key (`rust/two-mls-pq/src/session/pq_ops.rs:373-397`).
- Signature keys change only together with a credential. The engine calls `set_new_signing_identity` only on a
  credential handoff (`rust/two-mls-pq/src/session/messaging.rs:1023`, `pq_ops.rs:1127`), so the credential is its sync
  point for key changes.

We don't carry that coupling over. Decisions:

- **D1 — no shared keys.** The APQ combiner's classical and PQ groups are independent, so they share no keys. Each of
  the four groups has its own signing key. Nothing bundles "a principal's keys". A classical rotation never mints or
  touches a PQ key. A leaf gets a new signing key only through an operation in its own group.
  Sharing a key across groups works only if every group changes its key at the same moment, which needs a sync point
  like the deployed engine's credential change. Letting each group move its key on its own is simpler, and D3 leaves
  no sync point anyway.
- **D2 — keys only.** The independence covers keys, not credentials. A PQ leaf's credential id still converges to the
  classical canonical principal, through the book's A.5 (§1).
- **D3 — key cadence: every leaf move.** Every own-leaf move, in any group, carries a freshly minted signature key for
  that group. MLS allows this (§7.5 "MAY"), and it costs no wire bytes (§7.2), so we take every chance.
  - A credential change is then just a leaf move that also carries a new credential id. Keys never wait for a
    credential, so there is no sync point between groups.
  - A key a leaf starts with (from an invitation KeyPackage, or carried in from a migrated archive) is replaced by the
    same rule at that leaf's next move.
  - One Update offer per epoch of the peer's group.
    - Frames within that epoch repeat the identical proposal, because the frame requires one and it is the ack (§1).
      The proposal section stays mandatory: it is our new key, stapled onto every frame until the peer takes it.
    - A new leaf node is minted only when that epoch moves (our offer was folded, or went stale), or to announce a
      further credential change, which gets its own offer while earlier candidates stay live (§1).
    - A leaf node is never re-sent into a later epoch, and none is minted per frame.
    - The deployed engine mints a fresh Update on every frame instead, "a plain key refresh of the unchanged leaf"
      (`rust/two-mls-pq/src/session/messaging.rs:884-889`).
      - Neither the book nor the code says why. The book only says "every round stages one"
        (`session-lifecycle.md:121-122`).
      - The cost is that the sender keeps every one of those secrets until the epoch moves, because the peer may fold
        any of them. This engine instead reuses the same offer bytes for the epoch's own target
        (`TwoMLSSession+Messaging.swift`'s `prepareToEncrypt`), so it never grows that per-frame cost.
    - The deployed engine accepts a repeated offer:
      - it validates each offer without keeping state and skips the work once the epoch is already licensed
        (`messaging.rs:1625-1655`, `:599-640`: "safe to repeat");
      - it stores the latest offer (`:1655`);
      - approval is single-slot, latest-wins (`:2081-2118`), and the book says approval "never accumulates a second
        Update" (`group-rules.md:131-134`).
      This engine's receive path behaves the same (`TwoMLSSession+Messaging.swift:551-563`;
      `TwoMLSSession+ClassicalCommit.swift:21-32`).
    - Hosts bind the per-round proposal hash into each message (`session-lifecycle.md:117`, `:139`), so consecutive
      messages in one epoch carry the same hash. The host we checked signs it into a per-message proposal, and the
      receiver checks that proposal against the same frame's digest. Nothing is keyed on the hash, so a repeat is fine.
- **D4 — KeyPackage keys.** Every KeyPackage half gets a fresh signing key; there is no principal-wide signing key.
  The book (`concepts.md:14-20`) itself says the principal is "a credential-scoped identity (one MLS Basic
  Credential)" and that "a principal may use one signing key for every half it mints, or a fresh key per half; both
  conform" — our per-half minting is the second of those two conforming shapes, not a departure from it. Every group
  a party founds is founded on a freshly minted leaf; a KeyPackage half's key lands only in the one group that half
  joins.
- **D5 — superseded: the book now specifies the reciprocal A.5** (`protocol-flows.md:56`, `:704-708`;
  `group-rules.md:143-158` rule 4). The non-rotated peer's own next turn opens the catch-up for the rotated party's
  still-lagging leaf; there is no extra trigger left for us to add.
- **D6 — catch-up offers are approved.** The book says a born-dedicated acceptor's recv-group leaf "converges from the
  invitation identity to the dedicated principal via its first committed Upd" (`group-rules.md:147-148`). But a peer
  commits only an offer its host approved, and a host that approves only offers introducing a new client never approves
  a catch-up. So:
  - The engine marks a received offer that moves the proposer's leaf to a *different* credential id that is already
    canonical. Such an offer authorizes no new credential.
  - Hosts approve marked offers the same way as offers from a new client.
  - Routine same-id refresh offers stay at the host's discretion ("the receiver may freely drop", `group-rules.md:136`).
  - Against a deployed-engine peer whose host does not approve catch-ups, our leaf keeps its old credential, and its key
    stays in custody.

## 3. What we accept versus what we do

"Accept" is how lenient we are toward a peer. "Do" is our own behavior. Where the two profiles of §5 differ, the row
says so.

| Behavior | Accepted from a peer | Done ourselves | Basis |
|---|---|---|---|
| One signing key shared across a party's groups or halves | yes: nothing compares a peer's keys across groups | never | RFC 9420 §16.7 is per group; D1 |
| Same-id signing-key change on any group | yes, including on a lagging leaf; canonicalizes nothing | on every own-leaf move | book `group-rules.md:160-161`; D3 |
| A commit moving the committer's lagging leaf to an already-canonical, non-head id | accepted; canonicalizes nothing | own leaves catch up only to the current canonical id (the "An own leaf..." row below) | book `group-rules.md:149-152` |
| A peer's offer that catches its leaf up to an already-canonical id | approved and folded | offered; converges once the peer folds it | book `group-rules.md:147-148`; D6 |
| PQ leaf moving to a new credential id | only to an id already canonical in the AS | only to our own current canonical id | book `group-rules.md:149-152` |
| A PQ leaf's id and key changing together in one A.5 | yes | yes, with a key freshly minted in that group only | book §A.5; D1 |
| A leaf move inside a pathless PQ bind or ack | no (malformed) | never | book `protocol-flows.md:51` |
| Catch-up to an id that is authorized but not yet canonical | no, at respond and at apply | never | book `group-rules.md:149-152` |
| An old key kept on a lagging send-PQ leaf (one-sided rotation, peer never opens an A.5) | yes | yes, whenever the book's trigger leaves that leaf unmoved | book `group-rules.md:154-155`; `session-lifecycle.md:269-273` anomaly #1 |
| Reciprocal A.5 opened before the peer's own A.5 has landed | never, ourselves — see C2 | never | C2 |
| Upd′ authenticated data | absent, or equal to the leaf's new id; any other value is rejected | deployed-compatible: C1; correct: never sent | C1 |
| An own leaf (any group, any cause — a rotation, a born-dedicated acceptor's recv leaf, or a migrated session's stored key set) presenting an id other than the current canonical principal | n/a (own-leaf only) | catches up: recv-classical and recv-PQ mint a fresh key into that group's own `pending[current canonical id]` at the next offer, held until the peer folds it; send-classical and send-PQ mint fresh at their next commit and go straight to `current` — neither ever holds a `pending` catch-up key | book `group-rules.md:143-158` rule 4; `protocol-flows.md:696-708` |
| Carrying the id-changing move even when a strict deployed validator would refuse it (the lagging leaf's old id evicted from the peer's history and not an A.3 founding pin) | n/a | always carried, on both A.5 legs, exactly as the deployed responder itself does; a refusal there is retriable and leaves the classical ratchet unaffected, but the refused leg is re-served until the peer accepts it, so that session's PQ ratchet stalls meanwhile | book `group-rules.md:152-154` rule 4 |
| A peer leaf that does not advertise `APQInfo` (`0xF0A1`) and `AppDataUpdate` (`0x0008`) | rejected (`leafCapabilityUnadvertised`) at offer approval and fold, at establishment and A.3 founding and joins, at A.5 respond, and at the migration mint. Known gap: not yet checked on the path leaf of a peer's commit applied to a receive group | our leaves always advertise both | book `wire-format.md:302-304` |
| A PQ leaf presenting a credential evicted from the history window | accepted as a move's predecessor while any live PQ leaf still presents it; pinned while presented, retired once no live PQ leaf presents it any longer; a migrated session's pins are derived at the mint (§4) rather than carried over from the deployed engine's own pins | same | book `group-rules.md:152-154` rule 4 |

## 4. What we do only for compatibility with the deployed Rust engine

C1 and C2 are the only divergences. The deployed engine's other quirks need nothing special from us. For example, it
shares a key across its groups, and nothing compares a peer's keys across groups, so we accept that as-is (§3).

- **C1 — announce the handed-off id in the A.5 Upd′ authenticated data.**
  - On send, the deployed engine writes the raw ClientId bytes into the Upd′'s authenticated data
    (`pq_ops.rs:390-397`). The same id is also in the new leaf's credential.
  - On receive, it uses the value as an extra canonical-history check, skipped when absent (`pq_ops.rs:1081-1103`).
    It also returns the value to the host (`pq_ops.rs:977-982`), whose apps use it to trigger reconciliation.
  - The leaf credential is what the tree and the AS validate, so the announced value adds nothing to correctness. The
    book mentions it only in its header-encryption leak inventory (`header-encryption.md:55`). Its A.5 text now
    specifies where: "our `Upd'` announces our identity" (`protocol-flows.md:56`) — onto our own leaf in the peer's
    send group, the round the rotated party itself opens.
  - In a deployed-compatible session we send the value only on an A.5 that changes the credential id, never on a
    key-only one. On receive we treat it as a hint, in both profiles (§3).
- **C2 — defer the reciprocal A.5 until the peer's own A.5 has landed.**
  - What it is: when the peer's leaf in OUR recv-PQ lags, we don't open the reciprocal A.5 the moment it does. We wait
    until the peer's own A.5 has landed — its leaf in OUR send-PQ presents its current canonical id — before opening
    the round that catches its leaf up. Deferring means opening a plain A.4 instead — the turn must still pass, or
    the peer could never run the A.5 we are waiting on. That round runs in the PEER's send-PQ group — our own
    recv-PQ, the group its leaf lags in, never a group we founded (`protocol-flows.md:706`: "Bob's next turn opens
    the reciprocal A.5 on [ASG-PQ]", Alice's send-PQ group). Our own catch-up (opening an A.5 when OUR OWN leaf lags)
    is not deferred by this — C2 gates only the reciprocal round. A residual case this doesn't cover: against a
    deployed peer that rotated before its own A.3 bind, that peer's answer to OUR A.5 — as responder, whichever A.5
    it is — still orphans its key (the book's anomaly #5 covers any A.5 the deployed party answers, not only a
    reciprocal one).
  - Why: the deployed engine's A.3 join signs with its *current* PQ key rather than the KP′ key its leaf actually
    presents there (contrary to rule 4). If that party rotates before its A.3 bind, its own A.5 `Upd'` in that group
    is mis-signed and permanently rejected, and the presented KP′ key survives only as its own send-PQ group's
    signer. When it later answers a peer's A.5, ITS OWN responder `Commit'` replaces that signer, orphaning the leaf
    for good — no copy of the key remains anywhere. Deferring until the peer's own A.5 has genuinely landed avoids
    ever building the reciprocal `Commit'` against a party still stuck in this state (`session-lifecycle.md:291-302`,
    anomaly #5, "Unchecked join").
  - Cost against a conforming peer: at most one extra round — the reciprocal round waits one turn longer than the
    book's bare trigger rule would otherwise allow, exactly the same "race costs one extra round, never a stall"
    shape as §1's other races.
- **Migrated sessions.** A session migrated from the deployed engine carries four inputs beyond its key layout:
  - **Per-group signing keys.** The authoritative form is one stored key set per group (send-classical, recv-classical,
    send-PQ, recv-PQ) — a `current` key plus zero or more `pending[target id]` keys, exactly this engine's own D1
    shape, EXCEPT send-classical: its own commit mints fresh and applies immediately, so it carries `current` only —
    the mint drops any supplied send-classical `pending` entries rather than converting them. Until a migrator
    supplies these directly, mint falls back to a temporary conversion from the deployed engine's owner-keyed parts.
  - **Pinned credentials.** The mint derives each party's pinned set itself, from the ids that party's live PQ leaves
    present in the restored trees — the deployed engine pins only the A.3 founding ids, so its own supplied pins are
    ignored rather than carried over.
  - **The own-offer window.** The deployed engine may hold far more outstanding own-Update offers than this engine's
    framed store carries inline; the excess rides its own separate, on-demand blob (never the session archives), keyed
    by a shared id both a migrator's mint and a later re-mint compute the same way. A staple that names an offer this
    session's framed store doesn't hold asks the host to supply that blob; a supplied blob that still doesn't name it
    is terminal for that staple, which the peer must re-send in a later commit that builds on it.
  - **The wedge and no-custody states.** A migrated session may already be side-band-wedged (§1's "The wedge") or
    missing signing custody over one or more of its four groups (`noCustody`) — a group in that set can only receive;
    a no-custody PQ group's own driver stops rather than opening a round it cannot complete. Concretely, a session with
    no recv-PQ key keeps ratcheting A.4 even while its recv-PQ leaf genuinely lags: it can never sign the catch-up
    `Upd'` there, and the trigger must never even attempt a round it cannot complete. Both states are read-only
    queries on the restored session; no-custody clears the moment a promotion genuinely supplies that group's
    `current` key.
  - **Dropping an unverifiable parked re-key proposal.** A migrated session may carry a parked §A.5 `Upd'`
    (`.rekeyInitiated`) that no longer verifies against its restored recv-PQ group — the exact state the deployed
    engine's own `pq_rekey_apply` would fail on forever. Mint drops it instead: self-drive then opens a fresh A.4
    round under the carried key (book anomaly 5's own resolution, `session-lifecycle.md` at `69a9f0e`: "drops its
    mis-signed parked `Upd'` and re-proposes under the carried key").

## 5. Session profiles and KeyPackage signaling

The behavior above comes in two profiles:

- **Correct:** the book plus D1–D6, with nothing kept only for the deployed engine. We intend to run this everywhere
  eventually.
- **Deployed-compatible:** the correct behavior plus C1 and C2. It is *frozen*: it changes only to fix a
  bug or to follow a change in the deployed engine. It is what a session runs whenever the peer might be the deployed
  engine.

| Item | Correct | Deployed-compatible |
|---|---|---|
| C1: announce the handed-off id | never sent; a present value is still cross-checked | sent on an A.5 that changes the id |
| C2: defer the reciprocal A.5 | opens the moment the peer's leaf lags, per the book's bare trigger rule (§1) | defers until the peer's own A.5 has landed |
| D3: a fresh key on every leaf move | yes | yes: the deployed engine's successor check passes a same-id change (`rust/apq/src/authentication.rs:166-168`) |
| Migrated sessions | never correct | always this profile |

**The profile is chosen per session, from the two KeyPackages.**
- Each party's KeyPackage advertises the profiles it can start, as capability entries in its leaves: a TwoMLSPQ
  extension type per profile. This is the same mechanism the book uses for the AppBinding extension (§1). The
  deployed-compatible profile needs no entry; it is what a KeyPackage without one gets.
- At establishment, each side holds the other's KeyPackage. The initiator has the acceptor's published one, and the
  acceptor receives the initiator's. A session runs the correct profile only if both advertise it. Both sides compute
  the same answer from signed KeyPackages, so no extra negotiation message is needed.
- The chosen profile is recorded in the group, the same way the book records the AppBinding extension
  (`group-rules.md:58-78`).
  - It is a GroupContext extension written at creation into both classical halves of the initiator's group.
  - The acceptor checks it against its own result from the two KeyPackages, and mirrors it onto its return group. The
    initiator requires the return welcome to carry it back unchanged.
  - PQ halves carry none. It is never rewritten: the book's GroupContextExtensions ban makes it immutable.
  - Because the group carries it, every leaf must keep advertising it, as for AppBinding: "a binding-carrying group can
    only ever contain capability-bearing leaves" (`group-rules.md:77-78`).
- The profile is fixed for the session's life. It is not a runtime switch, and it never changes when a peer upgrades.
  Sessions migrated from the deployed engine, and every session created before profiles exist, are deployed-compatible.
- The deployed engine never advertises the correct profile, so any session with it stays deployed-compatible. Sessions
  between two upgraded clients start in the correct profile without a flag day.

**Rules that keep this sound.**
- A client advertises a profile only once it implements that profile completely. For the correct profile, that means
  after per-group keys have fully landed.
- Once shipped, a profile is frozen too. A later wire-visible change to the correct behavior ships as a *new* profile
  with its own capability entry, and a session uses the newest profile both KeyPackages advertise. The book allocates
  the codepoints.
- Before shipping, confirm that the deployed engine accepts a KeyPackage whose leaf capabilities list an extension type
  it does not know. If it doesn't, the signal needs a different carrier.

Downgrade protection is out of scope for now.
