# Message sizes

On-wire size of each frame kind, for a fixed 43-byte payload. This is the
Swift counterpart of the Rust reference's `rust/two-mls-pq/benches/sizes.rs`
and of the table the TwoMLSPQ book documents in `book/src/wire-format.md`
("Message-frame anatomy").

Reproduce with:

```sh
swift test --filter PayloadSizesTests
```

The harness (`Tests/TwoMLSPQSessionTests/PayloadSizesTests.swift`) prints the
table below and asserts only structural invariants — a frame's sections plus
framing sum to its on-wire length, and the rotation commit folds its peer
proposal by reference, never by value — so it is deterministic and CI-safe.

Measurements: `curve25519chaCha` + ML-KEM-768 (SwiftCrypto), 43-byte payload,
opaque 30-byte client ids, DEBUG, 2026-09-28.

## Frame kinds

| Frame | Tag | Bytes |
|-------|-----|------:|
| §A.1 initial envelope A (bare) | — | 6616 |
| §A.1 pre-establishment app (bare) | — | 6853 |
| §A.1 pre-establishment app (payload) | — | 6561 |
| APQ welcome B, sealed | `0x01` | 982 |
| no-commit message frame + app | `0x03` | 5835 |
| folding commit + app | `0x03` | 1287 |
| rotation commit + app | `0x03` | 1287 |
| PQ bootstrap KP, sealed | `0x13` | 2624 |
| PQ bootstrap welcome, sealed | `0x15` | 4212 |
| PQ ratchet EK, sealed | `0x17` | 1380 |
| PQ ratchet CT, sealed | `0x19` | 1336 |
| PQ ratchet bind frame (`0x03` + staple) | `0x03` | 1573 |
| PQ re-key `Upd'`, sealed | `0x1B` | 1498 |
| PQ re-key `Commit'`, sealed | `0x1D` | 3929 |
| born-dedicated establishment handoff | `0x0B` | 936 |

Notes:

- **The no-commit frame is large by design.** It is Alice's first frame after
  joining Group_B, so it still re-staples her full two-half APQ welcome until
  her first commit — the app-gated window the book calls out in "Why
  re-stapling stays cheap". Steady state is the folding/rotation rows.
- **Side-band legs are header-sealed**, so their tag is not the first wire
  byte; open them on the recipient to reach it.
- **`0x0B`** wraps the acceptor's envelope beside its unmodified `0x01`
  welcome.
- **Every founding commit omits its own `UpdatePath`.** Group_A's classical and
  PQ halves and both Group_B halves all found pathless (the founding commit's
  path is a redundant leaf self-update — there is no gap between group creation
  and the member-add it would cover). This is why the envelope-A / pre-establishment
  / no-commit rows are smaller than an equivalent pathed founding. Group_A's
  classical half is the last to drop its path, so those Group_A-carrying rows
  (and only those) shrink by 86 B each; the Group_B-only `0x01`, `0x15`, and
  `0x0B` rows were already pathless and are unchanged.

## Steady-state message frame (rotation)

For the 43-byte payload, a rotation frame is 1287 B. Split on the `u32`-LE
section prefixes:

| Section | Bytes | Contents |
|---------|------:|----------|
| `staple` (commit) | 633 | classical rotation commit `MLSMessage` — `UpdatePath` (rotated leaf + one path node), one by-value proposal (the 73 B APQ PSK), signature/confirmation/membership tags |
| `proposal` (`Upd`) | 373 | `[u32 proposingLen][ClientId][Upd(sender)]` |
| `app` | 236 | application `PrivateMessage` |
| framing | 45 | frame tag (1) + three `u32` section prefixes (12) + plaintext length prefix (4) + header-seal nonce (12) + tag (16) |

The book documents this split as 1341 / 651 / 395 / 254 / 41 for the Rust
engine (awslc). The rows differ by a few percent: the credential-bearing
sections track the engine's own MLS encoding and the client-id length, and
the book's framing figure of 41 predates the 4-byte plaintext frame-length
prefix the seal adds (`header-encryption.md`). The harness asserts the two
invariants that *must* hold regardless of engine — the split sums to the
frame, and the commit's by-value proposals stay under 200 B — rather than
pinning the book's absolute numbers.

## PQ ratchet bind

| Section | Bytes |
|---------|------:|
| `APQPrivateMessage` staple | 973 |
| classical commit (`t`) | 672 |
| PQ partial-commit (no path, `pq`) | 292 |

The bind rides one `0x03` frame as a `0x05` staple —
`[0x05][u32 t][u32 pq]` — so the frame is 1573 B against a 43 B payload.

## Per-round PQ commit

The A.5 re-key `Commit'` carries the one large PQ `UpdatePath` of a round; the
per-round ratchet commit is instead a pathless PSK commit riding the bind
staple's `pq` section. Unsealed, that is 3896 B vs 292 B — the ~13x saving the
APQ↔ratchet rework buys. (The Rust bench prints the same comparison as OLD vs
NEW.)
