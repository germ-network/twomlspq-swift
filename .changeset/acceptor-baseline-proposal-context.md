---
"@germ-network/twomlspq-swift": minor
---

`Invitation.receive`'s return tuple gains a `baseline` element — the spawned session's baseline checkpoint `StateUpdate`, so an acceptor is restorable before its first PQ round (source-breaking for positional two-element destructuring). Add `TwoMLSSession.proposalContext()` and `QueuedProposal.context` — the raw proposal-context digests a host binds proposals to, matching the reference implementation. No wire or behavior change.
