---
"@germ-network/twomlspq-swift": minor
---

Every founding commit now omits its own `UpdatePath` — all four (Group_A classical and PQ, Group_B classical and PQ). The founding path is a redundant leaf self-update: it exists for forward secrecy, but there is no gap between group creation and the member-add it would cover, so it buys nothing. Each half is founded pathless. Wire deltas (43-byte payload, deployed suite): the Group_A-carrying rows — initial envelope A (6702 → 6616), pre-establishment app bare (6939 → 6853) and payload (6647 → 6561), and the first no-commit frame (5921 → 5835) — each shrink 86 B; the Group_B-only `0x01` (982), `0x15` (4212), and `0x0B` (936) rows were already pathless and are unchanged. The deployed Rust engine accepts a pathless classical founding (mls-rs rejects a pathless commit only when a proposal forces a path; Add/PSK never do). Requires swift-mls 0.1.7 (its `CombinerGroup.establish` no longer emits a founding UpdatePath).
