---
"@germ-network/twomlspq-swift": minor
---

New public error case `TwoMLSError.messageFromUnretainedEpoch(epoch:)`. A peer app message sealed at an epoch this session no longer holds message secrets for (`MLS.RFC9420.GroupError.messageFromUnretainedEpoch`) is folded at the message-path `unprotect` boundary into this classified case rather than crossing as an unmapped generic error. Two indistinguishable shapes: an epoch we were in but have pruned past the retention window (a late/replayed frame, or a behind-restored sender's fresh seal at its rewound epoch), or an epoch above current (misordered or forged). The common host action is discard-as-stale; re-route at the invitation layer or re-establish only with independent evidence the peer was restored.
