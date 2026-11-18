---
"@germ-network/twomlspq-swift": patch
---

A commit round that fails no longer spends the cross-party `0xFF02` PSK: the receive-group export and its `lastCrossInjected` stamp are written back only with the rest of a successful round, so a retried round still binds that epoch's PSK.
