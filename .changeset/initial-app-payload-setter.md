---
"@germ-network/twomlspq-swift": minor
---

A pre-join initiator can now attach a host app payload with the new `setInitialAppPayload`, making the establishment envelope self-sufficient: once set, `pendingOutbound()` seals the payload alone instead of the bare welcome and return key package, and a later call replaces an earlier payload. The engine does not interpret the payload; the host is responsible for making it carry everything the acceptor needs.
