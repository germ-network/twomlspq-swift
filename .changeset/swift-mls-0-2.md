---
"@germ-network/twomlspq-swift": minor
---

Adopt swift-mls 0.2.0. Breaking: `TwoMLSSession.initiate`, `Invitation.receive` and `TwoMLSSession.pqBootstrapRespond` take a required `now: Date`, the host's current time, which RFC 9420 §7.3 checks against the lifetime of each KeyPackage they add. An expired or not-yet-valid peer KeyPackage throws `GroupError.leafNodeLifetimeOutOfRange` with state unchanged, so the call is retryable; a Rust KP′ answered after its 365-day lifetime can no longer found the PQ half. Migration mint maps a KeyPackage that fails to decode with a `WireError` (such as a repeated extension type) to `.archiveInvalid`.
