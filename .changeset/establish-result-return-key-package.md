---
"@germ-network/twomlspq-swift": patch
---

Add `EstablishResult.returnKeyPackage`, carrying the established session's own classical KeyPackage so an initiator/replier can put it into the welcome's keyMaterial (the value the Rust `PQClient.reply` returns as `myKeyPackage`).
