---
"@germ-network/twomlspq-swift": minor
---

Every peer leaf a session admits — folded, offered, joined, or found as creator, on either the classical or the PQ half — must now advertise both the `APQInfo` extension and the `AppDataUpdate` proposal (book `wire-format.md`), or it is rejected with the new `TwoMLSError.leafCapabilityUnadvertised` before any state changes. A migrated session's mint applies the same check to every occupied leaf of the restored trees and to a retained `initialTheirKP`, refusing to mint a session around a capability-less peer leaf.
