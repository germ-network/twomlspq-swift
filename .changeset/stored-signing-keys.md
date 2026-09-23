---
"@germ-network/twomlspq-swift": minor
---

Sessions now store each group's own signing keys by role in the session archive, and signing reads the stored key directly; every message is signed with the same keys as before and nothing changes on the wire. Every state update, restore, and migration mint checks that each group's own leaf presents its stored key: a failing state update throws `.credentialUnknown` and returns nothing to persist, and a failing restore or mint throws `.archiveInvalid`. Session archives written by earlier versions no longer restore. A second rotation to a different id is now refused with `.rotationInFlight` until the receive group's epoch moves past the candidate's latest proposal.
