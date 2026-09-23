---
"@germ-network/twomlspq-swift": patch
---

`TwoMLSSession.restore` now throws `.archiveInvalid` when an archive is missing a group its recorded state implies. That covers a missing send group, a missing recv group (only an initiator that has not yet joined may lack one), and a missing Group_B PQ half once §A.3 has reached that side. It also rejects an archive whose classical group ids don't match the groups it restores.
