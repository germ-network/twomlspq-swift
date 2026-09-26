---
"@germ-network/twomlspq-swift": patch
---

Spec-conformance fix: the own-leaf catch-up is no longer a classical commit trigger. A plain `prepareToEncrypt()` with nothing queued and nothing owed no longer commits — a lagging send-classical leaf now rides the next round that commits for one of the book's two legal reasons (an approved peer Update fold, or a licensed owed-bind discharge), or worst case the PQ cadence, matching the deployed engine.
