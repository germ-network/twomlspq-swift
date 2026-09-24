---
"@germ-network/twomlspq-swift": minor
---

Both §A.5 PQ legs now mint a fresh signature key for their own leaf: `pqRekeyBegin` stages one in recv-PQ, promoted on apply; `pqRekeyRespond` presents a fresh send-PQ key directly, under the SAME credential id it already presents. No wire-format change and no archive shape change.
