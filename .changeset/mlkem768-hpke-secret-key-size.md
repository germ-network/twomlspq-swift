---
"@germ-network/twomlspq-swift": patch
---

Add `MLKEM768CipherSuiteProvider.hpkeSecretKeySize` (96, the CryptoKit `integrityCheckedRepresentation` length) so snapshot restore can length-check ML-KEM-768 HPKE secret keys against `Nsk` (spec/snapshot.md §3.1).
