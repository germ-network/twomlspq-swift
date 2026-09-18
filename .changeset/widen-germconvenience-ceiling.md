---
"@germ-network/twomlspq-swift": patch
---

Widen the GermConvenience requirement from `.upToNextMinor(from: "0.8.0")` to `from: "0.8.0"`. Consumers pin this package exactly, so the minor ceiling capped their whole graph below GermConvenience 0.9.0 — that is what made 0.9.0 unreachable for CoreAppLogic (GER-2495). This package imports only the base `GermConvenience` product, which 0.9.0 leaves untouched (its change is in `GermConvenienceHTTP`).
