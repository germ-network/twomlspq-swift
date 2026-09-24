---
"@germ-network/twomlspq-swift": minor
---

Migration inputs on stored per-group signing keys: `MigratedLeafKeys` (authoritative per-group keys, superseding the temporary owner-keyed conversion when supplied), `MigratedOwnOfferWindow`/`SessionMigration.mintOwnOfferWindow` (an on-demand own-Update-offer blob, never the session archives), and `MigratedDeployedState` (the deployed engine's PQ-wedge and no-custody flags), all wired into `SessionMigration.mintArchive(deployedState:)`. `processIncoming`/`processIncomingApproved` gain a defaulted `ownOfferWindow:` blob parameter to resolve a staple that names an offer outside the framed store. `TwoMLSSession` gains the read-only `pqSideBandWedged`, `noCustody`, `canSend`, and `ownOfferWindowID` queries.

The own-leaf catch-up generalizes beyond rotation and born-dedicated custody: any own leaf lagging behind its party's current canonical credential catches up via that group's own `pending[current id]`, in every group, not just the ones native code used to cover — fixing a latent brick where a migrated or otherwise-lagging session that won a rotation and then rotated again natively could lose its catch-up key.

Mint now drops an unverifiable parked §A.5 `Upd'` at import rather than minting a session that can never apply its own re-key round.

Four new `TwoMLSError` cases — `ownOfferWindowRequired`, `ownOfferUnavailable`, `pqSideBandWedged`, `leafCustodyUnavailable` — source-breaking for an exhaustive switch over `TwoMLSError`.

Requires swift-mls 0.1.6.
