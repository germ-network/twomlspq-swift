---
"@germ-network/twomlspq-swift": patch
---

Approving a peer's offered Update (`queueProposal`) now validates the replacement leaf itself — its own signature and RFC 9420 section 7.3 policy (capabilities, credential-type mutual support, `required_capabilities`, and that its encryption key actually changed) — not only the enclosing proposal's framing signature. A folded approval whose commit then fails to build for any reason is dropped rather than left silently re-triable, and a still-outstanding (not yet canonical) authorization for it is withdrawn.
