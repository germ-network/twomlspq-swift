---
"@germ-network/twomlspq-swift": minor
---

**Breaking:** removed `TwoMLSIdentity.generate(clientID:signingKey:signatureKey:pqSigningKey:pqSignatureKey:classicalProvider:pqProvider:)` and `TwoMLSIdentity.freshPQKeyPackage(pqProvider:)`. Neither has any known caller.

`Principal` no longer holds or shares a signing key across the invitations and sessions it mints: every `TwoMLSIdentity` `Principal.generateInvitation`/`TwoMLSSession.initiate(principal:)` produces now gets its own fresh, independent classical and PQ signing pair. KP′ (the §A.3 bootstrap KeyPackage) is now `identity`'s own PQ half directly, rather than a separately minted key package — one fewer key in play, and `EstablishResult.returnKeyPackage` on a born-dedicated acceptor is now the invitation's classical KeyPackage rather than the dedicated principal's (documented as initiator-only; no known caller reads it on the acceptor path).
