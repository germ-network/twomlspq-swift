---
"@germ-network/twomlspq-swift": minor
---

`Invitation.receive` takes an optional `expectedRemoteClientID`: the id the host authenticated for the initiator. A return key package naming any other id throws `.remoteIdentityMismatch` before the invitation's tables are touched. The default `nil` keeps today's behavior. The check binds ids, not keys: the host's authentication must cover this welcome (see README, Authenticating the initiator).
