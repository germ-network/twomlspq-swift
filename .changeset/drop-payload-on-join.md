---
"@germ-network/twomlspq-swift": patch
---

A migrated pre-join initiator carrying a host app payload no longer fails to restore after it joins the acceptor's group: the payload now drains alongside the peer's key package the moment the join completes. A payload with no retained key package to re-seal to is now rejected at migration mint and at restore.
