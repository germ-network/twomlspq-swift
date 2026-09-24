---
"@germ-network/twomlspq-swift": patch
---

Require swift-secret-bytes 0.7.1, whose keyed-container decode is linear. Restoring a group snapshot that holds many pending self-Updates in one epoch was quadratic before.
