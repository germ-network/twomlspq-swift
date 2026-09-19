import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420

/// The single funnel for the read-`group`-then-`takeOutput()` handoff on
/// `Transition` (a non-frozen `~Copyable` struct). Under `-O`, the Swift 6.4.0
/// Android-SDK compiler mis-owns that two-step in whatever body it optimizes
/// — SIL verification fails with "read-only scope invalidated by a local
/// write" (same family swift-mls 0.1.2 worked around in
/// `CombinerGroup.createAndAdd`; it reproduces only cross-compiling for
/// Android). `takeOutput()` is trivial and always inlines, so an
/// `@_optimize(none)` alone does not protect a caller; `@inline(never)` keeps
/// the handoff's SIL here, in this unoptimized body, instead.
@_optimize(none)
@inline(never)
func withTransitionHandoff<Output: ~Copyable & Sendable, Result>(
	_ transition: consuming MLS.RFC9420.Transition<Output>,
	_ body: (MLS.RFC9420.Group, consuming Output) throws -> Result
) rethrows -> Result {
	let group = transition.group
	let output = transition.takeOutput()
	return try body(group, output)
}
