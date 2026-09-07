import MLSCodec
import MLSExtensions

/// Scope a hand-rolled group operation under the deployed `ComponentID` wire
/// width. `CombinerGroup.establish`/`join` already wrap themselves in this;
/// every hand-rolled group create/commit/join and `PreSharedKeyID` decode this
/// module performs on Group_B (which is not a `CombinerGroup`) must wrap
/// itself explicitly, or the `apq_psk`/cross-party PSK ids encode/decode at
/// the wrong width and diverge from the deployed peer.
func withDeployedWireWidth<T>(_ body: () throws -> T) rethrows -> T {
	try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32, operation: body)
}
