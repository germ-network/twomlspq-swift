import MLSCodec
import MLSExtensions
import MLSProfileRFC9420

/// Scope a hand-rolled group operation under the two deployed-wire
/// divergences from spec-clean swift-mls: the `ComponentID` `uint32` width,
/// and the AppDataUpdate (`0x0008`) proposal's `opaque<V>` wrapper.
/// `CombinerGroup.establish`/`join` already wrap themselves in the width
/// half; every hand-rolled group create/commit/join and `PreSharedKeyID`
/// decode this module performs on Group_B (which is not a `CombinerGroup`)
/// must wrap itself explicitly, or the `apq_psk`/cross-party PSK ids and the
/// attestation proposal encode/decode at the wrong width or shape and
/// diverge from the deployed peer. The custom-proposal half makes every
/// decode inside the scope accept a wrapped `0x0008` as `Proposal.custom`
/// (`CommitEffect.customProposal`) rather than the typed, unwrapped
/// `.appDataUpdate` arm — this module only ever emits and expects the
/// wrapped form now, so scoping it here (rather than per call) keeps every
/// decode of one message agreeing, as `customProposalTypes`'s own doc
/// requires.
func withDeployedWireConventions<T>(_ body: () throws -> T) rethrows -> T {
	try MLS.Extensions.ComponentID.$componentIDWireWidth.withValue(.uint32) {
		try MLS.RFC9420.$customProposalTypes.withValue(
			[.init(.appDataUpdate)], operation: body)
	}
}
