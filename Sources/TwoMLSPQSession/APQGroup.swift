import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQCrypto

/// draft-ietf-mls-combiner-02 §6's sentinel for an unbound epoch field. The
/// Swift combiner does not export this (it has no deferred-half concept);
/// twomlspq-swift needs it for Group_B's `pqEpoch`.
let epochUnbound: UInt64 = .max

/// The directional `{classical, pq?}` group pair. Mirrors the Rust
/// `CombinerGroup{classical, pq: Option}` — the Swift `MLS.Combiner.CombinerGroup.pq`
/// is non-optional, so it cannot hold Group_B's deferred (pq-less) state; this
/// wrapper can.
@available(iOS 26, macOS 26, *)
struct APQGroup: Sendable {
	var classical: MLS.RFC9420.Group
	/// `nil` while the PQ half is deferred (Group_B pre-A.3).
	var pq: MLS.RFC9420.Group?
	var pskStore: MLS.Combiner.PSKStore
	let codepoints: MLS.Combiner.Codepoints
}

@available(iOS 26, macOS 26, *)
extension APQGroup {
	/// Group_A: establish a full pair via the combiner (PQ-first, `apq_psk`
	/// bound in), then `verifyPair` — `establish` does not call it internally
	/// (only `join` does), so the founder checks its own construction here.
	static func establishFull(
		classical: MLS.Combiner.HalfCreation,
		pq: MLS.Combiner.HalfCreation,
		mode: UInt8,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> (group: APQGroup, welcome: MLS.Combiner.APQWelcome) {
		let (combinerGroup, welcome) = try MLS.Combiner.CombinerGroup.establish(
			classical: classical, pq: pq, mode: mode,
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints)
		try combinerGroup.verifyPair()
		let group = APQGroup(
			classical: combinerGroup.classical, pq: combinerGroup.pq,
			pskStore: combinerGroup.pskStore, codepoints: codepoints)
		return (group, welcome)
	}

	/// Group_A join: both halves, `apq_psk` re-derived, `verifyPair` and the
	/// membership-consistency check — all performed inside `CombinerGroup.join`.
	static func joinFull(
		welcome: MLS.Combiner.APQWelcome,
		classicalCredentials: MLS.RFC9420.Group.JoinerCredentials,
		pqCredentials: MLS.RFC9420.Group.JoinerCredentials,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> APQGroup {
		let combinerGroup = try MLS.Combiner.CombinerGroup.join(
			welcome: welcome, classicalCredentials: classicalCredentials,
			pqCredentials: pqCredentials, classicalProvider: classicalProvider,
			pqProvider: pqProvider, codepoints: codepoints)
		return APQGroup(
			classical: combinerGroup.classical, pq: combinerGroup.pq,
			pskStore: combinerGroup.pskStore, codepoints: codepoints)
	}

	/// Group_B: a classical-only creation commit, hand-rolled (there is no
	/// `CombinerGroup` for a pq-less pair). Mirrors the combiner's private
	/// `createAndAdd`: `Group.create` the founder's one-member classical group
	/// carrying a deferred-PQ `APQInfo`, then commit `[Add(peer),
	/// PreSharedKey(crossPSK)]` — no `AppDataUpdate` attestation (a draft-02
	/// PARTIAL commit). Must run under the deployed `ComponentID` wire width:
	/// the cross-party PSK's id encodes at that width.
	static func establishClassicalOnly(
		founder: MLS.Combiner.HalfCreation,
		pqGroupID: Data,
		crossPSK: MLS.Combiner.ExportedPsk,
		nonce: Data,
		provider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> (group: APQGroup, welcome: MLS.RFC9420.Welcome) {
		try withDeployedWireWidth {
			let info = MLS.Combiner.APQInfo(
				tSessionGroupID: founder.groupID,
				pqSessionGroupID: pqGroupID,
				mode: 0,
				tCipherSuite: provider.cipherSuite,
				pqCipherSuite: MLS.CipherSuite(
					id: MLKEM768CipherSuiteProvider.cipherSuiteID),
				tEpoch: 1,
				pqEpoch: epochUnbound)
			let infoExtension = try info.asExtension(
				type: codepoints.apqInfoExtensionType)

			var pskStore = MLS.Combiner.PSKStore()
			pskStore.register(crossPSK)

			let epoch0 = try MLS.RFC9420.Group.create(
				provider, groupID: founder.groupID, leafNode: founder.leafNode,
				leafSecretKey: founder.leafSecretKey, extensions: [infoExtension],
				epochSecret: founder.epochSecret)
			let transition = try epoch0.committing(
				provider,
				proposals: [
					.proposal(.add(founder.peerKeyPackage)),
					.proposal(crossPSK.proposal(nonce: nonce)),
				],
				signingKey: founder.signingKey, randomness: founder.randomness,
				psk: pskStore.resolver())
			let adopted = transition.group
			let sent = transition.takeOutput()
			guard let welcome = sent.welcome else {
				throw MLS.Combiner.Error.missingWelcome
			}
			let advanced = try sent.takePending().apply(onto: adopted)

			let group = APQGroup(
				classical: advanced.group, pq: nil, pskStore: pskStore,
				codepoints: codepoints)
			return (group, welcome)
		}
	}

	/// Group_B join: a bare classical `Group.joining` resolving only the
	/// cross-party PSK, then the hand-written deferred-`APQInfo` check (there is
	/// no combiner `verifyPair` for a pq-less pair — it reads the absent
	/// `pq.context`).
	static func joinClassicalOnly(
		welcome: MLS.RFC9420.Welcome,
		credentials: MLS.RFC9420.Group.JoinerCredentials,
		crossPSK: MLS.Combiner.ExportedPsk,
		provider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> APQGroup {
		try withDeployedWireWidth {
			var pskStore = MLS.Combiner.PSKStore()
			pskStore.register(crossPSK)
			let pending = try MLS.RFC9420.Group.joining(
				provider, welcome: welcome, credentials: credentials,
				psk: pskStore.resolver())
			let transition = pending.apply()
			let group = transition.group
			try verifyAPQInfoDeferred(on: group, codepoints: codepoints)
			return APQGroup(
				classical: group, pq: nil, pskStore: pskStore,
				codepoints: codepoints)
		}
	}

	/// The deferred-pair analogue of `CombinerGroup.verifyPair()`, hand-written
	/// because the combiner has no deferred verifier: `APQInfo` present and
	/// naming this group; `tEpoch` matches the observed epoch and is bound
	/// (`!= epochUnbound`); `pqEpoch` is unbound; a pq group id is
	/// pre-allocated; and the suite pair is `(classical, 0xFDEA)`.
	static func verifyAPQInfoDeferred(
		on group: MLS.RFC9420.Group, codepoints: MLS.Combiner.Codepoints = .deployed
	) throws {
		guard
			let info = try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: group.context,
				type: codepoints.apqInfoExtensionType)
		else {
			throw TwoMLSError.deferredApqInfoMismatch
		}
		guard
			info.tSessionGroupID == group.context.groupID,
			info.tEpoch == group.context.epoch,
			info.tEpoch != epochUnbound,
			info.pqEpoch == epochUnbound,
			!info.pqSessionGroupID.isEmpty,
			info.tCipherSuite == group.context.cipherSuite,
			info.pqCipherSuite
				== MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID)
		else {
			throw TwoMLSError.deferredApqInfoMismatch
		}
	}
}

@available(iOS 26, macOS 26, *)
extension APQGroup {
	/// Non-blank leaf count — `TwoPartyRules.ensureTwoParty`'s reading of
	/// either half.
	var classicalRosterCount: Int { classical.tree.nonBlankLeaves().count }
}
