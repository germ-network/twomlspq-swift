import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto

/// Germ's own sentinel for an unbound epoch field on a deferred (pq-less)
/// half — mirrors the Rust `apq/src/component.rs` `EPOCH_UNBOUND` constant.
/// draft-ietf-mls-combiner-02 has no deferred-half concept and defines no such
/// sentinel, so the Swift combiner does not export one; twomlspq-swift needs
/// it for Group_B's `pqEpoch`.
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
	///
	/// `appBinding`, when non-nil, is welded into the classical half only (the
	/// PQ half inherits coverage through the `APQInfo` half-binding, book
	/// group-rules.md rule 8) via the PR-0 `classicalExtraExtensions` seam.
	/// Empty is reserved-invalid (rejected defensively here too, even though
	/// every wired caller already rejects it at its own choke point — mirrors
	/// Rust's shared `with_app_binding`, which both directions call through);
	/// non-nil additionally requires both the founder's own leaf and the
	/// peer's leaf to advertise `0xF0A2` (swift-mls does not enforce this the
	/// way mls-rs's per-client extension registration does).
	static func establishFull(
		classical: MLS.Combiner.HalfCreation,
		pq: MLS.Combiner.HalfCreation,
		mode: UInt8,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		appBinding: Data? = nil,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> (group: APQGroup, welcome: MLS.Combiner.APQWelcome) {
		if let appBinding {
			guard !appBinding.isEmpty else { throw TwoMLSError.appBindingMismatch }
			try ensureAppBindingLeafAdvert(
				founder: classical.leafNode, peer: classical.peerKeyPackage.leafNode
			)
		}
		let (combinerGroup, welcome) = try MLS.Combiner.CombinerGroup.establish(
			classical: classical, pq: pq, mode: mode,
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			classicalExtraExtensions: try appBinding.map {
				[try AppBinding(data: $0).asExtension()]
			} ?? [],
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
	///
	/// `appBinding`, when non-nil, is appended as a second creation-time
	/// GroupContext extension (mirrors Group_A's `establishFull`, and the
	/// acceptor's mirror of the verified incoming binding — book
	/// group-rules.md rule 8). Empty is reserved-invalid — rejected
	/// defensively here even though the caller (`receive`) already rejects an
	/// empty expectation at its own choke point, mirroring Rust's shared
	/// `with_app_binding`; non-nil additionally requires both the founder's
	/// own leaf and the peer's leaf to advertise `0xF0A2`.
	static func establishClassicalOnly(
		founder: MLS.Combiner.HalfCreation,
		pqGroupID: Data,
		crossPSK: MLS.Combiner.ExportedPsk,
		nonce: Data,
		provider: any MLS.CipherSuiteProvider,
		appBinding: Data? = nil,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> (group: APQGroup, welcome: MLS.RFC9420.Welcome) {
		if let appBinding {
			guard !appBinding.isEmpty else { throw TwoMLSError.appBindingMismatch }
			try ensureAppBindingLeafAdvert(
				founder: founder.leafNode, peer: founder.peerKeyPackage.leafNode)
		}
		return try withDeployedWireConventions {
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
			var classicalExtensions = [infoExtension]
			if let appBinding {
				classicalExtensions.append(
					try AppBinding(data: appBinding).asExtension())
			}

			var pskStore = MLS.Combiner.PSKStore()
			pskStore.register(crossPSK)

			let epoch0 = try MLS.RFC9420.Group.create(
				provider, groupID: founder.groupID, leafNode: founder.leafNode,
				leafSecretKey: founder.leafSecretKey,
				extensions: classicalExtensions,
				epochSecret: founder.epochSecret)
			let proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(.add(founder.peerKeyPackage)),
				.proposal(crossPSK.proposal(nonce: nonce)),
			]
			try TwoPartyRules.validateCreationProposals(proposals)
			let transition = try epoch0.committing(
				provider, proposals: proposals, signingKey: founder.signingKey,
				randomness: founder.randomness, psk: pskStore.resolver())
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

	/// Group_B join: a bare classical `Group.joining` that now REQUIRES the
	/// cross-party `0xFF02` PSK the Welcome references — a recording resolver
	/// flags that swift-mls asked for the exact `(componentID, pskID)` this
	/// session derived off its own Group_A, and the join is refused
	/// (`.missingCrossPartyPSK`) if it never did, because the establishment PSK
	/// is the join's authenticity gate (`psk-binding.md`) — then pins the
	/// joined creator leaf's `.basic` identity to the caller-supplied
	/// `expectedCreatorID` (the invitation identity, `group-rules.md`;
	/// mirroring the Rust reference's bare-welcome creator ≡ invitation-identity
	/// contract-26 rule), then the hand-written deferred-`APQInfo` check (there
	/// is no combiner `verifyPair` for a pq-less pair — it reads the absent
	/// `pq.context`).
	static func joinClassicalOnly(
		welcome: MLS.RFC9420.Welcome,
		credentials: MLS.RFC9420.Group.JoinerCredentials,
		crossPSK: MLS.Combiner.ExportedPsk,
		expectedCreatorID: Data,
		provider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> APQGroup {
		try withDeployedWireConventions {
			var pskStore = MLS.Combiner.PSKStore()
			pskStore.register(crossPSK)
			var sawCrossPSK = false
			let resolve = pskStore.resolver()
			let pending = try MLS.RFC9420.Group.joining(
				provider, welcome: welcome, credentials: credentials,
				psk: { identifier in
					if case .application(let componentID, let pskID, _) =
						identifier,
						componentID == crossPSK.componentID,
						pskID == crossPSK.pskID
					{
						sawCrossPSK = true
					}
					return try resolve(identifier)
				})
			// The resolver is invoked exactly once per PSK id the Welcome's
			// `GroupSecrets` lists (swift-mls, after framing/membership
			// verification), so the flag is exact: a Welcome naming no PSK — or
			// some other id — never resolves and is refused rather than joined.
			guard sawCrossPSK else { throw TwoMLSError.missingCrossPartyPSK }
			let transition = pending.apply()
			let group = transition.group
			try TwoPartyRules.ensureTwoParty(group)
			let creatorID = try basicIdentifier(
				TwoMLSSession.joinedCreatorLeaf(of: group).credential)
			guard creatorID == expectedCreatorID else {
				throw TwoMLSError.remoteIdentityMismatch
			}
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
	/// pre-allocated; and the suite pair is `(classical, 0xFDEA)`. Reads the
	/// `APQInfo` off the live group and delegates the pure comparison to
	/// `checkAPQInfoDeferred`.
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
		try checkAPQInfoDeferred(
			info: info, observedGroupID: group.context.groupID,
			observedEpoch: group.context.epoch,
			classicalSuite: group.context.cipherSuite,
			pqSuite: MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID))
	}

	/// The pure half of `verifyAPQInfoDeferred`: a decoded `APQInfo` against
	/// the observed group id/epoch and the expected suite pair, taking no
	/// `Group` — exercisable against hand-built values.
	static func checkAPQInfoDeferred(
		info: MLS.Combiner.APQInfo,
		observedGroupID: Data,
		observedEpoch: UInt64,
		classicalSuite: MLS.CipherSuite,
		pqSuite: MLS.CipherSuite
	) throws {
		guard
			info.tSessionGroupID == observedGroupID,
			info.tEpoch == observedEpoch,
			info.tEpoch != epochUnbound,
			info.pqEpoch == epochUnbound,
			!info.pqSessionGroupID.isEmpty,
			info.tCipherSuite == classicalSuite,
			info.pqCipherSuite == pqSuite
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

// MARK: - §A.3 PQ bootstrap: Group_B.pq create-with-member and join

@available(iOS 26, macOS 26, *)
extension APQGroup {
	/// The responder (Bob) founds Group_B.pq: a one-member PQ creation
	/// carrying the **mirror** `APQInfo` (`{tEpoch: EPOCH_UNBOUND, pqEpoch:
	/// 1}` — the mirror of the classical half's `{tEpoch: 1, pqEpoch:
	/// EPOCH_UNBOUND}`), then a bare `Add(peerBootstrapKP)` commit — no
	/// `AppDataUpdate` attestation, a draft-02 PARTIAL creation. The pq
	/// group id is the one pre-allocated in `sendGroupClassical`'s own
	/// `APQInfo.pqSessionGroupID` at establishment. Must run under the
	/// deployed `ComponentID` wire width.
	///
	/// Seam: does not check `peerBootstrapKP`'s leaf credential names the
	/// already-established peer (see `TwoMLSSession.pqBootstrapRespond`).
	static func foundPQHalf(
		sendGroupClassical: MLS.RFC9420.Group,
		ownPQLeaf: MLS.RFC9420.LeafNode,
		ownPQLeafSecret: MLS.HpkeSecretKey,
		signingKey: MLS.SignatureSecretKey,
		peerBootstrapKP: MLS.RFC9420.KeyPackage,
		randomness: MLS.RFC9420.Group.CommitRandomness,
		epochSecret: SecretBytes,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> (pqGroup: MLS.RFC9420.Group, welcome: MLS.RFC9420.Welcome) {
		try withDeployedWireConventions {
			guard
				let classicalInfo = try MLS.Combiner.APQInfo.read(
					fromExtensionsOf: sendGroupClassical.context,
					type: codepoints.apqInfoExtensionType)
			else { throw TwoMLSError.deferredApqInfoMismatch }
			let pqGroupID = classicalInfo.pqSessionGroupID

			let mirrorInfo = MLS.Combiner.APQInfo(
				tSessionGroupID: classicalInfo.tSessionGroupID,
				pqSessionGroupID: pqGroupID,
				mode: classicalInfo.mode,
				tCipherSuite: classicalInfo.tCipherSuite,
				pqCipherSuite: classicalInfo.pqCipherSuite,
				tEpoch: epochUnbound,
				pqEpoch: 1)
			let mirrorExtension = try mirrorInfo.asExtension(
				type: codepoints.apqInfoExtensionType)

			let epoch0 = try MLS.RFC9420.Group.create(
				pqProvider, groupID: pqGroupID, leafNode: ownPQLeaf,
				leafSecretKey: ownPQLeafSecret, extensions: [mirrorExtension],
				epochSecret: epochSecret)

			let proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(.add(peerBootstrapKP))
			]
			try TwoPartyRules.validateCreationProposals(proposals)
			let transition = try epoch0.committing(
				pqProvider, proposals: proposals, signingKey: signingKey,
				randomness: randomness, includePath: true, psk: { _ in nil })
			let adopted = transition.group
			let sent = transition.takeOutput()
			guard let welcome = sent.welcome else {
				throw MLS.Combiner.Error.missingWelcome
			}
			let advanced = try sent.takePending().apply(onto: adopted)

			return (advanced.group, welcome)
		}
	}

	/// The initiator (Alice) joins Group_B.pq off the responder's Welcome′,
	/// using the session-owned bootstrap-KP secrets (KP′) as joiner
	/// credentials, then verifies the mirror `APQInfo` against Group_B's
	/// already-joined classical half. Must run under the deployed
	/// `ComponentID` wire width.
	static func joinPQHalf(
		welcome: MLS.RFC9420.Welcome,
		credentials: MLS.RFC9420.Group.JoinerCredentials,
		classicalHalfForPairCheck: MLS.RFC9420.Group,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> MLS.RFC9420.Group {
		try withDeployedWireConventions {
			let pending = try MLS.RFC9420.Group.joining(
				pqProvider, welcome: welcome, credentials: credentials,
				psk: { _ in nil })
			let group = pending.apply().group
			try verifyDeferredPQMirrorInfo(
				pqGroup: group, classicalGroup: classicalHalfForPairCheck,
				codepoints: codepoints)
			try TwoPartyRules.ensureTwoParty(group)
			return group
		}
	}

	/// The joined pq group's mirror `APQInfo` against Group_B's classical
	/// half: names this pq group, `pqEpoch == 1` (the observed epoch),
	/// `tEpoch` unbound, and the 5 identity fields (everything but the two
	/// epoch fields) equal to the classical half's `APQInfo` — `identityFieldsMatch`
	/// is combiner-internal, so those 5 fields are compared by hand in
	/// `checkDeferredPQMirror`.
	static func verifyDeferredPQMirrorInfo(
		pqGroup: MLS.RFC9420.Group,
		classicalGroup: MLS.RFC9420.Group,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws {
		guard
			let pqInfo = try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: pqGroup.context,
				type: codepoints.apqInfoExtensionType)
		else { throw TwoMLSError.deferredPQMirrorMismatch }
		guard
			let classicalInfo = try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: classicalGroup.context,
				type: codepoints.apqInfoExtensionType)
		else { throw TwoMLSError.deferredPQMirrorMismatch }
		try checkDeferredPQMirror(
			pqInfo: pqInfo, classicalInfo: classicalInfo,
			observedPQGroupID: pqGroup.context.groupID,
			observedPQEpoch: pqGroup.context.epoch)
	}

	/// The pure half of `verifyDeferredPQMirrorInfo`: two decoded `APQInfo`s
	/// against the observed pq group id/epoch, taking no `Group` —
	/// exercisable against hand-built values.
	static func checkDeferredPQMirror(
		pqInfo: MLS.Combiner.APQInfo,
		classicalInfo: MLS.Combiner.APQInfo,
		observedPQGroupID: Data,
		observedPQEpoch: UInt64
	) throws {
		guard
			pqInfo.pqSessionGroupID == observedPQGroupID,
			pqInfo.tEpoch == epochUnbound,
			pqInfo.pqEpoch == observedPQEpoch,
			pqInfo.tSessionGroupID == classicalInfo.tSessionGroupID,
			pqInfo.pqSessionGroupID == classicalInfo.pqSessionGroupID,
			pqInfo.mode == classicalInfo.mode,
			pqInfo.tCipherSuite == classicalInfo.tCipherSuite,
			pqInfo.pqCipherSuite == classicalInfo.pqCipherSuite,
			pqInfo.tCipherSuite == TwoMLSSuite.classical,
			pqInfo.pqCipherSuite == TwoMLSSuite.pq
		else {
			throw TwoMLSError.deferredPQMirrorMismatch
		}
	}
}
