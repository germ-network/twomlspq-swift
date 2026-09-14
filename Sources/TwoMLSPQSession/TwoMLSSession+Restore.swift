import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Session restore + reconcile (slice 8a, PR1)

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Restores a session from a mandatory Checkpoint and an optional, more
	/// recent Core. Mirrors the persisted-object reconcile the book
	/// describes: PQ state comes from the Checkpoint, everything else from
	/// whichever blob has the higher `stateSeq` — fail-closed throughout, so
	/// a blob this can't fully trust is rejected rather than partially
	/// adopted.
	///
	/// 1. decode both bodies; validate `version`/suite/`kind`.
	/// 2. no Core → the Checkpoint alone is the result.
	/// 3. both present → the two must agree on session identity (client id,
	///    signature key, both classical group ids) — guards an app that
	///    mis-pairs two different sessions' blobs.
	/// 4. `checkpoint.stateSeq >= core.stateSeq` → take the Checkpoint
	///    outright (`>=` skips a redundant splice on the tie a fresh
	///    baseline produces); else splice the Checkpoint's PQ halves into
	///    the (newer) Core, keeping the rest of the Core.
	/// 5. splicing only: the Core and Checkpoint PQ-epoch manifests must
	///    already agree, else the Core is stale relative to a PQ round the
	///    Checkpoint alone witnessed.
	/// 6. rebuild every group from its snapshot (combiner PSK stores start
	///    empty — a live `apq_psk`/cross-party PSK is already folded into
	///    the epoch secrets that referenced it; `sendCrossPSKLedger`, itself
	///    restored below, is what the live commit paths re-inject from, same
	///    as they always do).
	/// 7. re-verify each rebuilt pair's static `APQInfo` identity fields
	///    (partner group ids, mode, suite pair) — NOT the epoch-attestation
	///    fields `CombinerGroup.verifyPair()`/`APQGroup.verify*Deferred*`
	///    also carry, which are a join-time-only snapshot that goes stale
	///    the moment any later commit lands without re-attesting, so those
	///    live checks cannot run again post-establishment (see
	///    `verifyRestoredPairIdentity`). Still rejects a spliced-in PQ half
	///    naming the wrong partner group, even if it slipped past step 3's
	///    cheaper check.
	public static func restore(
		core: SecretArchive?,
		checkpoint: SecretArchive,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> TwoMLSSession {
		let ck = try checkpoint.decode(SessionArchive.self)
		try validateHeader(ck, expectedKind: .checkpoint)

		let winner: SessionArchive
		if let core {
			let co = try core.decode(SessionArchive.self)
			try validateHeader(co, expectedKind: .core)
			try validateIdentityAgreement(core: co, checkpoint: ck)

			if ck.stateSeq >= co.stateSeq {
				winner = ck
			} else {
				try validateManifestAgreement(core: co, checkpoint: ck)
				winner = splicingPQ(from: ck, into: co)
			}
		} else {
			winner = ck
		}

		try validateDecodeInvariants(winner)
		return try buildSession(
			from: winner, classicalProvider: classicalProvider, pqProvider: pqProvider)
	}

	// MARK: - Step 1: header

	private static func validateHeader(_ body: SessionArchive, expectedKind: BlobKind) throws {
		guard body.version == 1,
			body.classicalSuite == TwoMLSSuite.classical.id,
			body.pqSuite == TwoMLSSuite.pq.id,
			body.kind == expectedKind
		else {
			throw TwoMLSError.archiveInvalid
		}
	}

	// MARK: - Step 3: session-identity fail-closed

	private static func validateIdentityAgreement(
		core: SessionArchive, checkpoint: SessionArchive
	) throws {
		guard core.identity.clientID == checkpoint.identity.clientID,
			core.identity.signatureKey == checkpoint.identity.signatureKey,
			core.sendClassicalGroupID == checkpoint.sendClassicalGroupID,
			core.recvClassicalGroupID == checkpoint.recvClassicalGroupID
		else {
			throw TwoMLSError.archiveInvalid
		}
	}

	// MARK: - Step 5: PQ-manifest fail-closed (splicing branch only)

	/// `!=` on `Optional<UInt64>` already rejects a `Some` -> `nil` PQ-half
	/// regression on the Core relative to the Checkpoint (any mismatch
	/// between a present and an absent epoch compares unequal), so that
	/// case needs no separate clause.
	private static func validateManifestAgreement(
		core: SessionArchive, checkpoint: SessionArchive
	) throws {
		guard core.sendPQEpoch == checkpoint.sendPQEpoch,
			core.recvPQEpoch == checkpoint.recvPQEpoch
		else {
			throw TwoMLSError.archiveInvalid
		}
	}

	// MARK: - Step 4: splice

	/// The Core's own PQ-facing fields (both `GroupEntry.pq`s, and the
	/// manifest they mirror) are never populated to begin with — `Core`
	/// omits PQ trees regardless of kind — so this always pulls a real
	/// splice from the Checkpoint, never a no-op.
	private static func splicingPQ(from checkpoint: SessionArchive, into core: SessionArchive)
		-> SessionArchive
	{
		var spliced = core
		spliced.sendGroup?.pq = checkpoint.sendGroup?.pq
		spliced.recvGroup?.pq = checkpoint.recvGroup?.pq
		spliced.sendPQEpoch = checkpoint.sendPQEpoch
		spliced.recvPQEpoch = checkpoint.recvPQEpoch
		return spliced
	}

	// MARK: - Mid-A.3 decode invariants

	/// (a) the twin-field invariant (public KP′ must not outlive the
	/// private secret) is structurally vacuous post-derive-on-demand: there
	/// is no separate public field left to violate it. (c) `pqInflight` is
	/// serialized as one whole `Codable` value (`PQInflightArchive`), so a
	/// `.responding` round's `secret`/`wireCT` pair can't decode partially —
	/// a short archive fails at `decode` itself, before reaching here.
	private static func validateDecodeInvariants(_ body: SessionArchive) throws {
		if let commitment = body.expectedBootstrapKPCommitment, commitment.count != 32 {
			throw TwoMLSError.archiveInvalid
		}
	}

	// MARK: - Steps 6-7: rebuild groups + pair verification

	private static func buildSession(
		from body: SessionArchive,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> TwoMLSSession {
		// Group_A (this session's founding full pair) is always the
		// initiator's `sendGroup` / the responder's `recvGroup`; Group_B
		// (classical-only-then-bootstrapped) is the other side.
		let (sendGroup, recvGroup): (APQGroup?, APQGroup?) = try withDeployedWireConventions
		{
			if body.initiated {
				return (
					try restoreStandardPair(
						body.sendGroup,
						classicalProvider: classicalProvider,
						pqProvider: pqProvider),
					try restoreDeferredPair(
						body.recvGroup,
						classicalProvider: classicalProvider,
						pqProvider: pqProvider)
				)
			} else {
				return (
					try restoreDeferredPair(
						body.sendGroup,
						classicalProvider: classicalProvider,
						pqProvider: pqProvider),
					try restoreStandardPair(
						body.recvGroup,
						classicalProvider: classicalProvider,
						pqProvider: pqProvider)
				)
			}
		}

		var session = TwoMLSSession(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: .deployed, identity: try body.identity.restore(),
			auth: body.auth,
			sendGroup: sendGroup, recvGroup: recvGroup,
			currentStaple: body.currentStaple,
			pendingProposal: body.pendingProposal?.asTuple,
			joinedWelcomeDigest: body.joinedWelcomeDigest, initiated: body.initiated,
			bootstrapKPSecret: try body.bootstrapKPSecret?.restore(),
			expectedBootstrapKPCommitment: body.expectedBootstrapKPCommitment,
			pqTurnMine: body.pqTurnMine, owedBind: body.owedBind,
			pqInflight: try body.pqInflight?.restore(),
			pendingSideBand: body.pendingSideBand,
			peerAppliedSendEpoch: body.peerAppliedSendEpoch,
			lastCrossInjected: body.lastCrossInjected,
			lastCrossInjectedPQ: body.lastCrossInjectedPQ,
			lastSendPQExported: body.lastSendPQExported)

		session.offeredProposal = body.offeredProposal?.asTuple
		session.queuedProposal = body.queuedProposal?.asTuple
		session.stagedUpdates = body.stagedUpdates.map { $0.asTuple }
		session.sendCrossPSKLedger = try body.sendCrossPSKLedger.entries.mapValues {
			try $0.restore()
		}
		session.rotationCandidate = try body.rotationCandidate?.restore()
		return session
	}

	/// Group_A's shape: a `CombinerGroup`-established full pair. A Core-kind
	/// entry (or a pre-splice Core half) never carries `pq` — by the time
	/// this runs, reconcile has already spliced it in from the Checkpoint,
	/// so its absence here is a genuine corruption, not a normal Core
	/// omission.
	private static func restoreStandardPair(
		_ entry: GroupEntry?, classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> APQGroup? {
		guard let entry else { return nil }
		guard let pqSnapshot = entry.pq else { throw TwoMLSError.archiveInvalid }
		let classical = try MLS.RFC9420.Group.restore(
			from: entry.classical, classicalProvider)
		let pq = try MLS.RFC9420.Group.restore(from: pqSnapshot, pqProvider)
		try verifyRestoredPairIdentity(classical: classical, pq: pq)
		return APQGroup(
			classical: classical, pq: pq, pskStore: MLS.Combiner.PSKStore(),
			codepoints: .deployed)
	}

	/// Group_B's shape: classical-only until the §A.3 bootstrap founds its
	/// PQ half out of band (never via `CombinerGroup`).
	private static func restoreDeferredPair(
		_ entry: GroupEntry?, classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> APQGroup? {
		guard let entry else { return nil }
		let classical = try MLS.RFC9420.Group.restore(
			from: entry.classical, classicalProvider)
		guard let pqSnapshot = entry.pq else {
			try verifyRestoredDeferredIdentity(classical: classical, pq: nil)
			return APQGroup(
				classical: classical, pq: nil, pskStore: MLS.Combiner.PSKStore(),
				codepoints: .deployed)
		}
		let pq = try MLS.RFC9420.Group.restore(from: pqSnapshot, pqProvider)
		try verifyRestoredDeferredIdentity(classical: classical, pq: pq)
		return APQGroup(
			classical: classical, pq: pq, pskStore: MLS.Combiner.PSKStore(),
			codepoints: .deployed)
	}

	/// `CombinerGroup.verifyPair()`/`APQGroup.verify*Deferred*` (the live
	/// join-time checks) also compare `APQInfo`'s `tEpoch`/`pqEpoch`
	/// attestation against the group's OBSERVED epoch — valid only at the
	/// exact join moment they run at, never again: a `GroupContextExtensions`
	/// value carries over unchanged across an ordinary commit (RFC 9420),
	/// so that attestation is stale the moment any further commit lands
	/// without re-attesting (e.g. a routine fold). Restore can observe a
	/// session at any point in its life, so it checks only the fields that
	/// hold for a group's entire life — each half's `APQInfo` correctly
	/// naming the OTHER half's actual group id, and the two halves agreeing
	/// on mode/suite pair — which is exactly what catches a spliced-in PQ
	/// half naming the wrong partner group.
	private static func verifyRestoredPairIdentity(
		classical: MLS.RFC9420.Group, pq: MLS.RFC9420.Group
	) throws {
		let codepoints = MLS.Combiner.Codepoints.deployed
		guard
			let classicalInfo = try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: classical.context,
				type: codepoints.apqInfoExtensionType),
			let pqInfo = try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: pq.context, type: codepoints.apqInfoExtensionType)
		else {
			throw TwoMLSError.archiveInvalid
		}
		guard classicalInfo.tSessionGroupID == classical.context.groupID,
			classicalInfo.pqSessionGroupID == pq.context.groupID,
			pqInfo.tSessionGroupID == classical.context.groupID,
			pqInfo.pqSessionGroupID == pq.context.groupID,
			classicalInfo.mode == pqInfo.mode,
			classicalInfo.tCipherSuite == pqInfo.tCipherSuite,
			classicalInfo.pqCipherSuite == pqInfo.pqCipherSuite
		else {
			throw TwoMLSError.archiveInvalid
		}
	}

	/// The deferred-pair analogue of `verifyRestoredPairIdentity`, same
	/// epoch-free reasoning: Group_B's classical half must still name itself
	/// and its (pre-allocated or founded) PQ partner correctly, and — once a
	/// PQ half exists — the two must agree with each other.
	private static func verifyRestoredDeferredIdentity(
		classical: MLS.RFC9420.Group, pq: MLS.RFC9420.Group?
	) throws {
		let codepoints = MLS.Combiner.Codepoints.deployed
		guard
			let classicalInfo = try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: classical.context,
				type: codepoints.apqInfoExtensionType)
		else {
			throw TwoMLSError.archiveInvalid
		}
		guard classicalInfo.tSessionGroupID == classical.context.groupID,
			!classicalInfo.pqSessionGroupID.isEmpty,
			classicalInfo.tCipherSuite == TwoMLSSuite.classical,
			classicalInfo.pqCipherSuite == TwoMLSSuite.pq
		else {
			throw TwoMLSError.archiveInvalid
		}
		guard let pq else { return }
		guard
			let pqInfo = try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: pq.context, type: codepoints.apqInfoExtensionType)
		else {
			throw TwoMLSError.archiveInvalid
		}
		guard pqInfo.pqSessionGroupID == pq.context.groupID,
			pqInfo.tSessionGroupID == classicalInfo.tSessionGroupID,
			pqInfo.pqSessionGroupID == classicalInfo.pqSessionGroupID,
			pqInfo.mode == classicalInfo.mode,
			pqInfo.tCipherSuite == classicalInfo.tCipherSuite,
			pqInfo.pqCipherSuite == classicalInfo.pqCipherSuite
		else {
			throw TwoMLSError.archiveInvalid
		}
	}
}
