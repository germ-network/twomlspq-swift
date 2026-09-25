import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import SecretBytes

// MARK: - Session restore + reconcile (slice 8a, PR1)

// Gated because it bridges to a live iOS 26 port type — see IdentityArchive in SessionArchive.swift.
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
	///    BOTH independent per-half signature keys (D1), both classical
	///    group ids) — guards an app that mis-pairs two different sessions'
	///    blobs.
	/// 4. `checkpoint.stateSeq >= core.stateSeq` → take the Checkpoint
	///    outright (`>=` skips a redundant splice on the tie a fresh
	///    baseline produces); else splice the Checkpoint's PQ halves (trees
	///    AND `leafKeys.sendPQ`/`recvPQ`, which a Core never carries) into
	///    the (newer) Core, keeping the rest of the Core.
	/// 5. splicing only: the Core and Checkpoint PQ-epoch manifests —
	///    epochs and key-set fingerprints alike — must already agree, else
	///    the Core is stale relative to a PQ round the Checkpoint alone
	///    witnessed.
	/// 6. require every group the winner's recorded state implies
	///    (`validateGroupPresence`), then rebuild every group from its
	///    snapshot (combiner PSK stores start empty — a live
	///    `apq_psk`/cross-party PSK is already folded into the epoch secrets
	///    that referenced it; `sendCrossPSKLedger`, itself restored below, is
	///    what the live commit paths re-inject from, same as they always do).
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
		let ck = try decodeArchive(checkpoint)
		try validateHeader(ck, expectedKind: .checkpoint)

		let winner: SessionArchive
		if let core {
			let co = try decodeArchive(core)
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
		try validateGroupPresence(winner)
		return try buildSession(
			from: winner, classicalProvider: classicalProvider, pqProvider: pqProvider)
	}

	// MARK: - Step 1: decode + header

	/// `SecretArchive.decode` throws `DecodingError` (a shape/type mismatch)
	/// or `SecretArchiveError` (malformed CBOR, bounds, internal decode
	/// failure) for anything this format doesn't recognize — both fold into
	/// the one uniform `archiveInvalid` `restore` promises, rather than
	/// leaking a codec-internal error type to callers.
	private static func decodeArchive(_ archive: SecretArchive) throws -> SessionArchive {
		do {
			return try archive.decode(SessionArchive.self)
		} catch is DecodingError {
			throw TwoMLSError.archiveInvalid
		} catch is SecretArchiveError {
			throw TwoMLSError.archiveInvalid
		}
	}

	private static func validateHeader(_ body: SessionArchive, expectedKind: BlobKind) throws {
		guard body.version == sessionArchiveVersion,
			body.classicalSuite == TwoMLSSuite.classical.id,
			body.pqSuite == TwoMLSSuite.pq.id,
			body.kind == expectedKind
		else {
			throw TwoMLSError.archiveInvalid
		}
		// `leafKeys`' own PQ sets are kind-gated the same way `GroupEntry.pq`
		// is: present on a Checkpoint, absent on a Core. A body that gets
		// this backwards — a Checkpoint missing them, or a Core carrying
		// them — is malformed regardless of what `kind` itself claims.
		switch expectedKind {
		case .checkpoint:
			guard body.leafKeys.sendPQ != nil, body.leafKeys.recvPQ != nil else {
				throw TwoMLSError.archiveInvalid
			}
		case .core:
			guard body.leafKeys.sendPQ == nil, body.leafKeys.recvPQ == nil else {
				throw TwoMLSError.archiveInvalid
			}
		}
	}

	// MARK: - Step 3: session-identity fail-closed

	/// Internal rather than `private`, so this one check is directly
	/// unit-testable in isolation from step 7's pair-identity check
	/// (`SessionArchiveTests.swift`); every other restore helper stays
	/// `private`.
	///
	/// `recvClassicalGroupID` cannot be a plain equality clause like the
	/// other three: Alice's baseline Checkpoint is minted at `initiate`
	/// with no recv group yet (`nil`), and her very next Core — taken once
	/// Bob's first frame has joined her into Group_B — has it set. That is
	/// the ordinary mid-A.3 transition, not a mispair, so a lone `nil` is
	/// tolerated exactly when it names the OLDER of the two blobs (by
	/// `stateSeq`); once both sides have a recv group, they must agree.
	static func validateIdentityAgreement(
		core: SessionArchive, checkpoint: SessionArchive
	) throws {
		guard core.identity.clientID == checkpoint.identity.clientID,
			core.identity.signatureKey == checkpoint.identity.signatureKey,
			core.identity.pqSignatureKey == checkpoint.identity.pqSignatureKey,
			core.sendClassicalGroupID == checkpoint.sendClassicalGroupID
		else {
			throw TwoMLSError.archiveInvalid
		}
		switch (core.recvClassicalGroupID, checkpoint.recvClassicalGroupID) {
		case (nil, nil):
			break
		case (let coreID?, let checkpointID?):
			guard coreID == checkpointID else { throw TwoMLSError.archiveInvalid }
		case (nil, .some):
			guard core.stateSeq < checkpoint.stateSeq else {
				throw TwoMLSError.archiveInvalid
			}
		case (.some, nil):
			guard checkpoint.stateSeq < core.stateSeq else {
				throw TwoMLSError.archiveInvalid
			}
		}
	}

	// MARK: - Step 5: PQ-manifest fail-closed (splicing branch only)

	/// `!=` on `Optional<UInt64>` already rejects a `Some` -> `nil` PQ-half
	/// regression on the Core relative to the Checkpoint (any mismatch
	/// between a present and an absent epoch compares unequal), so that
	/// case needs no separate clause. The fingerprint comparison catches
	/// what the epoch alone would miss: a PQ key-set change that didn't
	/// also move the epoch (`GroupKeySetFingerprint`'s own doc explains
	/// why that's possible) — without it, a stale Core could pass the
	/// epoch check and still splice in a Checkpoint whose PQ trees disagree
	/// with what the Core itself last claimed.
	private static func validateManifestAgreement(
		core: SessionArchive, checkpoint: SessionArchive
	) throws {
		guard core.sendPQEpoch == checkpoint.sendPQEpoch,
			core.recvPQEpoch == checkpoint.recvPQEpoch,
			core.sendPQKeysFingerprint == checkpoint.sendPQKeysFingerprint,
			core.recvPQKeysFingerprint == checkpoint.recvPQKeysFingerprint
		else {
			throw TwoMLSError.archiveInvalid
		}
	}

	// MARK: - Step 4: splice

	/// The Core's own PQ-facing fields (both `GroupEntry.pq`s, `leafKeys`'
	/// `sendPQ`/`recvPQ`, and the manifest they mirror) are never populated
	/// to begin with — a Core omits PQ trees and PQ key sets alike,
	/// regardless of kind — so this always pulls a real splice from the
	/// Checkpoint, never a no-op.
	private static func splicingPQ(from checkpoint: SessionArchive, into core: SessionArchive)
		-> SessionArchive
	{
		var spliced = core
		spliced.sendGroup?.pq = checkpoint.sendGroup?.pq
		spliced.recvGroup?.pq = checkpoint.recvGroup?.pq
		spliced.sendPQEpoch = checkpoint.sendPQEpoch
		spliced.recvPQEpoch = checkpoint.recvPQEpoch
		spliced.leafKeys.sendPQ = checkpoint.leafKeys.sendPQ
		spliced.leafKeys.recvPQ = checkpoint.leafKeys.recvPQ
		return spliced
	}

	// MARK: - Mid-A.3 decode invariants

	/// (a) the twin-field invariant (public KP′ must not outlive the
	/// private secret) is structurally vacuous post-derive-on-demand: there
	/// is no separate public field left to violate it. (c) `pqInflight` is
	/// serialized as one whole `Codable` value (`PQInflightArchive`), so a
	/// `.responding` round's `secret`/`wireCT` pair can't decode partially —
	/// a short archive fails at `decode` itself, before reaching here.
	/// Internal (not `private`): the session migration minter
	/// (`SessionMigration.swift`) runs it kind-independently at mint — a
	/// core-kind mint gets no trial restore, which is the only other path to
	/// these checks.
	static func validateDecodeInvariants(_ body: SessionArchive) throws {
		if let commitment = body.expectedBootstrapKPCommitment, commitment.count != 32 {
			throw TwoMLSError.archiveInvalid
		}
		// Every restored rendezvous address is a 32-byte exporter output; a
		// wrong-length entry is a corrupt or adversarial archive — fail closed.
		if let listen = body.listenRendezvous,
			!listen.entries.values.allSatisfy({ $0.count == 32 })
		{
			throw TwoMLSError.archiveInvalid
		}
		// PR2: both header-key windows are 32-byte AEAD keys (the header
		// AEAD's own key size), validated the same way (book
		// header-encryption.md:456-458).
		if let classical = body.recvHeaderKeys,
			!classical.entries.values.allSatisfy({ $0.count == 32 })
		{
			throw TwoMLSError.archiveInvalid
		}
		if let pq = body.recvHeaderKeysPQ,
			!pq.entries.values.allSatisfy({ $0.count == 32 })
		{
			throw TwoMLSError.archiveInvalid
		}
		// Same reasoning, the `0xFF03` attachment components
		// (+Attachment.swift): each is a `safeExportSecret` output, exactly
		// `KDF.Nh` (32 bytes for the deployed classical suite) — a
		// wrong-length entry is corrupt or adversarial, same fail-closed
		// treatment as the windows above.
		if let sendAttachment = body.sendAttachmentLedger,
			!sendAttachment.entries.values.allSatisfy({
				$0.wrappedValue.byteCount == 32
			})
		{
			throw TwoMLSError.archiveInvalid
		}
		if let recvAttachment = body.recvAttachmentLedger,
			!recvAttachment.entries.values.allSatisfy({
				$0.wrappedValue.byteCount == 32
			})
		{
			throw TwoMLSError.archiveInvalid
		}
	}

	// MARK: - Pin safety check (book group-rules.md rule 4)

	/// A safety check, not exact equality (a pre-fix archive's empty
	/// `pinned` still passes; the next `stateUpdate` normalizes it to the
	/// true normal form — `pqPinnedAuth()`). For each owner o, given P(o) =
	/// what o's live PQ leaves actually present (`livePQPresentedIDs`),
	/// H(o) = `history`, A(o) = `authorizedNext`: (a) no duplicate ids in
	/// `pinned`; (b) `pinned` ⊆ P(o) ∖ (A(o) ∖ H(o)) — no stale pin, no
	/// pinned candidate; (c) P(o) ⊆ H(o) ∪ `pinned` ∪ A(o) — every presented
	/// id is covered by something. `.archiveInvalid` on any violation.
	private static func validatePQPins(
		_ auth: AuthCore, sendPQ: MLS.RFC9420.Group?, recvPQ: MLS.RFC9420.Group?
	) throws {
		guard
			let presented = try? livePQPresentedIDs(sendPQ: sendPQ, recvPQ: recvPQ)
		else { throw TwoMLSError.archiveInvalid }
		try validatePQPins(auth.mine, presented: presented.mine)
		try validatePQPins(auth.theirs, presented: presented.theirs)
	}

	private static func validatePQPins(_ sequence: PartySequence, presented: Set<Data>) throws {
		guard Set(sequence.pinned).count == sequence.pinned.count else {
			throw TwoMLSError.archiveInvalid
		}
		let candidates = Set(sequence.authorizedNext).subtracting(sequence.history)
		let allowedPins = presented.subtracting(candidates)
		guard Set(sequence.pinned).isSubset(of: allowedPins) else {
			throw TwoMLSError.archiveInvalid
		}
		let covered =
			Set(sequence.history).union(sequence.pinned).union(sequence.authorizedNext)
		guard presented.isSubset(of: covered) else {
			throw TwoMLSError.archiveInvalid
		}
	}

	// MARK: - Step 6: group presence

	/// Group_A (the initiator's send, the responder's recv) is a full pair
	/// from construction. Group_B's classical half is the responder's send
	/// from construction but the initiator's recv only from its join, and its
	/// PQ half exists only once §A.3 founds (responder) or joins (initiator)
	/// it. So exactly two absences are legitimate:
	///  - a pre-join initiator's recv group — the one state whose archive
	///    still carries the classical init secret (`IdentityArchive`); its
	///    §A.3 round is registered at `initiate` (`.bootstrapInitiated`) but
	///    cannot have gone any further, since that needs the join itself;
	///  - Group_B's PQ half before §A.3 reaches that side — required once
	///    any field names it: an export watermark, an owed bind (a commit on
	///    the send PQ half), or an inflight round that runs on it.
	/// PQ presence reads the manifest, which a Core carries too;
	/// `verifyManifestMatchesRebuiltGroups` ties it to the rebuilt groups.
	private static func validateGroupPresence(_ body: SessionArchive) throws {
		let preJoin = body.initiated && body.identity.classicalInitSecretKey != nil
		var needsRecvGroup = !preJoin
		var needsSendPQ =
			body.initiated || body.owedBind != nil || body.lastSendPQExported != nil
		var needsRecvPQ = !body.initiated || body.lastCrossInjectedPQ != nil
		switch body.pqInflight {
		case .bootstrapInitiated:
			break
		case .bootstrapResponded, .initiating, .rekeyResponded:
			needsSendPQ = true
		case .responding, .rekeyInitiated:
			needsRecvPQ = true
		case nil:
			break
		}
		// A pre-join initiator can only ever be pre- or newly-registered:
		// anything further along (a rekey/ratchet round, a responder round,
		// the round already answered) implies a recv group that isn't here.
		if preJoin {
			switch body.pqInflight {
			case nil, .bootstrapInitiated:
				break
			default:
				throw TwoMLSError.archiveInvalid
			}
		}
		guard body.sendGroup != nil,
			!needsRecvGroup || body.recvGroup != nil,
			!needsSendPQ || body.sendPQEpoch != nil,
			!needsRecvPQ || body.recvPQEpoch != nil
		else {
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
		try verifyManifestMatchesRebuiltGroups(
			body, sendGroup: sendGroup, recvGroup: recvGroup)

		let identity = try body.identity.restore()
		let bootstrapKPSecret = try body.bootstrapKPSecret?.restore()
		let pqInflight = try body.pqInflight?.restore()
		let rotationCandidate = body.rotationCandidate?.restore()
		// `LeafKeysArchive.restore()` runs the archive-level checks (every
		// key derives; every pending target non-empty/unique, and — since
		// the splice above already ran — the PQ sets are present);
		// `validateLeafKeys` then runs the semantic ones against the
		// just-rebuilt groups and the rest of this same decoded state.
		let leafKeys = try body.leafKeys.restore()
		try verifyManifestFingerprintsMatchRestoredLeafKeys(body, leafKeys: leafKeys)

		// Archive keys 44/45: decode + validate the deployed
		// carry, before `validateLeafKeys` — rule 3's `noCustody` and check
		// 6/7's window-shaped state both need it in hand first.
		let (pqWedge, noCustody, ownOfferWindowRecord) = try decodeDeployedCarry(
			body.deployedCarry, recvGroup: recvGroup)
		try validateInitialAppPayload(
			body.initialAppPayload, initiated: body.initiated, recvGroup: recvGroup,
			hasInitialTheirKP: body.initialTheirKP != nil)

		try validateLeafKeys(
			leafKeys, sendGroup: sendGroup, recvGroup: recvGroup, identity: identity,
			bootstrapKPSecret: bootstrapKPSecret,
			stagedUpdates: body.stagedUpdates.map { $0.asTuple },
			pendingProposal: body.pendingProposal?.asTuple,
			pqInflight: pqInflight, rotationCandidate: rotationCandidate,
			auth: body.auth,
			mode: .restore, noCustody: noCustody,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		try validatePQPins(body.auth, sendPQ: sendGroup?.pq, recvPQ: recvGroup?.pq)

		// `.deployed` is hard-coded, never archived: the port only ever
		// constructs a session under the deployed codepoints
		// (`makeSessionArchive` asserts as much at encode).
		var session = TwoMLSSession(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: .deployed, identity: identity,
			auth: body.auth,
			sendGroup: sendGroup, recvGroup: recvGroup,
			currentStaple: body.currentStaple,
			pendingProposal: body.pendingProposal?.asTuple,
			joinedWelcomeDigest: body.joinedWelcomeDigest, initiated: body.initiated,
			bootstrapKPSecret: bootstrapKPSecret,
			expectedBootstrapKPCommitment: body.expectedBootstrapKPCommitment,
			initialTheirKP: try body.initialTheirKP?.restore(),
			pqTurnMine: body.pqTurnMine, owedBind: body.owedBind,
			pqInflight: pqInflight,
			pendingSideBand: body.pendingSideBand,
			peerAppliedSendEpoch: body.peerAppliedSendEpoch,
			lastCrossInjected: body.lastCrossInjected,
			lastCrossInjectedPQ: body.lastCrossInjectedPQ,
			lastSendPQExported: body.lastSendPQExported,
			spawnToken: body.spawnToken,
			owesEstablishmentEnvelope: body.owesEstablishmentEnvelope ?? false,
			ownOfferWindow: ownOfferWindowRecord,
			pqWedge: pqWedge,
			noCustody: noCustody,
			initialAppPayload: body.initialAppPayload,
			leafKeys: leafKeys)

		session.offeredProposal = body.offeredProposal?.asTuple
		session.queuedProposal = body.queuedProposal?.asTuple
		session.stagedUpdates = body.stagedUpdates.map { $0.asTuple }
		session.sendCrossPSKLedger = try body.sendCrossPSKLedger.entries.mapValues {
			try $0.restore()
		}
		// Optional-with-empty-default, same reasoning as `listenRendezvous`
		// below: absent on a pre-existing archive, in which case this starts
		// empty and the capture-on-restore call further down populates it.
		session.sendAttachmentLedger =
			body.sendAttachmentLedger?.entries.mapValues { $0.wrappedValue } ?? [:]
		session.recvAttachmentLedger =
			body.recvAttachmentLedger?.entries.mapValues { $0.wrappedValue } ?? [:]
		session.rotationCandidate = try body.rotationCandidate?.restore()
		// Optional-with-empty-default (SessionArchive.swift): absent on a
		// pre-existing v1 archive, in which case this starts empty. Restore
		// is itself a capture site — re-derive the current classical epoch's
		// address at once (idempotent when the map already carries it), so
		// even an archive that omits the current epoch lists where the peer
		// posts NOW rather than only after the next commit.
		session.listenRendezvous = body.listenRendezvous?.entries ?? [:]
		// PR2: restore is a construction site for the header-key windows too
		// — re-derive the current classical + PQ header keys so a restored
		// session can open an in-flight frame at once.
		session.recvHeaderKeys = body.recvHeaderKeys?.entries ?? [:]
		session.recvHeaderKeysPQ = body.recvHeaderKeysPQ?.entries ?? [:]
		try session.recordListenRendezvous()
		try session.recordPQHeaderKey()
		// Same "restore is itself a capture site" reasoning, `0xFF03`
		// attachment component (+Attachment.swift): unlike the rendezvous/
		// header-key exporters above, `safeExportSecret` CONSUMES its leaf,
		// so a live capture here can genuinely fail — only when the
		// restored group's exporter tree shows the current epoch's
		// component already spent while the archived ledger (just restored
		// above) does not carry it, an internal inconsistency a corrupt or
		// tampered archive could produce. Maps that specific
		// `ExporterTree.ExportError` to the one uniform `archiveInvalid`
		// `restore` promises, rather than leaking a profile-internal error
		// type to callers — `safeExportSecret`'s other possible throw,
		// `GroupError.exporterTreeUnavailable`, is left uncaught: it would
		// mean the restored group itself is internally inconsistent (no
		// exporter tree for its own current epoch at all), which is
		// unreachable for any archive this port ever writes.
		do {
			try session.captureSendAttachmentComponent()
			try session.captureRecvAttachmentComponent()
		} catch is MLS.Extensions.ExporterTree.ExportError {
			throw TwoMLSError.archiveInvalid
		}
		// Return cadence (slice 8a): the reconciled `stateSeq` becomes both
		// the live counter to advance from and `currentStapleSeq`'s seed — a
		// safe, never-under value for the durability gate (this blob is
		// already durable, or the app could not have restored from it), even
		// if it overstates exactly when `currentStaple` was first installed.
		session.stateSeq = body.stateSeq
		session.currentStapleSeq = body.stateSeq
		// The winning body's own PQ-epoch manifest IS a manifest this session
		// can prove was actually persisted (it is exactly the `checkpoint:`
		// archive passed in, or splices from it) — seeding the sticky
		// checkpoint invariant from it, rather than leaving it at `nil`,
		// means a `.core` minted right after restore (before anything has
		// moved) is never spuriously upgraded.
		session.lastCheckpointedManifest = PQEpochManifest(
			sendPQEpoch: body.sendPQEpoch, recvPQEpoch: body.recvPQEpoch,
			sendPQKeys: leafKeys.sendPQ.fingerprint,
			recvPQKeys: leafKeys.recvPQ.fingerprint)
		return session
	}

	/// Archive key 44: decode + validate the deployed carry against
	/// the rebuilt groups. Every failure is `.archiveInvalid`. `noCustody`'s
	/// own set-equality against the rebuilt groups' `current` state is
	/// `validateLeafKeys`'s check 3, not duplicated here — this only
	/// decodes the raw archive shape (a valid `MigratedPQWedge`/
	/// `MigratedGroupRole` tag, a non-empty sorted-unique `noCustody`
	/// array) and the window record's own shape against the rebuilt
	/// recv-classical group.
	private static func decodeDeployedCarry(
		_ carry: DeployedCarryArchive?, recvGroup: APQGroup?
	) throws -> (
		pqWedge: MigratedPQWedge?, noCustody: Set<MigratedGroupRole>,
		ownOfferWindow: OwnOfferWindowRecord?
	) {
		guard let carry else { return (nil, [], nil) }
		guard !carry.isEmpty else { throw TwoMLSError.archiveInvalid }

		let pqWedge = try carry.pqWedged.map { raw -> MigratedPQWedge in
			guard let wedge = MigratedPQWedge(rawValue: raw) else {
				throw TwoMLSError.archiveInvalid
			}
			return wedge
		}

		var noCustody: Set<MigratedGroupRole> = []
		if let raw = carry.noCustody {
			guard !raw.isEmpty, raw == raw.sorted(), Set(raw).count == raw.count else {
				throw TwoMLSError.archiveInvalid
			}
			for value in raw {
				guard let role = MigratedGroupRole(rawValue: value) else {
					throw TwoMLSError.archiveInvalid
				}
				noCustody.insert(role)
			}
		}

		var ownOfferWindow: OwnOfferWindowRecord?
		if let record = carry.ownOfferWindow {
			guard record.id.count == 32, record.count >= 1,
				record.count <= UInt32(MigratedOwnOfferWindow.maximumOfferCount)
			else { throw TwoMLSError.archiveInvalid }
			guard let recv = recvGroup else { throw TwoMLSError.archiveInvalid }
			guard record.epoch == recv.classical.context.epoch,
				record.groupID == recv.classical.context.groupID,
				record.senderLeafIndex == recv.classical.myLeafIndex.value
			else { throw TwoMLSError.archiveInvalid }
			ownOfferWindow = record
		}

		return (pqWedge, noCustody, ownOfferWindow)
	}

	/// Rule 9, re-checked at restore: non-empty, only for a pre-join
	/// initiator, and only while a seal target (`initialTheirKP`) remains to
	/// carry it. Reads the archive's OWN `initialTheirKP` field (not the
	/// restored, decoded value) — this runs before that field's own
	/// `.restore()` call, further down.
	private static func validateInitialAppPayload(
		_ payload: Data?, initiated: Bool, recvGroup: APQGroup?, hasInitialTheirKP: Bool
	) throws {
		guard let payload else { return }
		guard !payload.isEmpty, initiated, recvGroup == nil, hasInitialTheirKP else {
			throw TwoMLSError.archiveInvalid
		}
	}

	/// The winning body's self-reported PQ-epoch manifest is what step 5
	/// fail-closes reconcile on — this cross-checks it against the epoch the
	/// REBUILT groups actually landed at, so a manifest that lied (whether
	/// through a bug upstream of `restore` or a tampered-but-otherwise-valid
	/// archive) can't silently steer the reconcile decision without ever
	/// being caught. `Optional<UInt64>` equality covers "claims a half that
	/// isn't there" and "omits a half that is" alike. The classical group
	/// ids step 3 compares get the same cross-check.
	private static func verifyManifestMatchesRebuiltGroups(
		_ body: SessionArchive, sendGroup: APQGroup?, recvGroup: APQGroup?
	) throws {
		guard body.sendPQEpoch == sendGroup?.pq?.context.epoch,
			body.recvPQEpoch == recvGroup?.pq?.context.epoch,
			body.sendClassicalGroupID == sendGroup?.classical.context.groupID,
			body.recvClassicalGroupID == recvGroup?.classical.context.groupID
		else {
			throw TwoMLSError.archiveInvalid
		}
	}

	/// The epoch check above proves the winning body's manifest didn't lie
	/// about the PQ TREE state; this is its fingerprint-side companion —
	/// proving it didn't lie about the PQ KEY-SET state either, by
	/// cross-checking `sendPQKeysFingerprint`/`recvPQKeysFingerprint`
	/// against the fingerprint the just-restored `leafKeys` PQ sets
	/// actually carry. `validateManifestAgreement` (splice path only)
	/// merely proves a Core and Checkpoint AGREE with EACH OTHER's claimed
	/// fingerprint, and a Checkpoint-alone restore never runs it at all —
	/// neither path proves a claimed fingerprint is truthful against the PQ
	/// key material the body itself carries. `leafKeys.sendPQ`/`recvPQ` are
	/// always the winning body's own restored PQ sets by this point
	/// (`winner` is either the Checkpoint outright, or a Core spliced with
	/// the Checkpoint's PQ halves — `splicingPQ` carries `leafKeys.sendPQ`/
	/// `recvPQ` across but leaves the fingerprint fields as the Core's own
	/// claim, already proven to agree with the Checkpoint's by
	/// `validateManifestAgreement`), so this one check closes the gap
	/// uniformly for both paths.
	private static func verifyManifestFingerprintsMatchRestoredLeafKeys(
		_ body: SessionArchive, leafKeys: LeafKeys
	) throws {
		guard body.sendPQKeysFingerprint == leafKeys.sendPQ.fingerprint,
			body.recvPQKeysFingerprint == leafKeys.recvPQ.fingerprint
		else {
			throw TwoMLSError.archiveInvalid
		}
	}

	/// Group_A's shape: a `CombinerGroup`-established full pair, present on
	/// both sides from construction. A Core-kind entry (or a pre-splice Core
	/// half) never carries `pq` — by the time this runs, reconcile has
	/// already spliced it in from the Checkpoint, so its absence here is a
	/// genuine corruption, not a normal Core omission.
	private static func restoreStandardPair(
		_ entry: GroupEntry?, classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> APQGroup {
		guard let entry, let pqSnapshot = entry.pq else {
			throw TwoMLSError.archiveInvalid
		}
		let classical = try MLS.RFC9420.Group.restore(
			from: entry.classical, classicalProvider)
		let pq = try MLS.RFC9420.Group.restore(from: pqSnapshot, pqProvider)
		try verifyRestoredPairIdentity(classical: classical, pq: pq)
		return APQGroup(
			classical: classical, pq: pq, pskStore: MLS.Combiner.PSKStore(),
			codepoints: .deployed)
	}

	/// Group_B's shape: classical-only until the §A.3 bootstrap founds its
	/// PQ half out of band (never via `CombinerGroup`). `nil` only for a
	/// pre-join initiator's recv group (`validateGroupPresence`).
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
	/// exact join moment they run at, never again: `APQInfo` is written once
	/// at creation and never rewritten (book `group-rules.md` rule 7), so
	/// that attestation is stale the moment any further commit lands
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
