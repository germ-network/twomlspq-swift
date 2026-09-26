import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing

@testable import TwoMLSPQSession

/// `GroupKeySet`'s own stage/promote/retention contract in isolation, plus
/// two session-level regression tests: a replacement keeping recv-
/// classical's dead entry around, and an idempotent re-stage refreshing the
/// epoch so a second rotation attempt within the same epoch keeps wedging.
@Suite struct LeafKeysTests {
	@available(iOS 26, macOS 26, *)
	private func freshKey() throws -> LeafKey {
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		return LeafKey(signingKey: signingKey, signatureKey: signatureKey)
	}

	// MARK: - GroupKeySet.stage

	@available(iOS 26, macOS 26, *)
	@Test func stageIsIdempotentForTheSameKey() throws {
		var set = GroupKeySet()
		let key = try freshKey()
		let target = Data("target".utf8)
		try set.stage(key, for: target)
		#expect(throws: Never.self) { try set.stage(key, for: target) }
		#expect(set.pending[target]?.signatureKey == key.signatureKey)
	}

	@available(iOS 26, macOS 26, *)
	@Test func stageThrowsOnAConflictingKeyForTheSameTarget() throws {
		var set = GroupKeySet()
		let target = Data("target".utf8)
		try set.stage(try freshKey(), for: target)
		#expect(throws: TwoMLSError.rotationInFlight) {
			try set.stage(try freshKey(), for: target)
		}
	}

	// MARK: - GroupKeySet.promoted

	@available(iOS 26, macOS 26, *)
	@Test func promotedIsANoOpWhenTheLeafAlreadyPresentsCurrent() throws {
		let current = try freshKey()
		var set = GroupKeySet(current: current)
		#expect(throws: Never.self) {
			try set.promoted(presenting: current.signatureKey, id: Data("id".utf8))
		}
		#expect(set.current?.signatureKey == current.signatureKey)
	}

	@available(iOS 26, macOS 26, *)
	@Test func promotedMovesAPendingEntryToCurrentAndRemovesIt() throws {
		let original = try freshKey()
		let staged = try freshKey()
		let target = Data("target".utf8)
		var set = GroupKeySet(current: original)
		try set.stage(staged, for: target)
		try set.promoted(presenting: staged.signatureKey, id: target)
		#expect(set.current?.signatureKey == staged.signatureKey)
		#expect(set.pending[target] == nil)
	}

	@available(iOS 26, macOS 26, *)
	@Test func promotedThrowsCredentialUnknownForAnUnheldKey() throws {
		var set = GroupKeySet(current: try freshKey())
		#expect(throws: TwoMLSError.credentialUnknown) {
			try set.promoted(
				presenting: try freshKey().signatureKey, id: Data("id".utf8))
		}
	}

	// MARK: - retainRecvClassical

	@available(iOS 26, macOS 26, *)
	@Test func retentionKeepsTheOutstandingCandidateAndDropsAnUnrelatedEntry() throws {
		let candidateID = Data("candidate".utf8)
		let staleID = Data("stale".utf8)
		var set = GroupKeySet()
		try set.stage(try freshKey(), for: candidateID)
		try set.stage(try freshKey(), for: staleID)
		set.retainRecvClassical(
			candidateID: candidateID, candidateCanonicalized: false, ruleFourTarget: nil
		)
		#expect(set.pending[candidateID] != nil)
		#expect(set.pending[staleID] == nil)
	}

	@available(iOS 26, macOS 26, *)
	@Test func retentionDropsTheCandidateOnceItHasCanonicalized() throws {
		let candidateID = Data("candidate".utf8)
		var set = GroupKeySet()
		try set.stage(try freshKey(), for: candidateID)
		set.retainRecvClassical(
			candidateID: candidateID, candidateCanonicalized: true, ruleFourTarget: nil)
		#expect(
			set.pending[candidateID] == nil,
			"a canonicalized candidate is no longer live")
	}

	@available(iOS 26, macOS 26, *)
	@Test func retentionKeepsTheRuleFourTarget() throws {
		let ruleFourTarget = Data("dedicated".utf8)
		var set = GroupKeySet()
		try set.stage(try freshKey(), for: ruleFourTarget)
		set.retainRecvClassical(
			candidateID: nil, candidateCanonicalized: true,
			ruleFourTarget: ruleFourTarget)
		#expect(set.pending[ruleFourTarget] != nil)
	}

	// MARK: - Session-level: a replacement keeps recv-classical's dead entry

	/// A replacement keeps recv-classical's outgoing entry around. The wedge
	/// relaxation replaces an uncanonicalized, epoch-stale candidate (c1)
	/// with a fresh one (c2) — `prepareToEncrypt(rotating:)` never prunes
	/// c1's own `pending` entry when it does; only the NEXT epoch advance's
	/// retention rule (which no longer treats c1 as live) eventually does.
	/// Mutation-tested: a version of `prepareToEncrypt` that explicitly
	/// pruned `pending[c1]` at the replacement moment passed every other
	/// test in the suite — this is the one that catches it.
	@available(iOS 26, macOS 26, *)
	@Test func replacementKeepsRecvClassicalsDeadEntry() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let c1 = Data("alice-c1".utf8)
		let c2 = Data("alice-c2".utf8)

		// Stage c1 (epoch E0), leave it unapproved.
		_ = try alice.prepareToEncrypt(rotating: c1)
		let c1Frame = try alice.encrypt(Data("c1-offer".utf8)).frame
		_ = try bob.processIncomingDecrypted(c1Frame)

		// Advance Group_B's epoch via an UNRELATED routine (non-rotating)
		// offer/fold — never touches alice's credential, so c1 stays
		// uncanonicalized while the epoch moves past its stage point.
		_ = try alice.prepareToEncrypt()
		let refreshFrame = try alice.encrypt(Data("refresh-offer".utf8)).frame
		let refreshDecrypted = try bob.processIncomingDecrypted(refreshFrame)
		_ = try bob.queueProposal(digest: refreshDecrypted.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold-refresh".utf8)).frame
		let foldDecrypted = try alice.processIncomingDecrypted(foldFrame)
		#expect(foldDecrypted.didApplyRemoteCommit)
		#expect(!foldDecrypted.ownCredentialCanonicalized)

		// c1 survived the advance (still the live candidate).
		#expect(alice.leafKeys.recvClassical.pending[c1] != nil)

		// The wedge relaxation now lets c2 replace c1 (epoch moved past
		// c1's stage point, and c1 never canonicalized).
		_ = try alice.prepareToEncrypt(rotating: c2)

		// c1's own pending entry is a dead leftover — still present right
		// after the replacement (the accepted parity gap), pruned only at
		// the NEXT epoch advance.
		#expect(
			alice.leafKeys.recvClassical.pending[c1] != nil,
			"a replacement must not itself prune the outgoing candidate's entry")
		#expect(alice.leafKeys.recvClassical.pending[c2] != nil)
	}

	// MARK: - An idempotent re-stage refreshes the wedge epoch

	/// Rotate to c1, let the epoch move past c1's stage
	/// point via an unrelated fold, THEN re-stage c1 (idempotent, same id)
	/// — the re-stage must refresh `proposedAtRecvEpoch` to the CURRENT
	/// epoch, so an immediately-following rotation to a DIFFERENT id (c2)
	/// still throws `.rotationInFlight` (c1's freshly re-staged offer is
	/// still live) rather than wrongly passing the wedge relaxation and
	/// bricking c1. Finally, the peer folds the re-staged Upd(c1) and the
	/// rotation converges normally.
	@available(iOS 26, macOS 26, *)
	@Test func restagingTheSameCandidateRefreshesItsEpochThenConverges() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let c1 = Data("alice-c1".utf8)
		let c2 = Data("alice-c2".utf8)

		// 1: stage c1 at epoch E0, leave it unapproved.
		_ = try alice.prepareToEncrypt(rotating: c1)
		let c1OfferE0 = try alice.encrypt(Data("c1-offer-e0".utf8)).frame
		_ = try bob.processIncomingDecrypted(c1OfferE0)

		// 2: advance Group_B's epoch (E0 -> E1) via an unrelated routine
		// fold, exactly like the replacement test above — c1 stays the
		// live (uncanonicalized) candidate across it.
		_ = try alice.prepareToEncrypt()
		let refreshFrame = try alice.encrypt(Data("refresh-offer".utf8)).frame
		let refreshDecrypted = try bob.processIncomingDecrypted(refreshFrame)
		_ = try bob.queueProposal(digest: refreshDecrypted.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold-refresh".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)

		// 3: idempotent re-stage — SAME id c1, now at the NEW epoch E1.
		// This must rebuild the candidate record with E1, not leave it
		// stuck at E0.
		_ = try alice.prepareToEncrypt(rotating: c1)

		// 4: a rotation to a DIFFERENT id must still wedge — c1's
		// freshly-restaged offer is live at the CURRENT epoch (E1), so
		// `recv.classical.context.epoch > existing.proposedAtRecvEpoch`
		// must be false. If the re-stage above had left `proposedAtRecvEpoch`
		// stuck at E0, this would wrongly succeed, dropping c1's key out
		// from under its still-live offer.
		#expect(throws: TwoMLSError.rotationInFlight) {
			try alice.prepareToEncrypt(rotating: c2)
		}

		// 5: send the re-staged c1 offer and let it converge normally.
		let c1OfferE1 = try alice.encrypt(Data("c1-offer-e1".utf8)).frame
		let c1Decrypted = try bob.processIncomingDecrypted(c1OfferE1)
		#expect(c1Decrypted.queuedProposal.proposing == c1)
		_ = try bob.queueProposal(digest: c1Decrypted.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let c1FoldFrame = try bob.encrypt(Data("fold-c1".utf8)).frame
		let c1FoldDecrypted = try alice.processIncomingDecrypted(c1FoldFrame)
		#expect(c1FoldDecrypted.ownCredentialCanonicalized)
		#expect(alice.myPrincipalState == .sync(c1))

		// Signing keeps working, now under c1, end to end.
		_ = try alice.prepareToEncrypt()
		let aliceMsg = try alice.encrypt(Data("post-restage".utf8)).frame
		let fromAlice = try bob.processIncomingDecrypted(aliceMsg)
		#expect(fromAlice.applicationMessage == Data("post-restage".utf8))
	}

	// MARK: - Choke point: a corrupted set fails closed

	/// Corrupts each of the four sets in turn: the call throws
	/// `.credentialUnknown` and `lastCheckpointedManifest` is unchanged.
	/// Runs after the §A.3 bootstrap so all four groups exist on both
	/// sides — a corrupted PQ set is caught ONLY by the choke point itself
	/// (a routine `prepareToEncrypt`/`encrypt` round never touches PQ
	/// signing), while a corrupted classical set may be caught earlier by
	/// its own accessor — either way the call must fail closed and mint
	/// nothing.
	@available(iOS 26, macOS 26, *)
	@Test func chokePointCorruptionOfEachSetFailsClosed() throws {
		func corrupted(
			_ label: String, _ session: TwoMLSSession,
			_ corrupt: (inout TwoMLSSession) throws -> Void,
			_ call: (inout TwoMLSSession) throws -> Void = {
				_ = try $0.prepareToEncrypt()
			}
		) throws {
			var copy = session
			try corrupt(&copy)
			let before = copy.lastCheckpointedManifest
			var thrown: Error?
			do { try call(&copy) } catch { thrown = error }
			#expect(thrown as? TwoMLSError == .credentialUnknown, "\(label)")
			#expect(copy.lastCheckpointedManifest == before, "\(label)")
		}

		// sendClassical: a session that has exchanged (so `recvGroup`
		// exists) but never bootstrapped §A.3 — nothing is licensed to
		// discharge, so a plain `prepareToEncrypt()` commits NOTHING and
		// the choke point is the ONLY thing standing between the
		// corrupted slot and a signed message.
		let (classicalOnlyAlice, _) = try SessionTestSupport.establishedAndExchanged()
		try corrupted("sendClassical", classicalOnlyAlice) {
			$0.leafKeys.sendClassical.current = try self.freshKey()
		}

		// recvClassical: `prepareToEncrypt()`'s routine branch always signs
		// with it directly, so swift-mls's own framing-signature check
		// catches a corruption there first, with its own (non-TwoMLSError)
		// error — not what this test is after. `pqBootstrapBegin()`'s
		// first-call path reaches `stateUpdate` without ever touching
		// classical signing at all (it only header-seals KP′), isolating
		// the choke point for this slot instead.
		let (recvClassicalOnlyAlice, _) = try SessionTestSupport.establishedAndExchanged()
		try corrupted(
			"recvClassical", recvClassicalOnlyAlice,
			{ $0.leafKeys.recvClassical.current = try self.freshKey() },
			{ _ = try $0.pqBootstrapBegin() })

		// PQ: needs the §A.3 bootstrap for both PQ groups to exist. A
		// routine `prepareToEncrypt()` never signs with either (even when
		// it also discharges the owed bind, which only touches the
		// classical and PQ EXPORT state, never a PQ leaf's identity), so
		// the choke point is what catches these too.
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let begin = try alice.pqBootstrapBegin()
		let respond = try bob.pqBootstrapRespond(begin.frame)
		_ = try alice.pqBootstrapJoin(respond.frame)
		#expect(alice.isFullyEstablished)
		#expect(bob.isFullyEstablished)
		try corrupted("sendPQ", alice) { $0.leafKeys.sendPQ.current = try self.freshKey() }
		try corrupted("recvPQ", alice) { $0.leafKeys.recvPQ.current = try self.freshKey() }
	}

	// MARK: - A fault injected before encode leaves the stamp unset

	/// Arms the `stateUpdate.beforeEncode` DEBUG fault point (after the kind-upgrade
	/// decision, before `makeSessionArchive`/the checkpoint stamp) and
	/// confirms `lastCheckpointedManifest` is untouched by the failed call.
	#if DEBUG
		@available(iOS 26, macOS 26, *)
		@Test func faultBeforeEncodeLeavesTheCheckpointStampUnset() throws {
			var (alice, _) = try SessionTestSupport.establishedAndExchanged()
			// Deliberately stale: the LIVE `pqEpochManifest` (computed from
			// `sendGroup`/`recvGroup`/`leafKeys`) does NOT match this — every
			// `established` session's manifest is non-empty (Group_A's send-PQ
			// half exists from birth), so this is guaranteed to differ, unlike
			// comparing against the session's OWN (already-matching) stamp,
			// which a stamp-before-encode bug would trivially re-write to the
			// SAME value and so never be caught.
			let stale = PQEpochManifest(
				sendPQEpoch: nil, recvPQEpoch: nil,
				sendPQKeys: GroupKeySetFingerprint(current: nil, pending: []),
				recvPQKeys: GroupKeySetFingerprint(current: nil, pending: []))
			#expect(stale != alice.pqEpochManifest)
			alice.lastCheckpointedManifest = stale
			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault("stateUpdate.beforeEncode")
				// Calls `stateUpdate` directly at `.checkpoint` (`@testable`) — a
				// plain `prepareToEncrypt()` here would request `.core` and never
				// even reach the conditional stamp (nothing PQ changed), which
				// would let a "stamp before encode" mutation hide behind an
				// untaken branch.
				#expect(throws: (any Error).self) {
					try alice.stateUpdate(kind: .checkpoint)
				}
			}
			#expect(
				alice.lastCheckpointedManifest == stale,
				"a fault before encode must leave the checkpoint stamp untouched")
		}
	#endif

	// MARK: - Archive round-trip with pending entries

	/// Stages a live rotation (so `leafKeys.recvClassical` carries a
	/// `pending` entry, not just `current` — send-classical never does),
	/// round-trips through `makeSessionArchive`/`restore`, and checks the
	/// restored `leafKeys` matches the live one field for field.
	@available(iOS 26, macOS 26, *)
	@Test func archiveRoundTripPreservesPendingEntries() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try alice.prepareToEncrypt(rotating: Data("alice-v2".utf8))
		#expect(!alice.leafKeys.recvClassical.pending.isEmpty)
		#expect(alice.leafKeys.sendClassical.pending.isEmpty)

		let checkpoint = try alice.stateUpdate(kind: .checkpoint).archive
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		#expect(
			Set(restored.leafKeys.sendClassical.pending.keys)
				== Set(alice.leafKeys.sendClassical.pending.keys))
		#expect(
			Set(restored.leafKeys.recvClassical.pending.keys)
				== Set(alice.leafKeys.recvClassical.pending.keys))
		for (target, key) in alice.leafKeys.recvClassical.pending {
			#expect(
				restored.leafKeys.recvClassical.pending[target]?.signatureKey
					== key.signatureKey)
		}
		_ = bob
	}

	/// A duplicate `pending` target in the raw archive shape is rejected —
	/// `GroupKeySetArchive.restore()`'s own check, exercised
	/// directly since the native `LeafKeys` type can never construct one
	/// itself (a `Dictionary` structurally can't hold a duplicate key).
	@available(iOS 26, macOS 26, *)
	@Test func groupKeySetArchiveRestoreRejectsADuplicateTarget() throws {
		let key = LeafKeyArchive(try freshKey())
		let target = Data("dup".utf8)
		let archive = GroupKeySetArchive(
			current: nil,
			pending: [
				PendingLeafKeyArchive(target: target, key: key),
				PendingLeafKeyArchive(target: target, key: key),
			])
		#expect(throws: TwoMLSError.archiveInvalid) {
			try archive.restore()
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func groupKeySetArchiveRestoreRejectsAnEmptyTarget() throws {
		let archive = GroupKeySetArchive(
			current: nil,
			pending: [
				PendingLeafKeyArchive(
					target: Data(), key: LeafKeyArchive(try freshKey()))
			]
		)
		#expect(throws: TwoMLSError.archiveInvalid) {
			try archive.restore()
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func leafKeyArchiveRestoreRejectsASigningKeyThatDoesNotDeriveToItsSignatureKey()
		throws
	{
		let real = LeafKeyArchive(try freshKey())
		let mismatched = LeafKeyArchive(
			signingKey: real.signingKey, signatureKey: try freshKey().signatureKey.data)
		#expect(throws: TwoMLSError.archiveInvalid) {
			try mismatched.restore()
		}
	}

	// MARK: - Restore negatives: key 41, and checks 2/3/7 through the full path

	/// `leafKeys` (archive key 41) is REQUIRED, unlike every other field
	/// added since v1 — a body encoded without it is a `DecodingError`,
	/// which `restore` folds to `.archiveInvalid` like any other malformed
	/// archive. `PartialSessionArchive` mirrors every OTHER required field
	/// of `SessionArchive` at the SAME coding keys (the optional ones need
	/// no stand-in — a missing optional key decodes to `nil` either way),
	/// so the only actual difference from a genuine archive is key 41's
	/// absence.
	@available(iOS 26, macOS 26, *)
	@Test func restoreRejectsAnArchiveMissingLeafKeys() throws {
		let alice = try SessionTestSupport.establishedAndExchanged().alice
		let real = try alice.makeSessionArchive(kind: .checkpoint).decode(
			SessionArchive.self)
		let truncated = PartialSessionArchive(
			version: real.version, classicalSuite: real.classicalSuite,
			pqSuite: real.pqSuite, kind: real.kind, stateSeq: real.stateSeq,
			identity: real.identity, auth: real.auth, currentStaple: real.currentStaple,
			initiated: real.initiated, pqTurnMine: real.pqTurnMine,
			stagedUpdates: real.stagedUpdates,
			sendCrossPSKLedger: real.sendCrossPSKLedger,
			sendPQKeysFingerprint: real.sendPQKeysFingerprint,
			recvPQKeysFingerprint: real.recvPQKeysFingerprint)

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: truncated),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	/// Check 2 through the FULL restore path (not just the live choke
	/// point): a decoded archive whose `sendClassical.current` no longer
	/// matches what the restored tree actually presents is rejected.
	@available(iOS 26, macOS 26, *)
	@Test func restoreRejectsCheck2ThroughTheFullPath() throws {
		let alice = try SessionTestSupport.establishedAndExchanged().alice
		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		body.leafKeys.sendClassical.current = LeafKeyArchive(try freshKey())

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	/// Check 3 through the full restore path: a pre-A.3 initiator's `recvPQ`
	/// reservation (no `recvGroup.pq` exists yet) must equal `identity`'s
	/// own PQ key — corrupting it is rejected.
	@available(iOS 26, macOS 26, *)
	@Test func restoreRejectsCheck3ThroughTheFullPath() throws {
		let alice = try SessionTestSupport.establishedAndExchanged().alice
		#expect(alice.recvGroup?.pq == nil)
		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		body.leafKeys.recvPQ = GroupKeySetArchive(
			current: LeafKeyArchive(try freshKey()), pending: [])

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	/// A pre-A.3 acceptor's send-PQ holds no reservation: a smuggled
	/// `current` is rejected, matching check 4's send-PQ arm.
	@available(iOS 26, macOS 26, *)
	@Test func restoreRejectsAPreA3SendPQReservation() throws {
		let bob = try SessionTestSupport.establishedAndExchanged().bob
		#expect(bob.sendGroup?.pq == nil)
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		let smuggled = GroupKeySet(current: try freshKey())
		body.leafKeys.sendPQ = GroupKeySetArchive(smuggled)
		// Keep the manifest fingerprint honest about the smuggled value —
		// otherwise `verifyManifestFingerprintsMatchRestoredLeafKeys` would
		// catch this first, leaving check 4 itself unpinned.
		body.sendPQKeysFingerprint = smuggled.fingerprint

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	/// Twin of the above: the canonical present-but-empty shape restores
	/// cleanly.
	@available(iOS 26, macOS 26, *)
	@Test func restoreAcceptsAPreA3SendPQPresentButEmpty() throws {
		let bob = try SessionTestSupport.establishedAndExchanged().bob
		#expect(bob.sendGroup?.pq == nil)
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		let body = try archive.decode(SessionArchive.self)
		let sendPQ = try #require(
			body.leafKeys.sendPQ, "a Checkpoint always carries a present-but-empty set")
		#expect(sendPQ.current == nil)
		#expect(sendPQ.pending.isEmpty)

		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: try SecretArchive(encoding: body),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.leafKeys.sendPQ.current == nil)
	}

	/// Check 7 through the full restore path: a born-dedicated Bob still
	/// lagging (his recv-classical leaf still presents the invitation's
	/// id, not yet caught up to his own identity) must carry
	/// `recvClassical.pending[identity.clientID]` — stripping it is
	/// rejected.
	@available(iOS 26, macOS 26, *)
	@Test func restoreRejectsCheck7ThroughTheFullPath() throws {
		let established = try SessionTestSupport.establishedDedicated(bob: "bob-d")
		let bob = established.bob
		#expect(bob.leafKeys.recvClassical.pending[established.dedicatedClientID] != nil)
		let target = established.dedicatedClientID
		let archive = try bob.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)
		#expect(
			body.leafKeys.recvClassical.pending.contains { $0.target == target })
		body.leafKeys.recvClassical.pending.removeAll { $0.target == target }

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	// MARK: - Rule-4 retention survives an unrelated recv advance

	/// A born-dedicated Bob's rule-4 catch-up target
	/// (`recvClassical.pending[identity.clientID]`) must survive a recv-
	/// classical epoch advance that does NOT fold it — here, alice's owed
	/// §A.3 PQ bind discharges on Group_A, advancing bob's recv-classical
	/// epoch without ever touching his still-lagging leaf. Round-trips
	/// through a real restore too, then drives the rule-4 offer to a real
	/// fold, confirming the retained entry was the genuine article, not a
	/// stale leftover the fold coincidentally still accepted.
	@available(iOS 26, macOS 26, *)
	@Test func ruleFourTargetSurvivesAnUnrelatedRecvAdvance() throws {
		let established = try SessionTestSupport.establishedDedicatedAndApproved(
			dedicatedClientID: Data("bob-d9".utf8))
		var alice = established.alice
		var bob = established.bob
		_ = try bob.prepareToEncrypt()
		let hello = try bob.encrypt(Data("hi".utf8)).frame
		_ = try alice.processIncomingDecrypted(hello)

		let begin = try alice.pqBootstrapBegin()
		let respond = try bob.pqBootstrapRespond(begin.frame)
		_ = try alice.pqBootstrapJoin(respond.frame)
		let prepared = try alice.prepareToEncrypt()
		#expect(prepared.didCommit, "alice's owed bind discharges on Group_A")
		let discharge = try alice.encrypt(Data("d".utf8)).frame
		let dischargeDecrypted = try bob.processIncomingDecrypted(discharge)
		#expect(dischargeDecrypted.didApplyRemoteCommit)
		#expect(!dischargeDecrypted.ownCredentialCanonicalized)
		#expect(
			bob.leafKeys.recvClassical.pending[established.dedicatedClientID] != nil,
			"rule-4 target must survive an advance that did not fold it")

		let checkpoint = try bob.makeSessionArchive(kind: .checkpoint)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(
			restored.leafKeys.recvClassical.pending[established.dedicatedClientID]
				!= nil)

		_ = try bob.prepareToEncrypt()
		let offer = try bob.encrypt(Data("o".utf8)).frame
		let offerDecrypted = try alice.processIncomingDecrypted(offer)
		_ = try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let fold = try alice.encrypt(Data("f".utf8)).frame
		let foldDecrypted = try bob.processIncomingDecrypted(fold)
		#expect(foldDecrypted.ownCredentialCanonicalized)
	}

	// MARK: - Seeding tables: initiate / receive / born-dedicated receive

	/// `initiate`'s seeding table: send-classical/send-PQ each present a
	/// freshly minted founding leaf — never `identity`'s own KP halves,
	/// which stay reserved for recv-classical (the return KP) and recv-PQ
	/// (KP′). Every `pending` is empty pre-join.
	@available(iOS 26, macOS 26, *)
	@Test func initiateSeedsAllFourSetsToIdentitysOwnKeys() throws {
		let alice = try SessionTestSupport.established().alice
		#expect(alice.recvGroup == nil)

		#expect(
			try TwoMLSSession.ownLeaf(of: try #require(alice.sendGroup?.classical))
				.signatureKey
				== alice.leafKeys.sendClassical.current?.signatureKey)
		#expect(
			alice.leafKeys.sendClassical.current?.signatureKey
				!= alice.identity.signatureKey)
		#expect(
			alice.leafKeys.recvClassical.current?.signatureKey
				== alice.identity.signatureKey)
		#expect(
			try TwoMLSSession.ownLeaf(of: try #require(alice.sendGroup?.pq))
				.signatureKey
				== alice.leafKeys.sendPQ.current?.signatureKey)
		#expect(
			alice.leafKeys.sendPQ.current?.signatureKey != alice.identity.pqSignatureKey
		)
		#expect(
			alice.leafKeys.recvPQ.current?.signatureKey == alice.identity.pqSignatureKey
		)
		for set in [
			alice.leafKeys.sendClassical, alice.leafKeys.recvClassical,
			alice.leafKeys.sendPQ, alice.leafKeys.recvPQ,
		] {
			#expect(set.pending.isEmpty)
		}
	}

	/// Plain (non-dedicated) `receive`'s seeding table: send-classical
	/// presents a fresh founding leaf (credential = the invitation id);
	/// recv-classical presents the invitation identity's own key (the
	/// half this session actually joined Group_A with); send-PQ is empty
	/// (not founded until A.3); recv-PQ presents the same invitation
	/// identity's PQ half. No recv-leaf custody, no `pending`.
	@available(iOS 26, macOS 26, *)
	@Test func plainReceiveSeedsSendAndRecvClassicalToTheSameIdentity() throws {
		let bob = try SessionTestSupport.established().bob
		#expect(bob.leafKeys.recvClassical.pending.isEmpty)

		#expect(
			try TwoMLSSession.ownLeaf(of: try #require(bob.sendGroup?.classical))
				.signatureKey
				== bob.leafKeys.sendClassical.current?.signatureKey)
		#expect(
			bob.leafKeys.sendClassical.current?.signatureKey
				!= bob.identity.signatureKey)
		#expect(
			bob.leafKeys.recvClassical.current?.signatureKey
				== bob.identity.signatureKey)
		#expect(bob.leafKeys.sendPQ.current == nil)
		#expect(
			bob.leafKeys.recvPQ.current?.signatureKey == bob.identity.pqSignatureKey)
		for set in [
			bob.leafKeys.sendClassical, bob.leafKeys.recvClassical, bob.leafKeys.sendPQ,
			bob.leafKeys.recvPQ,
		] {
			#expect(set.pending.isEmpty)
		}
	}

	/// Born-dedicated `receive`'s seeding table: `session.identity` stays
	/// the INVITATION bundle throughout — D is a credential
	/// id plus its own fresh founding leaf and catch-up key, never a
	/// separate identity bundle. send-classical presents D's fresh
	/// founding leaf from the moment Group_B is founded; recv-classical
	/// still presents the invitation identity (D has not caught up
	/// there yet), with D's fresh catch-up key staged at
	/// `pending[D.clientID]` (rule 4's target); send-PQ is empty (not
	/// founded until A.3); recv-PQ joins under the invitation identity's
	/// already-signed PQ leaf (also not yet D's).
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedReceiveSeedsSendToDAndRecvClassicalToTheInvitationWithDPending()
		throws
	{
		let established = try SessionTestSupport.establishedDedicated(bob: "bob-d")
		let bob = established.bob
		#expect(bob.identity.clientID == established.invitationClientID)
		#expect(bob.myPrincipalState == .sync(established.dedicatedClientID))

		let sendClassicalKey = try #require(bob.leafKeys.sendClassical.current)
		#expect(
			try TwoMLSSession.ownLeaf(of: try #require(bob.sendGroup?.classical))
				.signatureKey == sendClassicalKey.signatureKey,
			"send-classical presents D's fresh founding leaf from the moment Group_B is founded"
		)
		#expect(sendClassicalKey.signatureKey != bob.identity.signatureKey)
		#expect(
			bob.leafKeys.recvClassical.current?.signatureKey
				== bob.identity.signatureKey,
			"recv-classical still presents the invitation identity, not yet D")
		// The rule-4 catch-up key (book group-rules.md:143-158 rule 4) is
		// minted separately from the founding leaf's key — never the same
		// pair.
		let recvPending = try #require(
			bob.leafKeys.recvClassical.pending[established.dedicatedClientID])
		#expect(recvPending.signatureKey != sendClassicalKey.signatureKey)

		#expect(bob.leafKeys.sendPQ.current == nil)
		#expect(
			bob.leafKeys.recvPQ.current?.signatureKey == bob.identity.pqSignatureKey,
			"recv-PQ joins Group_A under the invitation identity's PQ leaf")
		#expect(bob.leafKeys.sendClassical.pending.isEmpty)
		#expect(bob.leafKeys.sendPQ.pending.isEmpty)
		#expect(bob.leafKeys.recvPQ.pending.isEmpty)
	}

	// MARK: - Identity not consulted once every step is behind us

	/// The stored-key design's central claim: once every KeyPackage-
	/// consuming step is behind a session (the §A.3 join, KP′'s founding —
	/// `prepareToEncrypt(rotating:)`'s own mint, `Bootstrap.swift`'s
	/// PQ-half founding), signing never reads `identity` again. Replaces `alice.identity` with an unrelated bogus
	/// identity, keeping only `clientID` (rule 4 reads
	/// `pending[identity.clientID]`), clears `rotationCandidate` too (this
	/// session is already converged, so it is already unused — clearing it
	/// removes any doubt), then drives: a routine send (which also
	/// discharges the owed PQ bind —
	/// `sendClassicalSigningKey`); two mechanical §A.5 rounds, one each
	/// direction (`recvPQSigningKey` via alice's own `pqRekeyBegin`,
	/// `sendPQSigningKey` via her `pqRekeyRespond`/discharge as the other
	/// round's committer); and a full classical rotation round (author/
	/// approve/fold/catch-up, exercising both classical accessors) — all
	/// while `bob`, who never sees `identity` at all, keeps verifying every
	/// frame.
	@available(iOS 26, macOS 26, *)
	@Test func identityNotConsultedOnceEveryKeyPackageStepIsBehindUs() throws {
		// Every group's `current` still traces back to the ORIGINAL identity
		// until each group's own next mechanism replaces it.
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let begin = try alice.pqBootstrapBegin()
		let respond = try bob.pqBootstrapRespond(begin.frame)
		_ = try alice.pqBootstrapJoin(respond.frame)
		#expect(alice.isFullyEstablished)
		#expect(bob.isFullyEstablished)

		let bogus = try TwoMLSIdentity.generate(
			clientID: alice.identity.clientID,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		alice.identity = bogus
		alice.rotationCandidate = nil

		// Routine send + the owed PQ bind's classical discharge commit
		// (`sendClassicalSigningKey`).
		_ = try alice.prepareToEncrypt()
		let firstFrame = try alice.encrypt(Data("post-swap".utf8)).frame
		let firstDecrypted = try bob.processIncomingDecrypted(firstFrame)
		#expect(firstDecrypted.applicationMessage == Data("post-swap".utf8))

		// Two mechanical §A.5 rounds, one each direction, so BOTH of
		// alice's PQ accessors get exercised under the bogus identity —
		// not just `sendClassicalSigningKey`/`recvClassicalSigningKey`
		// above. `pqRekeyBegin` reads the initiator's own recv-PQ slot;
		// `pqRekeyRespond` and the owed bind's discharge read the
		// committer's/initiator's own send-PQ slot. The discharge above
		// already passed the PQ turn to bob, so bob opens round 1 (alice
		// answers as committer, exercising her `sendPQ`); alice opens
		// round 2 with the turn back (exercising her `recvPQ`).
		let bobOpenedUpd = try bob.pqRekeyBegin().frame
		let bobOpenedCommit = try alice.pqRekeyRespond(bobOpenedUpd).frame
		_ = try bob.pqRekeyApply(bobOpenedCommit)
		_ = try bob.prepareToEncrypt()
		let bobOpenedBound = try bob.encrypt(Data("a5-bob-opened".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobOpenedBound)

		let aliceOpenedUpd = try alice.pqRekeyBegin().frame
		let aliceOpenedCommit = try bob.pqRekeyRespond(aliceOpenedUpd).frame
		_ = try alice.pqRekeyApply(aliceOpenedCommit)
		_ = try alice.prepareToEncrypt()
		let aliceOpenedBound = try alice.encrypt(Data("a5-alice-opened".utf8)).frame
		_ = try bob.processIncomingDecrypted(aliceOpenedBound)

		// A classical rotation: author (`recvClassicalSigningKey` for the
		// ring's OLD-key half), approve, fold by bob, then alice's own-leaf
		// catch-up (`sendClassicalSigningKey` again, this time via the
		// ring's `newIdentity`-carrying commit).
		let newID = Data("alice-post-swap-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		let foldDecrypted = try alice.processIncomingDecrypted(foldFrame)
		#expect(foldDecrypted.ownCredentialCanonicalized)
		// The catch-up rides a fold of Bob's routine offer (staged on the same
		// frame above), never a plain `prepareToEncrypt()`.
		_ = try alice.queueProposal(digest: foldDecrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
		let catchUpDecrypted = try bob.processIncomingDecrypted(catchUpFrame)
		#expect(catchUpDecrypted.newSender == newID)
		#expect(alice.myPrincipalState == .sync(newID))

		// Traffic keeps round-tripping end to end, under the new key.
		_ = try alice.prepareToEncrypt()
		let finalFrame = try alice.encrypt(Data("post-rotation".utf8)).frame
		let finalDecrypted = try bob.processIncomingDecrypted(finalFrame)
		#expect(finalDecrypted.applicationMessage == Data("post-rotation".utf8))
	}

	// MARK: - Check 7: send-classical `pending` must be strictly empty

	/// Send-classical never holds a `pending` entry — its own next
	/// committing round mints fresh for whatever id it then presents, so
	/// restore/mint reject any non-empty `pending` outright, even while a
	/// canonical candidate's send leaf still genuinely lags. Reaches the
	/// exact intermediate state (recv-leaf converged, send-leaf still
	/// lagging) `testFullClassicalRotationRoundTripsBothLeavesAndPrincipalStates`
	/// documents between its steps 4 and 5, confirms `leafKeys` is
	/// naturally empty there, then pollutes it with an entry and confirms
	/// `validateLeafKeys` rejects it.
	@available(iOS 26, macOS 26, *)
	@Test func validateLeafKeysRejectsANonEmptySendClassicalPendingEvenWhileACandidateLags()
		throws
	{
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let newID = Data("alice-v2".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		let foldDecrypted = try alice.processIncomingDecrypted(foldFrame)
		#expect(foldDecrypted.ownCredentialCanonicalized)
		#expect(alice.myPrincipalState == .sync(newID))
		let aliceSendClassicalLagging = try #require(alice.sendGroup?.classical)
		#expect(
			try basicIdentifier(
				TwoMLSSession.ownLeaf(of: aliceSendClassicalLagging).credential)
				== alice.identity.clientID,
			"send-classical documentedly still lags here")
		let candidate = try #require(alice.rotationCandidate)
		#expect(alice.leafKeys.sendClassical.pending.isEmpty)

		let (pollutedSigningKey, pollutedSignatureKey) =
			try TwoMLSIdentity.mintSignatureKeypair()
		var polluted = alice.leafKeys
		polluted.sendClassical.pending[candidate.clientID] = LeafKey(
			signingKey: pollutedSigningKey, signatureKey: pollutedSignatureKey)

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.validateLeafKeys(
				polluted, sendGroup: alice.sendGroup,
				recvGroup: alice.recvGroup,
				identity: alice.identity, bootstrapKPSecret: nil,
				stagedUpdates: alice.stagedUpdates,
				pendingProposal: alice.pendingProposal,
				pqInflight: alice.pqInflight,
				rotationCandidate: alice.rotationCandidate,
				auth: alice.auth,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}

		// The unmodified `leafKeys` (strictly empty send-classical `pending`) passes.
		#expect(throws: Never.self) {
			try TwoMLSSession.validateLeafKeys(
				alice.leafKeys, sendGroup: alice.sendGroup,
				recvGroup: alice.recvGroup,
				identity: alice.identity, bootstrapKPSecret: nil,
				stagedUpdates: alice.stagedUpdates,
				pendingProposal: alice.pendingProposal,
				pqInflight: alice.pqInflight,
				rotationCandidate: alice.rotationCandidate,
				auth: alice.auth,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
		_ = bob
	}

	// MARK: - Check 5: an unheld staged Upd is rejected

	/// A current-epoch staged Upd naming a key `leafKeys` doesn't hold
	/// (neither `current` nor `pending[its id]`) must fail
	/// `validateLeafKeys` — the direct negative for check 5. Hand-builds
	/// the Upd on alice's OWN recv-classical leaf (mirrors
	/// `FoldTests.authorBobCredentialRotation`) but deliberately never
	/// stages the fresh key into `leafKeys`, simulating a tampered or
	/// mis-mapped archive.
	@available(iOS 26, macOS 26, *)
	@Test func validateLeafKeysRejectsAStagedUpdateNamingAnUnheldKey() throws {
		let (alice, _) = try SessionTestSupport.establishedAndExchanged()
		var mirror = try #require(alice.recvGroup)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.classical.proposeUpdate(
			SessionTestSupport.classicalProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.classicalProvider,
				current: try alice.recvClassicalSigningKey(), new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: Data("alice-untracked".utf8)),
				signatureKey: freshSignatureKey))
		let bytes = try message.mlsEncoded()
		var withUntrackedUpdate = alice
		withUntrackedUpdate.stagedUpdates.append(
			(
				digest: try SessionTestSupport.classicalProvider.hash(bytes),
				message: bytes
			))

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.validateLeafKeys(
				withUntrackedUpdate.leafKeys,
				sendGroup: withUntrackedUpdate.sendGroup,
				recvGroup: withUntrackedUpdate.recvGroup,
				identity: withUntrackedUpdate.identity,
				bootstrapKPSecret: nil,
				stagedUpdates: withUntrackedUpdate.stagedUpdates,
				pendingProposal: withUntrackedUpdate.pendingProposal,
				pqInflight: withUntrackedUpdate.pqInflight,
				rotationCandidate: withUntrackedUpdate.rotationCandidate,
				auth: withUntrackedUpdate.auth,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}

		// Unmodified (no untracked staged Upd) passes.
		#expect(throws: Never.self) {
			try TwoMLSSession.validateLeafKeys(
				alice.leafKeys, sendGroup: alice.sendGroup,
				recvGroup: alice.recvGroup,
				identity: alice.identity, bootstrapKPSecret: nil,
				stagedUpdates: alice.stagedUpdates,
				pendingProposal: alice.pendingProposal,
				pqInflight: alice.pqInflight,
				rotationCandidate: alice.rotationCandidate,
				auth: alice.auth,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
		_ = mirror
	}

	/// Check 5's other direction: a `recvPQ.pending` entry with no parked
	/// §A.5 Upd′ (`pqInflight` not `.rekeyInitiated`) to justify it must
	/// also fail — the only thing that ever stages one is that parked Upd′,
	/// so an entry surviving under any other `pqInflight` is a leftover or
	/// smuggled key, never a meaningful in-flight offer.
	@available(iOS 26, macOS 26, *)
	@Test func validateLeafKeysRejectsARecvPQPendingEntryWithNoParkedUpd() throws {
		let (alice, _) = try RatchetTests.fullyEstablishedTurnOnBob()
		#expect(alice.pqInflight == nil)
		var withStrayPending = alice
		withStrayPending.leafKeys.recvPQ.pending[Data("stray-pq-target".utf8)] =
			try freshKey()

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.validateLeafKeys(
				withStrayPending.leafKeys,
				sendGroup: withStrayPending.sendGroup,
				recvGroup: withStrayPending.recvGroup,
				identity: withStrayPending.identity,
				bootstrapKPSecret: nil,
				stagedUpdates: withStrayPending.stagedUpdates,
				pendingProposal: withStrayPending.pendingProposal,
				pqInflight: withStrayPending.pqInflight,
				rotationCandidate: withStrayPending.rotationCandidate,
				auth: withStrayPending.auth,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}

		// Unmodified (empty recvPQ.pending) passes.
		#expect(throws: Never.self) {
			try TwoMLSSession.validateLeafKeys(
				alice.leafKeys, sendGroup: alice.sendGroup,
				recvGroup: alice.recvGroup,
				identity: alice.identity, bootstrapKPSecret: nil,
				stagedUpdates: alice.stagedUpdates,
				pendingProposal: alice.pendingProposal,
				pqInflight: alice.pqInflight,
				rotationCandidate: alice.rotationCandidate,
				auth: alice.auth,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	/// The `pendingProposal` arm of check 5 — `stagedUpdates` is not the
	/// only own-Update source: an offered-but-not-yet-staged proposal must
	/// ALSO name a held key, or restore/mint must reject it the same way.
	@available(iOS 26, macOS 26, *)
	@Test func validateLeafKeysRejectsAPendingProposalNamingAnUnheldKey() throws {
		let (alice, _) = try SessionTestSupport.establishedAndExchanged()
		var mirror = try #require(alice.recvGroup)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.classical.proposeUpdate(
			SessionTestSupport.classicalProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.classicalProvider,
				current: try alice.recvClassicalSigningKey(), new: freshSigningKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: Data("alice-untracked-pending".utf8)),
				signatureKey: freshSignatureKey))
		let bytes = try message.mlsEncoded()
		var withUntrackedPending = alice
		withUntrackedPending.pendingProposal = (
			proposing: alice.identity.clientID, message: bytes,
			hash: try SessionTestSupport.classicalProvider.hash(bytes)
		)

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.validateLeafKeys(
				withUntrackedPending.leafKeys,
				sendGroup: withUntrackedPending.sendGroup,
				recvGroup: withUntrackedPending.recvGroup,
				identity: withUntrackedPending.identity,
				bootstrapKPSecret: nil,
				stagedUpdates: withUntrackedPending.stagedUpdates,
				pendingProposal: withUntrackedPending.pendingProposal,
				pqInflight: withUntrackedPending.pqInflight,
				rotationCandidate: withUntrackedPending.rotationCandidate,
				auth: withUntrackedPending.auth,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
		_ = mirror
	}

	/// A non-empty `sendPQ.pending` is never meaningful in this version —
	/// nothing stages one (PQ has no rotation-candidate arm) — so
	/// validation must reject it even though it names no OTHER invariant
	/// check by itself.
	@available(iOS 26, macOS 26, *)
	@Test func validateLeafKeysRejectsANonEmptySendPQPending() throws {
		let (alice, _) = try SessionTestSupport.establishedAndExchanged()
		var withStrayPending = alice
		withStrayPending.leafKeys.sendPQ.pending[Data("stray".utf8)] = try freshKey()

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.validateLeafKeys(
				withStrayPending.leafKeys, sendGroup: withStrayPending.sendGroup,
				recvGroup: withStrayPending.recvGroup,
				identity: withStrayPending.identity, bootstrapKPSecret: nil,
				stagedUpdates: withStrayPending.stagedUpdates,
				pendingProposal: withStrayPending.pendingProposal,
				pqInflight: withStrayPending.pqInflight,
				rotationCandidate: withStrayPending.rotationCandidate,
				auth: withStrayPending.auth,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	// MARK: - The PQ sticky checkpoint upgrade depends on the fingerprint

	/// The sticky checkpoint invariant must fire on a PQ key-set
	/// change even when NEITHER PQ epoch moved — `pqEpochManifest` folds in
	/// each PQ set's fingerprint for exactly this reason (a bare epoch
	/// comparison alone would miss it). Adds a `recvPQ` pending entry
	/// directly (no epoch change) and confirms a plain `.core` request is
	/// upgraded to `.checkpoint`.
	@available(iOS 26, macOS 26, *)
	@Test func pqKeySetChangeAloneTriggersTheStickyCheckpointUpgrade() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let begin = try alice.pqBootstrapBegin()
		let respond = try bob.pqBootstrapRespond(begin.frame)
		_ = try alice.pqBootstrapJoin(respond.frame)
		let checkpoint = try alice.stateUpdate(kind: .checkpoint)
		#expect(checkpoint.kind == .checkpoint)

		let sendPQEpochBefore = alice.sendGroup?.pq?.context.epoch
		let recvPQEpochBefore = alice.recvGroup?.pq?.context.epoch
		alice.leafKeys.recvPQ.pending[Data("fingerprint-probe".utf8)] = try freshKey()

		let update = try alice.stateUpdate(kind: .core)
		#expect(alice.sendGroup?.pq?.context.epoch == sendPQEpochBefore)
		#expect(alice.recvGroup?.pq?.context.epoch == recvPQEpochBefore)
		#expect(
			update.kind == .checkpoint,
			"a PQ key-set change must upgrade a .core request even with no epoch move")
	}

	// MARK: - Fault injection: write-back is write-back-only-on-success

	/// A fault at `committingRound`'s own write-back point (the send-
	/// classical catch-up's promotion) must leave `leafKeys` completely
	/// untouched — proving the local-copy-then-write-back discipline this
	/// PR adds alongside the pre-existing `send`/`auth`/ledger copies, not
	/// merely alongside them. Reaches the catch-up path via a full
	/// rotation round (author/approve/fold), then arms the fault right
	/// before the round that would perform the send-leaf catch-up.
	/// Complements the four AFTER-write-back points below, which prove the
	/// opposite direction: this one proves nothing moved yet.
	#if DEBUG
		@available(iOS 26, macOS 26, *)
		@Test func committingRoundLeafKeysWriteBackFailsAtomicallyOnAFault() throws {
			var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
			let newID = Data("alice-v2".utf8)
			_ = try alice.prepareToEncrypt(rotating: newID)
			let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
			let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
			_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
			_ = try bob.prepareToEncrypt()
			let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
			let foldDecrypted = try alice.processIncomingDecrypted(foldFrame)
			#expect(foldDecrypted.ownCredentialCanonicalized)

			// Alice's next `prepareToEncrypt()` folds Bob's routine offer
			// (staged on the frame above) and rides the send-leaf catch-up
			// (`committingRound`'s `catchUpTargetID` branch) — arm the fault
			// right at its write-back point first.
			_ = try alice.queueProposal(digest: foldDecrypted.queuedProposal.digest)
			let before = alice.leafKeys
			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault("committingRound.beforeWriteBack")
				#expect(throws: (any Error).self) { try alice.prepareToEncrypt() }
				#expect(
					alice.leafKeys.sendClassical.current?.signatureKey
						== before.sendClassical.current?.signatureKey,
					"a fault at the write-back point must leave leafKeys untouched"
				)
			}

			// The session is not bricked: a fresh fold (fault no longer armed)
			// completes the catch-up normally.
			_ = try bob.prepareToEncrypt()
			let bobOfferFrame2 = try bob.encrypt(Data("bob-offer".utf8)).frame
			let bobOfferSaw2 = try alice.processIncomingDecrypted(bobOfferFrame2)
			_ = try alice.queueProposal(digest: bobOfferSaw2.queuedProposal.digest)
			_ = try alice.prepareToEncrypt()
			let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
			let catchUpDecrypted = try bob.processIncomingDecrypted(catchUpFrame)
			#expect(catchUpDecrypted.newSender == newID)
		}
	#endif

	// MARK: - Fault injection: AFTER write-back, before the next throwing call

	/// `committingRound`'s catch-up write-back (`leafKeys = updatedLeafKeys`)
	/// followed by a fault right before `recordListenRendezvous()` — the
	/// opposite proof from the test above: `leafKeys` must already be FULLY
	/// promoted even though this round never finishes. Compares the whole
	/// archived value against an unfaulted twin and confirms the live
	/// session stays internally consistent (`assertLeafKeysPresented()`). A
	/// live retry is NOT genuinely possible here: `sendGroup` (the tree,
	/// its epoch already advanced) writes back in the SAME assignment as
	/// `leafKeys`, before `currentStaple` is ever re-encoded — a second
	/// `prepareToEncrypt()` would try to commit again on top of an
	/// already-advanced tree with no matching staple to fall back to,
	/// producing a frame the peer's own epoch window cannot accept. The
	/// durable recovery path is what this test proves instead: a restore
	/// from the last-persisted Checkpoint (captured before this call, so it
	/// never saw the advance at all) still performs the catch-up cleanly.
	#if DEBUG
		@available(iOS 26, macOS 26, *)
		@Test func committingRoundLeafKeysSurviveAFaultAfterWriteBack() throws {
			var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
			let newID = Data("alice-v3".utf8)
			_ = try alice.prepareToEncrypt(rotating: newID)
			let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
			let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
			_ = try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest)
			_ = try bob.prepareToEncrypt()
			let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
			let foldDecrypted = try alice.processIncomingDecrypted(foldFrame)
			#expect(foldDecrypted.ownCredentialCanonicalized)

			let checkpointBeforeCatchUp = try alice.makeSessionArchive(
				kind: .checkpoint)
			var aliceControl = alice
			// A separate peer copy for the restore-continuation check — never
			// touched by the faulted `alice`'s own (never-delivered) frame.
			var bobForRestoreCheck = bob
			let recvClassicalBeforeThisCall = alice.leafKeys.recvClassical
			let sendClassicalBeforeThisCall = alice.leafKeys.sendClassical

			// The catch-up rides a fold of Bob's routine offer (staged on the
			// frame above) — on the faulted `alice` and on its control alike.
			_ = try alice.queueProposal(digest: foldDecrypted.queuedProposal.digest)
			_ = try aliceControl.queueProposal(
				digest: foldDecrypted.queuedProposal.digest)

			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault(
					"committingRound.afterWriteBackBeforeRendezvous")
				#expect(throws: (any Error).self) { try alice.prepareToEncrypt() }
				try alice.assertLeafKeysPresented()
			}

			_ = try aliceControl.prepareToEncrypt()
			// The fault fires inside `committingRound` — the send-side half
			// of `prepareToEncrypt`. Send-classical mints its key AT the
			// commit itself (system randomness), so — unlike sendPQ/recvPQ
			// below, which this round never touches — the faulted call and
			// the unfaulted control mint INDEPENDENT keys and can never
			// match byte for byte. What must still hold: the write-back
			// left `current` set to something new (the mint ran), and
			// `pending` empty (nothing is ever staged there in advance).
			// D3's fresh routine-offer mint is the RECV-side half, reached
			// only after `committingRound` returns; the faulted call never
			// gets there, so `recvClassical` stays exactly as it was going
			// into this call, not what the control's own (freshly minted,
			// randomized) offer left it as.
			#expect(alice.leafKeys.sendClassical.pending.isEmpty)
			#expect(
				alice.leafKeys.sendClassical.current?.signatureKey
					!= sendClassicalBeforeThisCall.current?.signatureKey,
				"the write-back must have minted and promoted a new send-classical key"
			)
			#expect(
				GroupKeySetArchive(alice.leafKeys.sendPQ)
					== GroupKeySetArchive(aliceControl.leafKeys.sendPQ))
			#expect(
				GroupKeySetArchive(alice.leafKeys.recvPQ)
					== GroupKeySetArchive(aliceControl.leafKeys.recvPQ))
			#expect(
				GroupKeySetArchive(alice.leafKeys.recvClassical)
					== GroupKeySetArchive(recvClassicalBeforeThisCall),
				"the recv-side offer mint never ran — recvClassical is untouched")

			// Restoring from the last blob persisted BEFORE this call continues
			// normally — a durable-but-behind record is not stuck, even though
			// the live session itself cannot safely retry in place.
			var restored = try TwoMLSSession.restore(
				core: nil, checkpoint: checkpointBeforeCatchUp,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			// The catch-up again rides a fold — `bobForRestoreCheck` surfaces a
			// routine `Upd(self)` for `restored` to approve and fold.
			_ = try bobForRestoreCheck.prepareToEncrypt()
			let restoredOfferFrame = try bobForRestoreCheck.encrypt(
				Data("restore-offer".utf8)
			).frame
			let restoredOfferSaw = try restored.processIncomingDecrypted(
				restoredOfferFrame)
			_ = try restored.queueProposal(
				digest: restoredOfferSaw.queuedProposal.digest)
			let preparedRestored = try restored.prepareToEncrypt()
			#expect(preparedRestored.didCommit)
			let restoredFrame = try restored.encrypt(Data("post-restore".utf8)).frame
			let restoredDecrypted = try bobForRestoreCheck.processIncomingDecrypted(
				restoredFrame)
			#expect(
				restoredDecrypted.applicationMessage == Data("post-restore".utf8))
		}
	#endif

	/// `prepareToEncrypt`'s recv-classical staging write-back
	/// (`leafKeys = mintedLeafKeys`) followed by a fault right before
	/// `message.mlsEncoded()` — the newly-staged candidate must already be
	/// in `leafKeys.recvClassical.pending` even though the proposal never
	/// gets encoded. An unfaulted TWIN is not the right comparison here: a
	/// first-time rotation mints a FRESH random candidate key per call, so
	/// two independent mints for the same target id are expected to
	/// differ. A live retry IS genuinely possible: re-staging the SAME
	/// candidate reuses the ALREADY-staged key (`existing.clientID ==
	/// rotating`), not a fresh mint — this is `GroupKeySet.stage`'s own
	/// documented idempotent no-op.
	#if DEBUG
		@available(iOS 26, macOS 26, *)
		@Test func prepareToEncryptLeafKeysSurviveAFaultAfterWriteBack() throws {
			var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
			let checkpointBeforeRotation = try alice.makeSessionArchive(
				kind: .checkpoint)
			// A separate peer copy for the restore-continuation check — `bob`
			// itself is used for the LIVE retry's frame.
			var bobForRestoreCheck = bob
			let newID = Data("alice-v4".utf8)

			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault(
					"prepareToEncrypt.afterWriteBackBeforeEncode")
				#expect(throws: (any Error).self) {
					try alice.prepareToEncrypt(rotating: newID)
				}
				try alice.assertLeafKeysPresented()

				let candidate = try #require(alice.rotationCandidate)
				#expect(candidate.clientID == newID)
				// Send-classical is never staged in advance — only
				// recv-classical holds the candidate's key until it converges.
				#expect(alice.leafKeys.recvClassical.pending[newID] != nil)
				#expect(alice.leafKeys.sendClassical.pending.isEmpty)
			}

			// A live retry (re-staging the same id) is the documented
			// idempotent case, and completes the round.
			_ = try alice.prepareToEncrypt(rotating: newID)
			let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
			let offerDecrypted = try bob.processIncomingDecrypted(offerFrame)
			#expect(offerDecrypted.queuedProposal != nil)

			var restored = try TwoMLSSession.restore(
				core: nil, checkpoint: checkpointBeforeRotation,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			_ = try restored.prepareToEncrypt()
			let restoredFrame = try restored.encrypt(Data("post-restore".utf8)).frame
			let restoredDecrypted = try bobForRestoreCheck.processIncomingDecrypted(
				restoredFrame)
			#expect(
				restoredDecrypted.applicationMessage == Data("post-restore".utf8))
		}
	#endif

	/// `processMessageFrame`'s fold-staple write-back (inside `handleStaple`,
	/// which promotes recv-classical on a folded rotation) followed by a
	/// fault right before `decryptAppSection` — the peer's rotation must
	/// already be folded into `leafKeys` even though the app section never
	/// decrypts. A live retry is NOT possible here: this fault fires while
	/// processing one specific inbound frame, and that frame's app section
	/// was never decrypted — there is nothing to "retry" against the same
	/// input (the shared classifier would treat a second delivery of the same staple as
	/// stale/behind, not as this round completing). The DURABLE recovery
	/// path is what this test proves instead: a restore from the
	/// last-persisted Checkpoint (captured before delivery) still folds
	/// the SAME frame cleanly.
	#if DEBUG
		@available(iOS 26, macOS 26, *)
		@Test func processMessageFrameLeafKeysSurviveAFaultAfterStaple() throws {
			var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
			let newID = Data("bob-v2".utf8)
			_ = try bob.prepareToEncrypt(rotating: newID)
			let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
			let offerDecrypted = try alice.processIncomingDecrypted(offerFrame)
			_ = try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)
			_ = try alice.prepareToEncrypt()
			let foldFrame = try alice.encrypt(Data("fold".utf8)).frame

			let checkpointBeforeFold = try bob.makeSessionArchive(kind: .checkpoint)
			var bobControl = bob

			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault(
					"processMessageFrame.afterStapleBeforeDecrypt")
				#expect(throws: (any Error).self) {
					try bob.processIncomingDecrypted(foldFrame)
				}
				try bob.assertLeafKeysPresented()
			}

			let controlDecrypted = try bobControl.processIncomingDecrypted(foldFrame)
			#expect(controlDecrypted.ownCredentialCanonicalized)
			#expect(
				LeafKeysArchive(bob.leafKeys, kind: .checkpoint)
					== LeafKeysArchive(bobControl.leafKeys, kind: .checkpoint),
				"the fold's write-back landed the SAME leafKeys value the unfaulted delivery would have"
			)

			var restored = try TwoMLSSession.restore(
				core: nil, checkpoint: checkpointBeforeFold,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			let restoredDecrypted = try restored.processIncomingDecrypted(foldFrame)
			#expect(restoredDecrypted.ownCredentialCanonicalized)
		}
	#endif

	/// `pqRekeyApply`'s recv-PQ promotion write-back (`leafKeys =
	/// updatedLeafKeys`) followed by a fault right before `owePQBind` — the
	/// rekeyed group's promoted key must already be in `leafKeys.recvPQ`
	/// even though the classical bind is never owed. A live retry is NOT
	/// possible: `pqRekeyApply` consumes `pqInflight`'s `.rekeyResponded`
	/// state as it runs (the Commit′ was already applied to the PQ tree
	/// before the fault point), so a second call has nothing left to
	/// apply. The durable recovery path is what this test proves instead.
	#if DEBUG
		@available(iOS 26, macOS 26, *)
		@Test func pqRekeyApplyLeafKeysSurviveAFaultAfterWriteBack() throws {
			// Same reason as `SigningKeyProtocolTests`'s protocol doc §3 catch-up tests:
			// the hand-built renaming Upd′ has no rotation-candidate arm to
			// resolve through.
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			// A routine (non-hand-built) mechanical round never renames the
			// credential, so `promoted` would be a no-op and this fault
			// couldn't move anything observable — hand-build a RENAMING
			// Upd′ instead (the write-back this test targets is the
			// promotion itself). Protocol doc §3's PQ leaf move is catch-up-only: the
			// new id must already be canonical, so bob classically rotates
			// and converges to it FIRST, exactly like
			// `SigningKeyProtocolTests.testSection3PQLeafCatchUpToAnAlreadyCanonicalID`.
			let newBobID = Data("bob-pq-fault-v2".utf8)
			_ = try bob.prepareToEncrypt(rotating: newBobID)
			let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
			let decryptedOffer = try alice.processIncomingDecrypted(offerFrame)
			_ = try alice.queueProposal(digest: decryptedOffer.queuedProposal.digest)
			let foldPrepared = try alice.prepareToEncrypt()
			#expect(foldPrepared.didCommit)
			let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
			_ = try bob.processIncomingDecrypted(foldFrame)
			#expect(alice.theirPrincipalState == .sync(newBobID))

			var bobMirror = try #require(bob.recvGroup)
			var bobPQ = try #require(bobMirror.pq)
			let (freshSigningKey, freshSignatureKey) =
				try TwoMLSIdentity.mintSignatureKeypair()
			let (message, _) = try bobPQ.proposeUpdate(
				SessionTestSupport.pqProvider,
				sign: MLS.RFC9420.signingClosure(
					SessionTestSupport.pqProvider,
					current: try bob.recvPQSigningKey(), new: freshSigningKey),
				framing: .publicMessage,
				newIdentity: MLS.RFC9420.NewSigningIdentity(
					credential: .basic(identity: newBobID),
					signatureKey: freshSignatureKey)
			)
			bobMirror.pq = bobPQ
			bob.recvGroup = bobMirror
			try bob.leafKeys.recvPQ.stage(
				LeafKey(
					signingKey: freshSigningKey, signatureKey: freshSignatureKey
				),
				for: newBobID)
			let updBytes = try message.mlsEncoded()
			let updFrame = Frames.encodePQRekeyUpd(updBytes)
			let commitFrame = try alice.pqRekeyRespond(updFrame).frame
			bob.pqInflight = .rekeyInitiated(updMessage: updBytes)

			let checkpointBeforeApply = try bob.makeSessionArchive(kind: .checkpoint)
			var bobControl = bob

			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault(
					"pqRekeyApply.afterWriteBackBeforeBind")
				#expect(throws: (any Error).self) {
					try bob.pqRekeyApply(commitFrame)
				}
				try bob.assertLeafKeysPresented()
			}

			_ = try bobControl.pqRekeyApply(commitFrame)
			#expect(
				LeafKeysArchive(bob.leafKeys, kind: .checkpoint)
					== LeafKeysArchive(bobControl.leafKeys, kind: .checkpoint),
				"the promotion's write-back landed the SAME leafKeys value the unfaulted apply would have"
			)

			var restored = try TwoMLSSession.restore(
				core: nil, checkpoint: checkpointBeforeApply,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			_ = try restored.pqRekeyApply(commitFrame)
			#expect(restored.owedBind != nil)
		}

		/// `pqBootstrapRespond` registers its founding key in the SAME
		/// non-throwing block as the group write-back, before
		/// `recordPQHeaderKey()` — a fault right after that write-back must
		/// still leave `sendGroup.pq` founded AND `leafKeys.sendPQ.current`
		/// already presenting its key, so the very next state-advancing
		/// call's choke point (`assertLeafKeysPresented`) passes even though
		/// this call itself threw.
		@available(iOS 26, macOS 26, *)
		@Test func pqBootstrapRespondRegistersTheFoundingKeyWithTheGroup() throws {
			var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
			let kpFrame = try alice.pqBootstrapBegin().frame

			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault("pqBootstrapRespond.afterWriteBack")
				#expect(throws: (any Error).self) {
					try bob.pqBootstrapRespond(kpFrame)
				}

				let sendPQGroup = try #require(
					bob.sendGroup?.pq, "the founded group survives the fault")
				let presentedKey = try TwoMLSSession.ownLeaf(of: sendPQGroup)
					.signatureKey
				#expect(bob.leafKeys.sendPQ.current?.signatureKey == presentedKey)
				try bob.assertLeafKeysPresented()
			}
		}

		/// `pqRekeyBegin` (via `stageRekey`) registers its fresh recv-PQ key
		/// in the SAME non-throwing block as `recvGroup`'s/`pqInflight`'s own
		/// write-back — a fault right after that block must still leave
		/// `leafKeys.recvPQ.pending` holding the fresh key, with `pqInflight`
		/// ALSO landed (the write-back is atomic: every field lands
		/// together, never a stray pending key with no parked round). A
		/// retry re-serves the SAME parked round idempotently (the top-of-
		/// call re-serve branch), rather than minting again.
		@available(iOS 26, macOS 26, *)
		@Test func pqRekeyBeginRegistersTheFreshKeyWithTheGroup() throws {
			var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			#expect(bob.myPQTurn)
			let ownID = try basicIdentifier(
				TwoMLSSession.ownLeaf(of: try #require(bob.recvGroup?.pq))
					.credential)
			let currentKeyBefore = bob.leafKeys.recvPQ.current

			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault("pqRekeyBegin.afterWriteBack")
				#expect(throws: (any Error).self) { try bob.pqRekeyBegin() }

				#expect(
					bob.pqInflight != nil,
					"the atomic write-back lands pqInflight too")
				let pendingKey = try #require(bob.leafKeys.recvPQ.pending[ownID])
				#expect(pendingKey.signatureKey != currentKeyBefore?.signatureKey)
				#expect(
					bob.leafKeys.recvPQ.current?.signatureKey
						== currentKeyBefore?.signatureKey)
				try bob.assertLeafKeysPresented()
			}
		}

		/// The self-drive's own call into `stageRekey` swallows its throw
		/// (`try?`), so `encrypt` itself never surfaces a fault armed there —
		/// it must still leave `self` in a state whose archive restores
		/// (check 6/7 pass): the atomic write-back means the parked
		/// `Upd′` and its staged key land together, never one without the
		/// other. Kills: splitting that write-back around a throw.
		@available(iOS 26, macOS 26, *)
		@Test func selfDriveFaultAfterWriteBackLeavesARestorableSession() throws {
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			let bobNewID = Data("bob-fault-after-writeback".utf8)

			_ = try bob.prepareToEncrypt(rotating: bobNewID)
			let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
			if case .initiating = bob.pqInflight {
				bob.pqInflight = nil
				bob.pendingSideBand = nil
			}
			let offerDecrypted = try alice.processIncomingDecrypted(offerFrame)
			try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)
			let foldPrepared = try alice.prepareToEncrypt()
			#expect(foldPrepared.didCommit)
			let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
			_ = try bob.processIncomingDecrypted(foldFrame)
			#expect(bob.myPrincipalState == .sync(bobNewID))
			#expect(bob.myPQTurn)

			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault("pqRekeyBegin.afterWriteBack")
				_ = try bob.prepareToEncrypt()
				#expect(throws: Never.self) {
					try bob.encrypt(Data("self-driven".utf8))
				}
			}

			let hasParkedUpd: Bool
			if case .rekeyInitiated = bob.pqInflight {
				hasParkedUpd = true
			} else {
				hasParkedUpd = false
			}
			let hasPendingKey = bob.leafKeys.recvPQ.pending[bobNewID] != nil
			#expect(
				hasParkedUpd == hasPendingKey,
				"the atomic write-back means both land or neither does")

			let archive = try bob.makeSessionArchive(kind: .checkpoint)
			#expect(throws: Never.self) {
				try TwoMLSSession.restore(
					core: nil, checkpoint: archive,
					classicalProvider: SessionTestSupport.classicalProvider,
					pqProvider: SessionTestSupport.pqProvider)
			}
		}

		/// `pqRekeyRespond` registers its fresh send-PQ key in the SAME
		/// non-throwing block as `sendGroup`'s own write-back, before
		/// `recordPQHeaderKey()` — a fault right after that write-back must
		/// still leave the rekeyed group's fresh key already promoted into
		/// `leafKeys.sendPQ.current`, matching `pqBootstrapRespond`'s own
		/// precedent above.
		@available(iOS 26, macOS 26, *)
		@Test func pqRekeyRespondRegistersTheFreshKeyWithTheGroup() throws {
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			let begin = try bob.pqRekeyBegin()

			try TwoMLSSessionTestHooks.withIsolatedFaults {
				TwoMLSSessionTestHooks.armFault("pqRekeyRespond.afterWriteBack")
				#expect(throws: (any Error).self) {
					try alice.pqRekeyRespond(begin.frame)
				}

				#expect(
					alice.pqInflight == nil,
					"the fault landed before pqInflight was set")
				let presentedKey = try TwoMLSSession.ownLeaf(
					of: try #require(alice.sendGroup?.pq)
				).signatureKey
				#expect(alice.leafKeys.sendPQ.current?.signatureKey == presentedKey)
				try alice.assertLeafKeysPresented()
			}
		}
	#endif

	// MARK: - Restore equals live, driven across the whole lifecycle

	/// Tracks the LATEST real `StateUpdate` archive of each kind a session
	/// has actually returned — never a fresh, synthetic pair minted on
	/// demand (which would always tie in `stateSeq` and so always take the
	/// Checkpoint, never exercising the splice path). Recording by `kind`
	/// alone is safe to pair at ANY later point: the sticky-checkpoint
	/// invariant guarantees any `StateUpdate` that actually moved PQ state
	/// is stamped `.checkpoint`, so a `.core` recorded after the latest
	/// `.checkpoint` can never disagree with it on PQ epoch or fingerprint.
	private struct RestoreTracker {
		var latestCore: SecretArchive?
		var latestCheckpoint: SecretArchive?

		mutating func record(_ update: StateUpdate) {
			switch update.kind {
			case .core: latestCore = update.archive
			case .checkpoint: latestCheckpoint = update.archive
			}
		}
	}

	/// Restores from the tracker's latest Core + latest Checkpoint (exactly
	/// what `restore` is meant to reconcile from) and checks the result
	/// matches `session.leafKeys` EXACTLY, right now. Called after every
	/// state-advancing call below, not just at the end, so a moment restore
	/// gets wrong can't hide behind a later step that happens to paper
	/// over it.
	@available(iOS 26, macOS 26, *)
	private func assertRestoreEqualsLive(
		_ session: TwoMLSSession, using tracker: RestoreTracker,
		sourceLocation: SourceLocation = #_sourceLocation
	) throws {
		guard let checkpoint = tracker.latestCheckpoint else {
			Issue.record("no checkpoint recorded yet", sourceLocation: sourceLocation)
			return
		}
		let live = LeafKeysArchive(session.leafKeys, kind: .checkpoint)
		let restored = try TwoMLSSession.restore(
			core: tracker.latestCore, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(
			LeafKeysArchive(restored.leafKeys, kind: .checkpoint) == live,
			"restore from the tracker's latest Core + latest Checkpoint",
			sourceLocation: sourceLocation)
	}

	/// Drives the plain lifecycle — establishment, §A.3, a full §A.4
	/// ratchet, a full §A.5 mechanical re-key, and a complete classical
	/// rotation (stage, peer fold, send-leaf catch-up) — recording every
	/// real `StateUpdate` into each side's own tracker and checking restore
	/// equals live after EVERY state-advancing call along the way, not
	/// only at the end. The classical rotation's own `.core` updates land
	/// AFTER the §A.5 round's last `.checkpoint`, so by then each tracker's
	/// latest Core is genuinely newer than its latest Checkpoint — the
	/// splice path, not just the Checkpoint-alone path, is exercised.
	@available(iOS 26, macOS 26, *)
	@Test func restoreEqualsLiveAcrossThePlainLifecycle() throws {
		let established = try SessionTestSupport.established()
		var alice = established.alice
		var bob = established.bob
		var aliceTracker = RestoreTracker()
		var bobTracker = RestoreTracker()
		// `established()` doesn't surface its own baseline `StateUpdate`,
		// so seed each tracker from a fresh Checkpoint of the
		// as-established state instead.
		aliceTracker.record(
			StateUpdate(
				kind: .checkpoint, stateSeq: alice.stateSeq,
				archive: try alice.makeSessionArchive(kind: .checkpoint)))
		bobTracker.record(
			StateUpdate(
				kind: .checkpoint, stateSeq: bob.stateSeq,
				archive: try bob.makeSessionArchive(kind: .checkpoint)))

		_ = try bob.prepareToEncrypt()
		let helloEncrypted = try bob.encrypt(Data("bob-hello".utf8))
		bobTracker.record(helloEncrypted.update)
		let helloDecrypted = try alice.processIncomingDecrypted(helloEncrypted.frame)
		aliceTracker.record(helloDecrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		try assertRestoreEqualsLive(bob, using: bobTracker)

		// §A.3.
		let begin = try alice.pqBootstrapBegin()
		aliceTracker.record(begin.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		let respond = try bob.pqBootstrapRespond(begin.frame)
		bobTracker.record(respond.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		let joinUpdate = try alice.pqBootstrapJoin(respond.frame)
		aliceTracker.record(joinUpdate)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		#expect(alice.owedBind != nil)
		let preparedDischarge = try alice.prepareToEncrypt()
		aliceTracker.record(preparedDischarge.update)
		let dischargeEncrypted = try alice.encrypt(Data("a3-discharge".utf8))
		aliceTracker.record(dischargeEncrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		let dischargeDecrypted = try bob.processIncomingDecrypted(dischargeEncrypted.frame)
		bobTracker.record(dischargeDecrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)

		// A full §A.4 ratchet, unconditional. Self-drive (`maybeStageNextRound`)
		// runs from `encrypt`, on whoever calls it while holding the PQ
		// turn — bob HOLDS the turn after the discharge above but hasn't
		// sent anything himself yet, so his own next routine send is what
		// triggers it. This is REQUIRED, not a maybe, so a silent `if case`
		// skip here would hide a genuine regression rather than merely a
		// slow engine.
		#expect(bob.myPQTurn)
		let preparedTrigger = try bob.prepareToEncrypt()
		bobTracker.record(preparedTrigger.update)
		let triggerEncrypted = try bob.encrypt(Data("a4-trigger".utf8))
		bobTracker.record(triggerEncrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		let triggerDecrypted = try alice.processIncomingDecrypted(triggerEncrypted.frame)
		aliceTracker.record(triggerDecrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		guard case .initiating = bob.pqInflight, let ekFrame = bob.pqPendingOutbound()
		else {
			Issue.record(
				"expected bob to have self-staged an A.4 EK on his own next send")
			return
		}
		let sealed = try alice.pqRatchetRespond(ekFrame)
		aliceTracker.record(sealed.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		let bindUpdate = try bob.pqRatchetBind(sealed.frame)
		bobTracker.record(bindUpdate)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		let preparedA4Bound = try bob.prepareToEncrypt()
		#expect(preparedA4Bound.didCommit)
		bobTracker.record(preparedA4Bound.update)
		let a4BoundEncrypted = try bob.encrypt(Data("a4-bound".utf8))
		bobTracker.record(a4BoundEncrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		let a4BoundDecrypted = try alice.processIncomingDecrypted(a4BoundEncrypted.frame)
		aliceTracker.record(a4BoundDecrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		#expect(alice.myPQTurn)

		// A full §A.5 mechanical re-key: alice (who now holds the PQ turn)
		// opens it, bob commits, alice applies and owes the bind, alice
		// discharges, bob applies the ack.
		let a5UpdFrame = try alice.pqRekeyBegin()
		aliceTracker.record(a5UpdFrame.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		let a5Commit = try bob.pqRekeyRespond(a5UpdFrame.frame)
		bobTracker.record(a5Commit.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		let a5ApplyUpdate = try alice.pqRekeyApply(a5Commit.frame)
		aliceTracker.record(a5ApplyUpdate)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		#expect(alice.owedBind != nil)
		let preparedA5Bound = try alice.prepareToEncrypt()
		#expect(preparedA5Bound.didCommit)
		aliceTracker.record(preparedA5Bound.update)
		let a5BoundEncrypted = try alice.encrypt(Data("a5-bound".utf8))
		aliceTracker.record(a5BoundEncrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		let a5BoundDecrypted = try bob.processIncomingDecrypted(a5BoundEncrypted.frame)
		bobTracker.record(a5BoundDecrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)

		// A full classical rotation: stage, peer fold, send-leaf catch-up —
		// every one of these updates is classical-only (`.core`), so from
		// here on each tracker's latest Core is genuinely ahead of its
		// latest Checkpoint (minted above, during §A.5).
		let newID = Data("alice-lifecycle-v2".utf8)
		let preparedRotation = try alice.prepareToEncrypt(rotating: newID)
		aliceTracker.record(preparedRotation.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		let offerEncrypted = try alice.encrypt(Data("offer".utf8))
		aliceTracker.record(offerEncrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		let offerDecrypted = try bob.processIncomingDecrypted(offerEncrypted.frame)
		bobTracker.record(offerDecrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		bobTracker.record(
			try bob.queueProposal(digest: offerDecrypted.queuedProposal.digest))
		let preparedFold = try bob.prepareToEncrypt()
		bobTracker.record(preparedFold.update)
		let foldEncrypted = try bob.encrypt(Data("fold".utf8))
		bobTracker.record(foldEncrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		let foldDecrypted = try alice.processIncomingDecrypted(foldEncrypted.frame)
		#expect(foldDecrypted.ownCredentialCanonicalized)
		aliceTracker.record(foldDecrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		// The catch-up rides a fold of Bob's routine offer (staged on the
		// same frame above), never a plain `prepareToEncrypt()`.
		aliceTracker.record(
			try alice.queueProposal(digest: foldDecrypted.queuedProposal.digest))
		let preparedCatchUp = try alice.prepareToEncrypt()
		aliceTracker.record(preparedCatchUp.update)
		let catchUpEncrypted = try alice.encrypt(Data("catchup".utf8))
		aliceTracker.record(catchUpEncrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		let catchUpDecrypted = try bob.processIncomingDecrypted(catchUpEncrypted.frame)
		#expect(catchUpDecrypted.newSender == newID)
		bobTracker.record(catchUpDecrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
	}

	/// The born-dedicated flow: `receive`'s own seeding, the routine send
	/// that discharges §A.3's owed bind, and a full rule-4 catch-up round —
	/// offer, fold, AND the resulting canonicalization — restore equals
	/// live at every step, tracked the same way as the plain lifecycle.
	@available(iOS 26, macOS 26, *)
	@Test func restoreEqualsLiveAcrossTheBornDedicatedLifecycle() throws {
		let established = try SessionTestSupport.establishedDedicatedAndApproved(
			dedicatedClientID: Data("bob-d2-dedicated".utf8))
		var alice = established.alice
		var bob = established.bob
		var aliceTracker = RestoreTracker()
		var bobTracker = RestoreTracker()
		// Neither side's baseline `StateUpdate` survives past `receive`'s
		// own return in this helper, so seed each tracker from a fresh
		// Checkpoint of the as-established state instead.
		bobTracker.record(
			StateUpdate(
				kind: .checkpoint, stateSeq: bob.stateSeq,
				archive: try bob.makeSessionArchive(kind: .checkpoint)))
		aliceTracker.record(
			StateUpdate(
				kind: .checkpoint, stateSeq: alice.stateSeq,
				archive: try alice.makeSessionArchive(kind: .checkpoint)))
		try assertRestoreEqualsLive(bob, using: bobTracker)
		try assertRestoreEqualsLive(alice, using: aliceTracker)

		let preparedHello = try bob.prepareToEncrypt()
		bobTracker.record(preparedHello.update)
		let helloEncrypted = try bob.encrypt(Data("dedicated-hello".utf8))
		bobTracker.record(helloEncrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		let helloDecrypted = try alice.processIncomingDecrypted(helloEncrypted.frame)
		aliceTracker.record(helloDecrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)

		// The rule-4 catch-up, driven to full convergence: bob offers his
		// own leaf's move up to D, alice approves and folds it, and bob's
		// own view canonicalizes once he processes that fold back.
		let preparedCatchUp = try bob.prepareToEncrypt()
		bobTracker.record(preparedCatchUp.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		let catchUpEncrypted = try bob.encrypt(Data("dedicated-catchup".utf8))
		bobTracker.record(catchUpEncrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
		let catchUpDecrypted = try alice.processIncomingDecrypted(catchUpEncrypted.frame)
		aliceTracker.record(catchUpDecrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)

		aliceTracker.record(
			try alice.queueProposal(digest: catchUpDecrypted.queuedProposal.digest))
		let preparedFold = try alice.prepareToEncrypt()
		aliceTracker.record(preparedFold.update)
		let foldEncrypted = try alice.encrypt(Data("dedicated-fold".utf8))
		aliceTracker.record(foldEncrypted.update)
		try assertRestoreEqualsLive(alice, using: aliceTracker)
		let foldDecrypted = try bob.processIncomingDecrypted(foldEncrypted.frame)
		#expect(foldDecrypted.ownCredentialCanonicalized)
		bobTracker.record(foldDecrypted.update)
		try assertRestoreEqualsLive(bob, using: bobTracker)
	}
}

/// `RotationCandidateArchive`'s pre-retirement shape (keys 0-3, keys 1/2
/// the now-dropped signing/signature key) — encoding-only, so this test can
/// build a body that still carries them.
@available(iOS 26, macOS 26, *)
private struct WideRotationCandidateArchive: Encodable {
	var clientID: Data
	var signingKey: Data
	var signatureKey: Data
	var proposedAtRecvEpoch: UInt64

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case clientID = 0
		case signingKey = 1
		case signatureKey = 2
		case proposedAtRecvEpoch = 3
	}
}

/// `RecvLeafPrincipalArchive`'s pre-retirement shape (archive key 40 in
/// `SessionArchive`) — encoding-only, standing in for a field this engine no
/// longer even declares.
@available(iOS 26, macOS 26, *)
private struct OldRecvLeafPrincipalArchive: Encodable {
	var clientID: Data
	var signingKey: Data
	var signatureKey: Data
	var pqSigningKey: Data
	var pqSignatureKey: Data

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case clientID = 0
		case signingKey = 1
		case signatureKey = 2
		case pqSigningKey = 3
		case pqSignatureKey = 4
	}
}

/// A `SessionArchive` body, encoding-only, at the exact same coding keys as
/// the live type — EXCEPT `rotationCandidate` (key 31) carries its retired
/// keys 1/2 and an extra `recvLeafPrincipal` (key 40) rides along, neither
/// of which the live `SessionArchive`/`RotationCandidateArchive` declare any
/// more. Proves an archive body shaped like a pre-retirement one (a real
/// migrator input, or a dev archive written before this change) still
/// decodes and restores: synthesized `Decodable` ignores unknown integer
/// keys.
@available(iOS 26, macOS 26, *)
private struct WideSessionArchive: Encodable {
	var version: UInt64
	var classicalSuite: UInt16
	var pqSuite: UInt16
	var kind: BlobKind
	var stateSeq: UInt64
	var sendPQEpoch: UInt64?
	var recvPQEpoch: UInt64?
	var sendClassicalGroupID: Data?
	var recvClassicalGroupID: Data?
	var identity: IdentityArchive
	var auth: AuthCore
	var sendGroup: GroupEntry?
	var recvGroup: GroupEntry?
	var currentStaple: Data
	var pendingProposal: PendingProposalArchive?
	var joinedWelcomeDigest: Data?
	var initiated: Bool
	var bootstrapKPSecret: BootstrapKPSecretArchive?
	var expectedBootstrapKPCommitment: Data?
	var pqTurnMine: Bool
	var owedBind: OwedBind?
	var pqInflight: PQInflightArchive?
	var pendingSideBand: Data?
	var peerAppliedSendEpoch: UInt64?
	var lastCrossInjected: UInt64?
	var lastCrossInjectedPQ: UInt64?
	var lastSendPQExported: UInt64?
	var offeredProposal: DigestedProposalArchive?
	var queuedProposal: DigestedProposalArchive?
	var stagedUpdates: [StagedUpdateArchive]
	var sendCrossPSKLedger: ArchiveIntegerKeyedMap<ExportedPskArchive>
	var rotationCandidate: WideRotationCandidateArchive?
	var spawnToken: Data?
	var listenRendezvous: ArchiveIntegerKeyedMap<Data>?
	var recvHeaderKeys: ArchiveIntegerKeyedMap<Data>?
	var recvHeaderKeysPQ: ArchiveIntegerKeyedMap<Data>?
	var initialTheirKP: CombinerKeyPackageArchive?
	var sendAttachmentLedger: ArchiveIntegerKeyedMap<SecretField<SecretBytes>>?
	var recvAttachmentLedger: ArchiveIntegerKeyedMap<SecretField<SecretBytes>>?
	var owesEstablishmentEnvelope: Bool?
	var recvLeafPrincipal: OldRecvLeafPrincipalArchive?
	var leafKeys: LeafKeysArchive
	var sendPQKeysFingerprint: GroupKeySetFingerprint
	var recvPQKeysFingerprint: GroupKeySetFingerprint
	var deployedCarry: DeployedCarryArchive?
	var initialAppPayload: Data?

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case version = 0
		case classicalSuite = 1
		case pqSuite = 2
		case kind = 3
		case stateSeq = 4
		case sendPQEpoch = 5
		case recvPQEpoch = 6
		case sendClassicalGroupID = 7
		case recvClassicalGroupID = 8
		case identity = 9
		case auth = 10
		case sendGroup = 11
		case recvGroup = 12
		case currentStaple = 13
		case pendingProposal = 14
		case joinedWelcomeDigest = 15
		case initiated = 16
		case bootstrapKPSecret = 17
		case expectedBootstrapKPCommitment = 18
		case pqTurnMine = 19
		case owedBind = 20
		case pqInflight = 21
		case pendingSideBand = 22
		case peerAppliedSendEpoch = 23
		case lastCrossInjected = 24
		case lastCrossInjectedPQ = 25
		case lastSendPQExported = 26
		case offeredProposal = 27
		case queuedProposal = 28
		case stagedUpdates = 29
		case sendCrossPSKLedger = 30
		case rotationCandidate = 31
		case spawnToken = 32
		case listenRendezvous = 33
		case recvHeaderKeys = 34
		case recvHeaderKeysPQ = 35
		case initialTheirKP = 36
		case sendAttachmentLedger = 37
		case recvAttachmentLedger = 38
		case owesEstablishmentEnvelope = 39
		case recvLeafPrincipal = 40
		case leafKeys = 41
		case sendPQKeysFingerprint = 42
		case recvPQKeysFingerprint = 43
		case deployedCarry = 44
		case initialAppPayload = 45
	}
}

extension LeafKeysTests {
	/// Test 14: a body shaped like a pre-retirement archive — carrying
	/// `RotationCandidateArchive`'s retired keys 1/2 and a `recvLeafPrincipal`
	/// at key 40 — still decodes and restores, because a synthesized
	/// `Decodable` ignores unknown integer keys. Kills a strict decoder that
	/// rejects an archive body it doesn't recognize every key of.
	@available(iOS 26, macOS 26, *)
	@Test func archiveWithRetiredKeyFieldsStillDecodes() throws {
		var alice = try SessionTestSupport.establishedAndExchanged().alice
		_ = try alice.prepareToEncrypt(rotating: Data("alice-retired-fields".utf8))
		let real = try alice.makeSessionArchive(kind: .checkpoint).decode(
			SessionArchive.self)
		let realCandidate = try #require(real.rotationCandidate)

		let wide = WideSessionArchive(
			version: real.version, classicalSuite: real.classicalSuite,
			pqSuite: real.pqSuite, kind: real.kind, stateSeq: real.stateSeq,
			sendPQEpoch: real.sendPQEpoch, recvPQEpoch: real.recvPQEpoch,
			sendClassicalGroupID: real.sendClassicalGroupID,
			recvClassicalGroupID: real.recvClassicalGroupID, identity: real.identity,
			auth: real.auth, sendGroup: real.sendGroup, recvGroup: real.recvGroup,
			currentStaple: real.currentStaple, pendingProposal: real.pendingProposal,
			joinedWelcomeDigest: real.joinedWelcomeDigest, initiated: real.initiated,
			bootstrapKPSecret: real.bootstrapKPSecret,
			expectedBootstrapKPCommitment: real.expectedBootstrapKPCommitment,
			pqTurnMine: real.pqTurnMine, owedBind: real.owedBind,
			pqInflight: real.pqInflight, pendingSideBand: real.pendingSideBand,
			peerAppliedSendEpoch: real.peerAppliedSendEpoch,
			lastCrossInjected: real.lastCrossInjected,
			lastCrossInjectedPQ: real.lastCrossInjectedPQ,
			lastSendPQExported: real.lastSendPQExported,
			offeredProposal: real.offeredProposal, queuedProposal: real.queuedProposal,
			stagedUpdates: real.stagedUpdates,
			sendCrossPSKLedger: real.sendCrossPSKLedger,
			rotationCandidate: WideRotationCandidateArchive(
				clientID: realCandidate.clientID,
				signingKey: Data(repeating: 0x11, count: 32),
				signatureKey: Data(repeating: 0x22, count: 32),
				proposedAtRecvEpoch: realCandidate.proposedAtRecvEpoch),
			spawnToken: real.spawnToken, listenRendezvous: real.listenRendezvous,
			recvHeaderKeys: real.recvHeaderKeys,
			recvHeaderKeysPQ: real.recvHeaderKeysPQ,
			initialTheirKP: real.initialTheirKP,
			sendAttachmentLedger: real.sendAttachmentLedger,
			recvAttachmentLedger: real.recvAttachmentLedger,
			owesEstablishmentEnvelope: real.owesEstablishmentEnvelope,
			recvLeafPrincipal: OldRecvLeafPrincipalArchive(
				clientID: Data("retired-principal".utf8),
				signingKey: Data(repeating: 0x33, count: 32),
				signatureKey: Data(repeating: 0x44, count: 32),
				pqSigningKey: Data(repeating: 0x55, count: 32),
				pqSignatureKey: Data(repeating: 0x66, count: 32)),
			leafKeys: real.leafKeys, sendPQKeysFingerprint: real.sendPQKeysFingerprint,
			recvPQKeysFingerprint: real.recvPQKeysFingerprint,
			deployedCarry: real.deployedCarry, initialAppPayload: real.initialAppPayload
		)

		let archive = try SecretArchive(encoding: wide)
		let decoded = try archive.decode(SessionArchive.self)
		#expect(decoded.rotationCandidate?.clientID == realCandidate.clientID)

		#expect(throws: Never.self) {
			try TwoMLSSession.restore(
				core: nil, checkpoint: archive,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}
}

/// Every field of `SessionArchive` that is itself REQUIRED (non-`Optional`),
/// at the SAME coding keys, EXCEPT key 41 (`leafKeys`) — used only to prove
/// `restore` rejects a body missing it. An optional field needs no stand-in
/// here: a `SessionArchive` decode treats a missing optional key exactly
/// like an explicit `nil`, so leaving one out of this struct changes
/// nothing decode-relevant about the fields this test actually cares about.
@available(iOS 26, macOS 26, *)
private struct PartialSessionArchive: Codable {
	var version: UInt64
	var classicalSuite: UInt16
	var pqSuite: UInt16
	var kind: BlobKind
	var stateSeq: UInt64
	var identity: IdentityArchive
	var auth: AuthCore
	var currentStaple: Data
	var initiated: Bool
	var pqTurnMine: Bool
	var stagedUpdates: [StagedUpdateArchive]
	var sendCrossPSKLedger: ArchiveIntegerKeyedMap<ExportedPskArchive>
	var sendPQKeysFingerprint: GroupKeySetFingerprint
	var recvPQKeysFingerprint: GroupKeySetFingerprint

	enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
		case version = 0
		case classicalSuite = 1
		case pqSuite = 2
		case kind = 3
		case stateSeq = 4
		case identity = 9
		case auth = 10
		case currentStaple = 13
		case initiated = 16
		case pqTurnMine = 19
		case stagedUpdates = 29
		case sendCrossPSKLedger = 30
		case sendPQKeysFingerprint = 42
		case recvPQKeysFingerprint = 43
	}
}
