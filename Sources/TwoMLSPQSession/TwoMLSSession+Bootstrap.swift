import Foundation
import MLSCodec
import MLSCombiner
import MLSProfileRFC9420
import SecretBytes

// MARK: - §A.3 PQ bootstrap

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// The §A.3 round is registered at `initiate`, around the pre-committed
	/// KP′ — every initiator carries `.bootstrapInitiated` and the parked
	/// `0x13` from birth. This is the post-join re-serve: once `recvGroup`
	/// exists and its PQ half is not yet founded, it re-seals the SAME
	/// retained frame rather than re-checking turn/state (a re-send should
	/// not depend on nothing having moved since the first call). Before the
	/// Group_B join it falls through to the readiness guard below, so a
	/// pre-join call still answers `.sessionNotReady` — pre-join delivery is
	/// `pqBootstrapEnvelope()`'s job, not this call's. A spent round (the
	/// bind already landed) also falls through, instead of re-emitting a
	/// stale `0x13`.
	public mutating func pqBootstrapBegin() throws -> SideBandResult {
		// The non-emittable gate.
		try ensureEstablishmentDelegated()
		// Readiness first: a recv group must already exist before the
		// idempotent branch can re-seal anything — `initiate` registers the
		// round on EVERY initiator, well before the Group_B join, so this
		// pre-join case is common, not a corner. Without the explicit
		// `recvGroup` check here, `recvGroup?.pq == nil` reads true for a
		// nil recv group too, and the re-seal below would throw
		// `.notEstablished` instead of this call's own `.sessionNotReady`.
		if case .bootstrapInitiated = pqInflight, let pending = pendingSideBand,
			let recv = recvGroup, recv.pq == nil
		{
			let sealed = try sealSideBand(pending)
			advanceStateSeq()
			return SideBandResult(frame: sealed, update: try stateUpdate(kind: .core))
		}
		guard
			pqTurnMine, sendGroup != nil, let recv = recvGroup, recv.pq == nil,
			let bootstrapKP = try bootstrapKPBytes()
		else {
			throw TwoMLSError.sessionNotReady
		}
		let frame = Frames.encodePQBootstrapKP(bootstrapKP)
		pqInflight = .bootstrapInitiated
		pendingSideBand = frame
		let sealed = try sealSideBand(frame)

		// Return cadence: parks the 0x13 frame — classical state only → `.core`.
		advanceStateSeq()
		return SideBandResult(frame: sealed, update: try stateUpdate(kind: .core))
	}

	/// The responder (Bob) receives KP′, checks it against the commitment
	/// pinned at `receive`, founds Group_B.pq (`APQGroup.foundPQHalf`) with
	/// KP′ as the sole Add, and returns the resulting Welcome′ as a `0x15`
	/// side-band frame. Bob is `isFullyEstablished` once this returns. The
	/// inbound frame is validated (tag, decode, commitment) before anything
	/// about this session's own state is consulted, so nothing is ever
	/// re-emitted for garbage or a mismatched KP′. Once `sendGroup.pq` is
	/// founded, this re-serves the retained `0x15` only while its own §A.3
	/// round is still open (`pqInflight == .bootstrapResponded`) — the
	/// re-serve carries no group-level move, so it returns `.core`.
	/// Afterward, or for a round that was never this one, it answers
	/// `.duplicateSideBand` with no state change.
	///
	/// Seam: this does not check KP′'s leaf credential names the already-
	/// established peer (Rust's AS `validate_member`). It fails closed regardless — a wrong-peer KP′ founds a
	/// Group_B.pq the real peer never agrees to join, so the bind can never
	/// complete.
	public mutating func pqBootstrapRespond(_ inbound: Data) throws -> SideBandResult {
		// The founding leaf is minted under this party's own then-canonical
		// id (book session-lifecycle.md: A.3 runs on the principal a prior
		// rotation may have installed) — before anything about the peer's
		// frame is even decoded, so an unused mint is the only cost of a
		// frame that later fails validation.
		guard let founderID = auth.mine.current else { throw TwoMLSError.credentialUnknown }
		let founding = try TwoMLSIdentity.mintFoundingLeaf(
			clientID: founderID, provider: pqProvider)
		return try pqBootstrapRespond(inbound, founding: founding)
	}

	/// The `founding:` seam: the current entry point above mints a fresh
	/// founding leaf and calls through here. Tests that need to control it
	/// directly (a deployed-shaped fixture, or an injected capability-less
	/// rogue leaf) call this overload.
	mutating func pqBootstrapRespond(_ inbound: Data, founding: FoundingLeaf) throws
		-> SideBandResult
	{
		// The non-emittable gate.
		try ensureEstablishmentDelegated()
		// Entry: the peer's `0x13` arrives header-sealed.
		let frame = openOrRaw(inbound)
		// Validate the frame itself FIRST — tag, decode, then the commitment
		// check — before anything about this session's own state is even
		// consulted, so garbage or a mismatched KP′ never earns a re-serve.
		let kpBytes = try Frames.decodePQBootstrapKP(frame)
		guard
			let expected = expectedBootstrapKPCommitment,
			try classicalProvider.hash(kpBytes) == expected
		else {
			throw TwoMLSError.bootstrapKPMismatch
		}
		if sendGroup?.pq != nil {
			// Re-serve only while THIS round is still open — once it has
			// closed (or was never this round), nothing is re-emitted for a
			// validated-but-stale KP′ either.
			guard case .bootstrapResponded = pqInflight, let pending = pendingSideBand
			else {
				throw TwoMLSError.duplicateSideBand
			}
			let sealed = try sealSideBand(pending)
			advanceStateSeq()
			return SideBandResult(
				frame: sealed, update: try stateUpdate(kind: .core))
		}
		guard
			case .keyPackage(let peerBootstrapKP) = try MLS.RFC9420.Message(
				mlsEncoded: kpBytes)
		else {
			throw TwoMLSError.malformedSideBandMessage
		}
		try TwoPartyRules.ensureAdvertisesAPQCapabilities(
			peerBootstrapKP.leafNode, codepoints: codepoints)
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }

		let (pqGroup, welcome) = try APQGroup.foundPQHalf(
			sendGroupClassical: send.classical,
			ownPQLeaf: founding.leafNode,
			ownPQLeafSecret: founding.leafSecretKey,
			signingKey: founding.key.signingKey,
			peerBootstrapKP: peerBootstrapKP, randomness: try .generate(pqProvider),
			epochSecret: SecretBytes(randomByteCount: pqProvider.hashSize),
			pqProvider: pqProvider,
			codepoints: codepoints)
		send.pq = pqGroup
		sendGroup = send
		// Registered in the same non-throwing block as the group write-back,
		// before `recordPQHeaderKey()` — the founding key this leaf just
		// presented becomes the group's own stored signing source right
		// away, never left implicit.
		leafKeys.sendPQ = GroupKeySet(current: founding.key)
		// (DEBUG only): a fault point right after the write-back above —
		// proves `sendGroup`/`leafKeys.sendPQ` are already fully
		// write-back-complete (both the founded group and its registered
		// key) even if the next throwing call fails.
		#if DEBUG
			if TwoMLSSessionTestHooks.shouldFault("pqBootstrapRespond.afterWriteBack") {
				throw InjectedTestFault(name: "pqBootstrapRespond.afterWriteBack")
			}
		#endif
		// Founds `sendGroup.pq`: capture its birth-epoch header key.
		try recordPQHeaderKey()

		let welcomeBytes = try MLS.RFC9420.Message.welcome(welcome).mlsEncoded()
		let responseFrame = Frames.encodePQBootstrapWelcome(welcomeBytes)
		pqInflight = .bootstrapResponded
		pendingSideBand = responseFrame
		let sealed = try sealSideBand(responseFrame)

		// Return cadence: founded `sendGroup.pq` → `.checkpoint`.
		advanceStateSeq()
		return SideBandResult(
			frame: sealed, update: try stateUpdate(kind: .checkpoint))
	}

	/// The initiator (Alice) joins Group_B.pq off Bob's Welcome′, using the
	/// KP′ secrets minted at `initiate` as joiner credentials, exports the
	/// cross-party `S` off the freshly-joined epoch-1 leaf, then owes the
	/// bind (`owePQBind(s:)`). Alice is `isFullyEstablished` once this
	/// returns. `pendingProposal == nil` guards against staple-stacking:
	/// a routine `Upd(self)` must already be discharged (`encrypt`)
	/// before the bootstrap can add its own commit to the pile. Clears
	/// `bootstrapKPSecret` once spent.
	///
	/// A Welcome′ can arrive before the Group_B join — the registered round
	/// means the acceptor may answer before the initiator's first send. Read
	/// before the join, this throws `.sessionNotReady`: retriable, no state
	/// change; a host holds the bytes and re-feeds them once the join
	/// completes.
	public mutating func pqBootstrapJoin(_ inbound: Data) throws -> StateUpdate {
		// Entry: the peer's `0x15` arrives header-sealed.
		let frame = openOrRaw(inbound)
		let welcomeBytes = try Frames.decodePQBootstrapWelcome(frame)
		guard case .welcome(let welcome) = try MLS.RFC9420.Message(mlsEncoded: welcomeBytes)
		else {
			throw TwoMLSError.malformedSideBandMessage
		}
		// The fatal name check, at every PQ door, checked right
		// after the untrusted decode and before any state-shape guard —
		// mirrors Rust's own `pq_bootstrap_bind` (decode, then
		// `check_not_wedged`, then its state-shape guards, `mod.rs`).
		guard pqWedge == nil else { throw TwoMLSError.pqSideBandWedged }
		guard pendingProposal == nil else { throw TwoMLSError.sessionNotReady }
		guard let secret = bootstrapKPSecret else { throw TwoMLSError.sessionNotReady }
		guard var recv = recvGroup else { throw TwoMLSError.sessionNotReady }
		// No-custody guard, before anything is consumed — this
		// door's `owePQBind` commits `sendGroup.pq`.
		guard !noCustody.contains(.sendPQ) else {
			throw TwoMLSError.leafCustodyUnavailable
		}

		let credentials = MLS.RFC9420.Group.JoinerCredentials(
			keyPackage: secret.keyPackage, initKey: secret.initSecretKey,
			encryptionKey: secret.leafSecretKey)
		var pqGroup = try APQGroup.joinPQHalf(
			welcome: welcome, credentials: credentials,
			classicalHalfForPairCheck: recv.classical, pqProvider: pqProvider,
			codepoints: codepoints)
		// Defense in depth (book group-rules.md rule 8): the binding lives on
		// the classical halves only — every PQ-half join re-checks that no
		// copy was smuggled in, even one Bob (an honest founder) never writes.
		try verifyPQHalfUnbound(pqGroup)
		try TwoPartyRules.ensureAdvertisesAPQCapabilities(
			Self.joinedCreatorLeaf(of: pqGroup), codepoints: codepoints)
		bootstrapKPSecret = nil

		try withDeployedWireConventions {
			let recvPQEpochBeforeExport = pqGroup.context.epoch
			let sExport = try MLS.Combiner.ExportedPsk.export(
				from: &pqGroup, pqProvider,
				componentID: Self.crossPartyComponentID)
			// Joining off KP′'s own secrets leaves `leafKeys.recvPQ`
			// untouched — it was already reserved to KP′'s key at
			// `receive`/founding.
			recv.pq = pqGroup
			recvGroup = recv
			lastCrossInjectedPQ = recvPQEpochBeforeExport
			try owePQBind(s: sExport.psk)
		}
		// The `0x13`/`0x15` side-band round is now fully spent (Group_B.pq is
		// joined and the bind is owed) — clear the retained frame and inflight
		// marker so a stray re-call of `pqBootstrapBegin`/`pqBootstrapRespond`
		// cannot re-emit them.
		pqInflight = nil
		pendingSideBand = nil

		// Return cadence: joined `recvGroup.pq` → `.checkpoint`.
		advanceStateSeq()
		return try stateUpdate(kind: .checkpoint)
	}

	/// Fold `s` into a pathless PARTIAL commit on `sendGroup.pq`
	/// and park the resulting commit message as `owedBind` until a licensed
	/// `prepareToEncrypt` can discharge it. Callers supply `s` however
	/// their round obtained it — the A.3 bootstrap exports it off the
	/// freshly-joined Group_B.pq (`pqBootstrapJoin`); the A.4 ratchet opens
	/// it from a KEM ciphertext (`pqRatchetBind`) — this function only ever
	/// reads/writes `sendGroup`/`send.pq`.
	///
	/// Seam: `s`'s single-shot leaf (however the caller obtained it) is
	/// already spent by the time this runs; a throw from `committing` wedges
	/// the session with `isFullyEstablished == true` but no `owedBind` and no
	/// way to re-derive `s` (Rust latches a `BindTriggerFailed` state for
	/// this). Not handled here.
	// internal: used by Ratchet.pqRatchetBind and Rekey.pqRekeyApply
	internal mutating func owePQBind(s: SecretBytes) throws {
		guard var send = sendGroup, let sendPQ = send.pq else {
			throw TwoMLSError.notEstablished
		}

		try withDeployedWireConventions {
			let attestation = MLS.Combiner.ApqInfoUpdate(
				tEpoch: send.classical.context.epoch + 1,
				pqEpoch: sendPQ.context.epoch + 1)

			// Id = LE64(epoch) ‖ groupID ‖ [0x52] — hand-rolled, never
			// re-derived from the wire; the peer recomputes this same id from
			// its own mirror and matches on it exactly, not on `.external`
			// alone.
			let injectedID =
				withUnsafeBytes(of: sendPQ.context.epoch.littleEndian) { Data($0) }
				+ sendPQ.context.groupID + Data([0x52])
			let nonce = pqProvider.randomBytes(pqProvider.hashSize)

			// Deployed Rust carries this as an mls-rs `CustomProposal` —
			// `0x0008 ‖ opaque<V>(body)` — not swift-mls's typed, unwrapped
			// `.appDataUpdate` arm. `.custom` reproduces that wrapper
			// byte-for-byte.
			let proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(
					.preSharedKey(.external(pskID: injectedID, nonce: nonce))),
				.proposal(
					.custom(
						type: .init(.appDataUpdate),
						body: try attestation.appDataUpdate(
							componentID: codepoints.apqComponentID
						).mlsEncoded())),
			]
			let transition = try sendPQ.committing(
				pqProvider, proposals: proposals,
				signingKey: try sendPQSigningKey(),
				randomness: try .generate(pqProvider), includePath: false,
				framing: .publicMessage,
				psk: { identifier in
					guard case .external(let pskID, _) = identifier,
						pskID == injectedID
					else {
						return nil
					}
					return s
				})
			try withTransitionHandoff(transition) { adopted, sent in
				let commitBytes = try sent.message.mlsEncoded()
				let advanced = try sent.takePending().apply(onto: adopted)
				send.pq = advanced.group
				sendGroup = send
				// The single funnel for every discharge-triggering commit on
				// `sendGroup.pq` (`pqBootstrapJoin`/`pqRatchetBind`/
				// `pqRekeyApply` all call this) — capture its just-advanced
				// epoch's header key here, once, rather than at each call site.
				try recordPQHeaderKey()

				owedBind = OwedBind(
					pqCommitMessage: commitBytes, tEpoch: attestation.tEpoch,
					pqEpoch: attestation.pqEpoch)
			}
		}
	}
}
