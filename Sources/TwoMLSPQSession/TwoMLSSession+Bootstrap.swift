import Foundation
import MLSCodec
import MLSCombiner
import MLSProfileRFC9420
import SecretBytes

// MARK: - §A.3 PQ bootstrap

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// The initiator (Alice) begins the bootstrap: hand the pre-committed KP′
	/// to the peer as a `0x13` side-band frame. Requires it be my turn, both
	/// groups founded, and Group_B.pq not yet founded. Idempotent while a
	/// begin is already outstanding: re-returns the retained frame rather
	/// than re-checking turn/state (a re-send should not depend on nothing
	/// having moved since the first call) — but only while `recvGroup.pq` is
	/// still nil, so a spent round (the bind already landed) falls through
	/// to the normal guard instead of re-emitting a stale `0x13`.
	public mutating func pqBootstrapBegin() throws -> SideBandResult {
		// Slice 11: the non-emittable gate.
		try ensureEstablishmentDelegated()
		if case .bootstrapInitiated = pqInflight, let pending = pendingSideBand,
			recvGroup?.pq == nil
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

		// Return cadence (slice 8a): parks the 0x13 frame — classical state only → `.core`.
		advanceStateSeq()
		return SideBandResult(frame: sealed, update: try stateUpdate(kind: .core))
	}

	/// The responder (Bob) receives KP′, checks it against the commitment
	/// pinned at `receive`, founds Group_B.pq (`APQGroup.foundPQHalf`) with
	/// KP′ as the sole Add, and returns the resulting Welcome′ as a `0x15`
	/// side-band frame. Bob is `isFullyEstablished` once this returns.
	/// Idempotent once `sendGroup.pq` is founded: re-returns the retained
	/// `0x15` rather than founding a second Group_B.pq off a re-delivered
	/// `0x13` (a re-delivery with no retained frame to re-serve —
	/// `pendingSideBand` rides the session archive (slice 8a), so it
	/// survives a restore; a raw in-memory restart with no restore is the
	/// case with nothing to re-serve — is `.duplicateSideBand`).
	///
	/// Seam: this does not check KP′'s leaf credential names the already-
	/// established peer (Rust's AS `validate_member`; no AS exists until a
	/// later slice). It fails closed regardless — a wrong-peer KP′ founds a
	/// Group_B.pq the real peer never agrees to join, so the bind can never
	/// complete.
	public mutating func pqBootstrapRespond(_ inbound: Data) throws -> SideBandResult {
		// Slice 11: the non-emittable gate.
		try ensureEstablishmentDelegated()
		// Entry (PR2): the peer's `0x13` arrives header-sealed.
		let frame = openOrRaw(inbound)
		if sendGroup?.pq != nil {
			guard let pending = pendingSideBand else {
				throw TwoMLSError.duplicateSideBand
			}
			let sealed = try sealSideBand(pending)
			advanceStateSeq()
			return SideBandResult(
				frame: sealed, update: try stateUpdate(kind: .checkpoint))
		}
		let kpBytes = try Frames.decodePQBootstrapKP(frame)
		guard
			let expected = expectedBootstrapKPCommitment,
			try classicalProvider.hash(kpBytes) == expected
		else {
			throw TwoMLSError.bootstrapKPMismatch
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
		// Founding signs with the reservation already held in
		// `leafKeys.sendPQ.current` — seeded at `receive` to the founder
		// identity's own PQ pair (D's, once a dedicated principal exists),
		// which is why this reads the stored slot rather than
		// `identity.pqSigningKey` directly.
		guard let sendPQReservation = leafKeys.sendPQ.current else {
			throw TwoMLSError.credentialUnknown
		}

		// Slice 11: founding always presents `identity`'s OWN
		// fresh PQ leaf — with `identity` = D that is Group_B.pq's own
		// founder, `leafKeys.sendPQ.current` already names D's own key, so
		// this is correct without any further lookup; no existing
		// group to read a "presented leaf" off yet.
		let (pqGroup, welcome) = try APQGroup.foundPQHalf(
			sendGroupClassical: send.classical,
			ownPQLeaf: identity.keyPackage.pq.leafNode,
			ownPQLeafSecret: identity.pqLeafSecretKey,
			signingKey: sendPQReservation.signingKey,
			peerBootstrapKP: peerBootstrapKP, randomness: try .generate(pqProvider),
			epochSecret: SecretBytes(randomByteCount: pqProvider.hashSize),
			pqProvider: pqProvider,
			codepoints: codepoints)
		// `sendPQReservation` (already `leafKeys.sendPQ.current`, seeded at
		// `receive`) signed the founding leaf above; this call founds the
		// GROUP off it, so `leafKeys` itself is untouched.
		send.pq = pqGroup
		sendGroup = send
		// Founds `sendGroup.pq` (PR2): capture its birth-epoch header key.
		try recordPQHeaderKey()

		let welcomeBytes = try MLS.RFC9420.Message.welcome(welcome).mlsEncoded()
		let responseFrame = Frames.encodePQBootstrapWelcome(welcomeBytes)
		pqInflight = .bootstrapResponded
		pendingSideBand = responseFrame
		let sealed = try sealSideBand(responseFrame)

		// Return cadence (slice 8a): founded `sendGroup.pq` → `.checkpoint`.
		advanceStateSeq()
		return SideBandResult(
			frame: sealed, update: try stateUpdate(kind: .checkpoint))
	}

	/// The initiator (Alice) joins Group_B.pq off Bob's Welcome′, using the
	/// KP′ secrets minted at `initiate` as joiner credentials, exports the
	/// cross-party `S` off the freshly-joined epoch-1 leaf, then owes the
	/// bind (`owePQBind(s:)`, §4a). Alice is `isFullyEstablished` once this
	/// returns. `pendingProposal == nil` guards against staple-stacking
	/// (§11 #4): a routine `Upd(self)` must already be discharged (`encrypt`)
	/// before the bootstrap can add its own commit to the pile. Clears
	/// `bootstrapKPSecret` once spent (§11 #11).
	public mutating func pqBootstrapJoin(_ inbound: Data) throws -> StateUpdate {
		// Entry (PR2): the peer's `0x15` arrives header-sealed.
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
		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }
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

		// Return cadence (slice 8a): joined `recvGroup.pq` → `.checkpoint`.
		advanceStateSeq()
		return try stateUpdate(kind: .checkpoint)
	}

	/// §4a/§4c: fold `s` into a pathless PARTIAL commit on `sendGroup.pq`
	/// and park the resulting commit message as `owedBind` until a licensed
	/// `prepareToEncrypt` can discharge it (§4b). Callers supply `s` however
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

			// Id = LE64(epoch) ‖ groupID ‖ [0x52] — hand-rolled per §4, never
			// re-derived from the wire; the peer recomputes this same id from
			// its own mirror and matches on it exactly, not on `.external`
			// alone (§11 #5).
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
				// epoch's header key here, once, rather than at each call site
				// (PR2).
				try recordPQHeaderKey()

				owedBind = OwedBind(
					pqCommitMessage: commitBytes, tEpoch: attestation.tEpoch,
					pqEpoch: attestation.pqEpoch)
			}
		}
	}
}
