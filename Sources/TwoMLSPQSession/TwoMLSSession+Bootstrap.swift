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
	public mutating func pqBootstrapBegin() throws -> Data {
		if case .bootstrapInitiated = pqInflight, let pending = pendingSideBand,
			recvGroup?.pq == nil
		{
			return pending
		}
		guard
			pqTurnMine, sendGroup != nil, let recv = recvGroup, recv.pq == nil,
			let bootstrapKP
		else {
			throw TwoMLSError.sessionNotReady
		}
		let frame = Frames.encodePQBootstrapKP(bootstrapKP)
		pqInflight = .bootstrapInitiated
		pendingSideBand = frame
		return frame
	}

	/// The responder (Bob) receives KP′, checks it against the commitment
	/// pinned at `receive`, founds Group_B.pq (`APQGroup.foundPQHalf`) with
	/// KP′ as the sole Add, and returns the resulting Welcome′ as a `0x15`
	/// side-band frame. Bob is `isFullyEstablished` once this returns.
	/// Idempotent once `sendGroup.pq` is founded: re-returns the retained
	/// `0x15` rather than founding a second Group_B.pq off a re-delivered
	/// `0x13` (a re-delivery with no retained frame to re-serve, e.g. after
	/// a restart, is `.duplicateSideBand` — this module does not persist
	/// `pendingSideBand` across process restarts).
	///
	/// Seam: this does not check KP′'s leaf credential names the already-
	/// established peer (Rust's AS `validate_member`; no AS exists until a
	/// later slice). It fails closed regardless — a wrong-peer KP′ founds a
	/// Group_B.pq the real peer never agrees to join, so the bind can never
	/// complete.
	public mutating func pqBootstrapRespond(_ frame: Data) throws -> Data {
		if sendGroup?.pq != nil {
			guard let pending = pendingSideBand else {
				throw TwoMLSError.duplicateSideBand
			}
			return pending
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
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }

		let (pqGroup, welcome) = try APQGroup.foundPQHalf(
			sendGroupClassical: send.classical,
			ownPQLeaf: identity.keyPackage.pq.leafNode,
			ownPQLeafSecret: identity.pqLeafSecretKey, signingKey: identity.signingKey,
			peerBootstrapKP: peerBootstrapKP, randomness: try .generate(pqProvider),
			epochSecret: SecretBytes(randomByteCount: pqProvider.hashSize),
			pqProvider: pqProvider,
			codepoints: codepoints)
		send.pq = pqGroup
		sendGroup = send

		let welcomeBytes = try MLS.RFC9420.Message.welcome(welcome).mlsEncoded()
		let responseFrame = Frames.encodePQBootstrapWelcome(welcomeBytes)
		pqInflight = .bootstrapResponded
		pendingSideBand = responseFrame
		return responseFrame
	}

	/// The initiator (Alice) joins Group_B.pq off Bob's Welcome′, using the
	/// KP′ secrets minted at `initiate` as joiner credentials, exports the
	/// cross-party `S` off the freshly-joined epoch-1 leaf, then owes the
	/// bind (`owePQBind(s:)`, §4a). Alice is `isFullyEstablished` once this
	/// returns. `pendingProposal == nil` guards against staple-stacking
	/// (§11 #4): a routine `Upd(self)` must already be discharged (`encrypt`)
	/// before the bootstrap can add its own commit to the pile. Clears
	/// `bootstrapKPSecret` once spent (§11 #11).
	public mutating func pqBootstrapJoin(_ frame: Data) throws {
		guard pendingProposal == nil else { throw TwoMLSError.sessionNotReady }
		let welcomeBytes = try Frames.decodePQBootstrapWelcome(frame)
		guard case .welcome(let welcome) = try MLS.RFC9420.Message(mlsEncoded: welcomeBytes)
		else {
			throw TwoMLSError.malformedSideBandMessage
		}
		guard let secret = bootstrapKPSecret else { throw TwoMLSError.sessionNotReady }
		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }

		let credentials = MLS.RFC9420.Group.JoinerCredentials(
			keyPackage: secret.keyPackage, initKey: secret.initSecretKey,
			encryptionKey: secret.leafSecretKey)
		var pqGroup = try APQGroup.joinPQHalf(
			welcome: welcome, credentials: credentials,
			classicalHalfForPairCheck: recv.classical, pqProvider: pqProvider,
			codepoints: codepoints)
		bootstrapKPSecret = nil

		try withDeployedWireWidth {
			let recvPQEpochBeforeExport = pqGroup.context.epoch
			let sExport = try MLS.Combiner.ExportedPsk.export(
				from: &pqGroup, pqProvider,
				componentID: Self.crossPartyComponentID)
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

		try withDeployedWireWidth {
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

			let proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(
					.preSharedKey(.external(pskID: injectedID, nonce: nonce))),
				.proposal(
					try attestation.proposal(
						componentID: codepoints.apqComponentID)),
			]
			let transition = try sendPQ.committing(
				pqProvider, proposals: proposals, signingKey: identity.signingKey,
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
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let advanced = try sent.takePending().apply(onto: adopted)
			send.pq = advanced.group
			sendGroup = send

			owedBind = OwedBind(
				pqCommitMessage: commitBytes, tEpoch: attestation.tEpoch,
				pqEpoch: attestation.pqEpoch)
		}
	}
}
