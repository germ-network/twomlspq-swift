import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Invitation
//
// The self-contained receiving capability (book concepts.md's
// `TwoMlsPqInvitation`): one published combiner key package's private
// material, the captured signing identity, and the four tables that let one
// invitation service many welcomes with no live client. Return-based, no
// sink (book concepts.md's push-based persistence, adapted here the same
// way `TwoMLSSession`'s own state-advancing methods are): `receive` mutates
// `self` and returns the resulting session, its baseline checkpoint, and the
// updated invitation archive for the app to seal and save. Persist the
// baseline BEFORE (or atomically with) the invitation archive, and before
// transmitting any frame from the session: it is the acceptor's first
// restorable checkpoint, and an archive-only save followed by a crash loses
// the session (a redelivered welcome only reads back as `.duplicateWelcome`).

/// One published combiner key package's receiving capability. Holds the
/// captured KP private material plus signing identity as one
/// `TwoMLSIdentity`-shaped bundle (`nil` once a single-use invitation's KP
/// is consumed — book concepts.md: single-use "consum[es] it (dropping the
/// private material from the archive)"), and the four tables
/// `receive` maintains, each keyed as book session-lifecycle.md's
/// "Invitations & replayed initial frames" section describes, valued by the
/// spawned session's recv-group **classical** group id.
@available(iOS 26, macOS 26, *)
public struct Invitation: Sendable {
	let classicalProvider: any MLS.CipherSuiteProvider
	let pqProvider: any MLS.CipherSuiteProvider
	let codepoints: MLS.Combiner.Codepoints
	/// Kept independent of `identity` (which goes `nil` once a single-use
	/// invitation's key package is consumed) so this — book
	/// api-reference.md's `client_id()` invitation accessor — still answers
	/// after that.
	public let clientID: Data
	var identity: TwoMLSIdentity?
	public let lastResort: Bool
	public internal(set) var stateSeq: UInt64 = 0

	/// `spawnToken -> recv-group classical id` — resolves a replayed initial
	/// frame to the session that already accepted it.
	var forwardTable: [Data: Data] = [:]
	/// `SHA-256(welcome) -> recv-group classical id` — the content-keyed
	/// counterpart, resolving a re-delivered welcome by its exact bytes.
	var processedWelcomes: [Data: Data] = [:]
	/// `H(untagged KP′) -> recv-group classical id` — keyed by the SAME
	/// preimage as the `bootstrapKPCommitment` argument (the MLSMessage-
	/// wrapped KP′ bytes, no `0x13` side-band tag), so `bootstrapKPGroupID`
	/// can route a §A.3 frame delivered either way.
	var bootstrapRouting: [Data: Data] = [:]
	/// The remote client ids this invitation has already accepted a welcome
	/// from — the per-remote dedup guard.
	var consumedRemotes: Set<Data> = []

	init(
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints,
		clientID: Data,
		identity: TwoMLSIdentity?,
		lastResort: Bool
	) {
		self.classicalProvider = classicalProvider
		self.pqProvider = pqProvider
		self.codepoints = codepoints
		self.clientID = clientID
		self.identity = identity
		self.lastResort = lastResort
	}

	/// What to publish — `nil` once a single-use invitation's key package
	/// has been consumed.
	public var combinerKeyPackage: CombinerKeyPackage? { identity?.keyPackage }

	mutating func advanceStateSeq() {
		let (next, overflow) = stateSeq.addingReportingOverflow(1)
		if !overflow { stateSeq = next }
	}

	/// Establish from a remote initiator's welcome, delegating the actual
	/// join/found work to the identity-based `TwoMLSSession.receive`. Each
	/// half of `welcome` (the `0x01` APQ welcome) is an RFC 9420
	/// `MLSMessage`-wrapped `Welcome`; a bare struct is refused.
	/// Validation order — everything before any table insert or consume, so
	/// a rejected welcome claims nothing (book session-lifecycle.md):
	/// 1. `bootstrapKPCommitment` must be exactly 32 bytes.
	/// 2. parse `theirClassicalKeyPackage` for the remote's client id.
	/// 3. an already-processed welcome digest → `.duplicateWelcome`.
	/// 4. a single-use invitation whose KP is already spent →
	///    `.invitationSpent`.
	/// 5. an already-consumed remote → `.duplicateWelcome`.
	/// 6. delegate to `TwoMLSSession.receive` (enforces the welcome-creator
	///    ≡ KP identity binding, verifies `expectedAppBinding`, joins
	///    Group_A, founds Group_B) — a throw here (including
	///    `.appBindingMismatch`) claims nothing: this method's own table
	///    writes below all happen on a copy, only after this call returns.
	/// 7. commit: insert all four tables, single-use consume, bump
	///    `stateSeq`, return the spawned session, its baseline `.checkpoint`
	///    `StateUpdate` (`TwoMLSSession.receive`'s own
	///    `EstablishResult.baseline`, passed through verbatim — the
	///    acceptor's first restorable checkpoint, exactly
	///    `TwoMLSSession.initiate`'s `baseline` counterpart), and the
	///    updated invitation archive. Persist the baseline BEFORE (or
	///    atomically with) the archive, and before transmitting any frame
	///    from the session: the first frame's durability rests on it — a
	///    plain acceptor's first `prepareToEncrypt().dependsOnSeq` is
	///    `baseline.stateSeq`, and a born-dedicated acceptor's first frame
	///    depends on the `installEstablishmentEnvelope` `.core`, which
	///    restores only spliced onto this baseline.
	///
	/// `expectedAppBinding` is a TRAILING optional (see
	/// `TwoMLSSession.receive`) — the app-state binding the welcome must
	/// carry, `nil` for an unbound session. `newClientID` mirrors
	/// `TwoMLSSession.receive`'s own trailing slot —
	/// see its doc for the dedicated-principal semantics.
	public mutating func receive(
		welcome: Data,
		theirClassicalKeyPackage: MLS.RFC9420.KeyPackage,
		bootstrapKPCommitment: Data,
		spawnToken: Data,
		expectedAppBinding: Data? = nil,
		newClientID: Data? = nil
	) throws -> (session: TwoMLSSession, archive: SecretArchive, baseline: StateUpdate) {
		guard bootstrapKPCommitment.count == 32 else {
			throw TwoMLSError.bootstrapKPMismatch
		}
		let remoteID = try basicIdentifier(theirClassicalKeyPackage.leafNode.credential)
		let welcomeDigest = try classicalProvider.hash(welcome)

		guard processedWelcomes[welcomeDigest] == nil else {
			throw TwoMLSError.duplicateWelcome
		}
		guard let capturedIdentity = identity else {
			throw TwoMLSError.invitationSpent
		}
		guard !consumedRemotes.contains(remoteID) else {
			throw TwoMLSError.duplicateWelcome
		}

		let result = try TwoMLSSession.receive(
			identity: capturedIdentity, welcome: welcome,
			theirClassicalKeyPackage: theirClassicalKeyPackage,
			bootstrapKPCommitment: bootstrapKPCommitment, spawnToken: spawnToken,
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, expectedAppBinding: expectedAppBinding,
			newClientID: newClientID)
		guard let recvGroupID = result.session.recvGroup?.classical.context.groupID else {
			throw TwoMLSError.sessionNotReady
		}

		// Commit staged on a copy first: if `makeInvitationArchive()` throws
		// (an encode failure), `self` must be left unclaimed — none of the
		// four tables written, no consume — rather than half-committed with
		// no archive to show for it.
		var next = self
		next.forwardTable[spawnToken] = recvGroupID
		next.processedWelcomes[welcomeDigest] = recvGroupID
		next.bootstrapRouting[bootstrapKPCommitment] = recvGroupID
		next.consumedRemotes.insert(remoteID)
		if !lastResort {
			next.identity = nil
		}
		next.advanceStateSeq()
		let archive = try next.makeInvitationArchive()
		self = next
		return (session: result.session, archive: archive, baseline: result.baseline)
	}

	// MARK: - Routing helpers (read-only, no state change)

	/// `Some` means this exact initial frame was already accepted; route the
	/// payload to the owning session instead of surfacing a fresh welcome.
	public func forwardGroupID(spawnToken: Data) -> Data? {
		forwardTable[spawnToken]
	}

	/// The content-keyed counterpart of the forward table: resolves a
	/// re-delivered welcome by the digest of its exact bytes.
	public func processedWelcomeGroupID(welcome: Data) -> Data? {
		guard let digest = try? classicalProvider.hash(welcome) else { return nil }
		return processedWelcomes[digest]
	}

	/// Resolves a §A.3 bootstrap-KP frame (`[0x13][KP′]`, or the bare
	/// untagged KP′ bytes) to the session that owes A.3 for it — strips a
	/// leading `0x13` tag if present before hashing, so this routes whether
	/// the frame arrives tagged or already untagged (the same preimage
	/// `bootstrapKPCommitment()` hashes). The wire `0x13` travels
	/// header-sealed on the steady-state side-band and HPKE-sealed in the
	/// initiator's parallel `pqBootstrapEnvelope()`, so `kpFrame` here is the
	/// OPENED frame either way — a host calls this on the plaintext
	/// `openIncoming`/`tryOpen`/`openInitial` already produced, never on the
	/// sealed wire bytes. Resolves to `nil` before `receive` has run (the
	/// structural routing gate: no session exists yet).
	public func bootstrapKPGroupID(kpFrame: Data) -> Data? {
		let untagged =
			kpFrame.first == Frames.pqBootstrapKPTag
			? Data(kpFrame.dropFirst()) : kpFrame
		guard let digest = try? classicalProvider.hash(untagged) else { return nil }
		return bootstrapRouting[digest]
	}

	// MARK: - open_initial

	/// Opens a §A.1 envelope with this invitation's own (still-live) PQ
	/// init secret. Decrypt-only: no table writes, no consume — the four
	/// tables and `identity` are untouched either way, so an un-consumed
	/// invitation (single-use or last-resort) stays fully `receive`-able
	/// afterward, and re-opens are harmless. A spent single-use invitation
	/// (`identity` already `nil`) fails cleanly with `.invitationSpent`
	/// rather than crash.
	public func openInitial(_ envelope: Data) throws -> OpenedInitial {
		guard let identity else { throw TwoMLSError.invitationSpent }
		guard let pqInitSecretKey = identity.pqInitSecretKey else {
			throw TwoMLSError.sessionNotReady
		}
		let (enc, ciphertext) = try EstablishmentEnvelope.unframeHpkeBlob(envelope)
		let plaintext: Data
		do {
			plaintext = try pqProvider.hpkeOpen(
				enc: enc, secretKey: pqInitSecretKey, info: clientID,
				aad: EstablishmentEnvelope.envelopeFramingAAD(),
				ciphertext: ciphertext)
		} catch {
			throw TwoMLSError.decryptionFailed
		}
		return try EstablishmentEnvelope.decodePlaintext(plaintext)
	}
}
