import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Invitation (slice 8b)
//
// The self-contained receiving capability (book concepts.md's
// `TwoMlsPqInvitation`): one published combiner key package's private
// material, the captured signing identity, and the four tables that let one
// invitation service many welcomes with no live client. Return-based, no
// sink (book concepts.md's push-based persistence, adapted here the same
// way `TwoMLSSession`'s own state-advancing methods are): `receive` mutates
// `self` and returns the resulting session alongside the updated archive
// for the app to seal and save.

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
	/// join/found work to the identity-based `TwoMLSSession.receive`.
	/// Validation order — everything before any table insert or consume, so
	/// a rejected welcome claims nothing (book session-lifecycle.md):
	/// 1. `bootstrapKPCommitment` must be exactly 32 bytes.
	/// 2. parse `theirClassicalKeyPackage` for the remote's client id.
	/// 3. an already-processed welcome digest → `.duplicateWelcome`.
	/// 4. a single-use invitation whose KP is already spent →
	///    `.invitationSpent`.
	/// 5. an already-consumed remote → `.duplicateWelcome`.
	/// 6. delegate to `TwoMLSSession.receive` (enforces the welcome-creator
	///    ≡ KP identity binding, joins Group_A, founds Group_B).
	/// 7. commit: insert all four tables, single-use consume, bump
	///    `stateSeq`, return the spawned session plus the updated archive.
	public mutating func receive(
		welcome: Data,
		theirClassicalKeyPackage: MLS.RFC9420.KeyPackage,
		bootstrapKPCommitment: Data,
		spawnToken: Data
	) throws -> (session: TwoMLSSession, archive: SecretArchive) {
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
			codepoints: codepoints)
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
		return (session: result.session, archive: archive)
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
	/// the frame arrives tagged (the side-band wire shape) or already
	/// untagged (the same preimage `bootstrapKPCommitment()` hashes).
	public func bootstrapKPGroupID(kpFrame: Data) -> Data? {
		let untagged =
			kpFrame.first == Frames.pqBootstrapKPTag
			? Data(kpFrame.dropFirst()) : kpFrame
		guard let digest = try? classicalProvider.hash(untagged) else { return nil }
		return bootstrapRouting[digest]
	}
}
