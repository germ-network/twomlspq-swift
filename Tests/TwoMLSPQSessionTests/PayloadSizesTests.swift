import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// Payload-size report — the Swift analogue of `two-mls-pq`'s
/// `benches/sizes.rs` (which prints a table and exits). Prints the on-wire
/// size of every frame kind for a fixed 43-byte payload, so the Swift
/// engine's sizes can be read beside the Rust reference and the table the
/// book documents in `wire-format.md` ("Message-frame anatomy").
///
///   swift test --filter PayloadSizesTests
///
/// The recorded table lives in `docs/protocol/message-sizes.md`.
///
/// Not a timing benchmark: it prints and asserts only structural invariants
/// (a frame's sections plus framing sum to its on-wire length; the rotation
/// commit folds its peer proposal by reference, never by value), so it is
/// safe to run in CI.
@Suite struct PayloadSizesTests {
	/// The Rust bench's own payload — 43 bytes, matching `wire-format.md`'s
	/// documented table.
	private static let payload = Data(
		"the quick brown fox jumps over the lazy dog".utf8)

	/// The documented rotation-frame split from `wire-format.md`
	/// (`CURVE25519_CHACHA`, awslc, 43-byte payload) — printed for
	/// comparison: the reference bench stamps ~30-byte opaque client ids, so
	/// credential-bearing sections track the id length and the engine's own
	/// encoding, and only the framing offset (the length prefix) is asserted.
	///
	private enum Documented {
		static let total = 1341
		static let staple = 651
		static let proposal = 395
		static let app = 254
		static let framing = 41
	}

	/// A Rust-shaped opaque client id (~30 bytes), so credential-bearing
	/// sections land at a comparable size to the documented table.
	private static func clientID(_ name: String, _ n: Int) -> Data {
		var id = Data("size-client-\(name)-\(n)".utf8)
		if id.count < 30 { id.append(Data(repeating: 0x0A, count: 30 - id.count)) }
		return id
	}

	@available(iOS 26, macOS 26, *)
	private static func principal(_ name: String, _ n: Int) throws -> Principal {
		try Principal.generate(
			clientID: clientID(name, n),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	@available(iOS 26, macOS 26, *)
	@Test func payloadSizeReport() throws {
		let payload = Self.payload

		// MARK: Establishment (§A.1) — cold principals, Alice initiates to
		// Bob's published combiner KP, Bob's invitation receives.
		let alicePrincipal = try Self.principal("alice", 1)
		let bobPrincipal = try Self.principal("bob", 0)
		var (bobInvitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let bobKP = try #require(bobInvitation.combinerKeyPackage)

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: bobKP)
		var alice = initiated.session
		let envelopeA = try alice.pendingOutbound()
		// Unseal the envelope while the invitation is still live (decrypt-only,
		// non-consuming) to read its inner welcome / return-KP split, and split
		// Alice's own APQ welcome into its classical (`t`) and PQ halves.
		let welcomeA = try #require(alice.initialWelcome())
		let openedEnvelope = try bobInvitation.openInitial(envelopeA)
		let welcomeAT = try Frames.decodeAPQWelcome(welcomeA).t
		let welcomeAPQ = try Frames.decodeAPQWelcome(welcomeA).pq

		// §A.1 pre-establishment app frames: the initiator's pre-join send,
		// bare shape (welcome + classical return-KP sections) vs the
		// self-sufficient payload shape (`setInitialAppPayload` replaces the
		// bare sections with one opaque blob).
		_ = try alice.prepareToEncrypt()
		let preEstBare = try alice.encrypt(payload).frame
		let identityPayload =
			Data("identity-envelope:".utf8) + (try #require(alice.initialWelcome()))
		_ = try alice.setInitialAppPayload(identityPayload)
		_ = try alice.prepareToEncrypt()
		let preEstPayload = try alice.encrypt(payload).frame

		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let received = try bobInvitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.identity.keyPackage.classical,
			bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		var bob = received.session
		// Bob's sealed `0x01` birth welcome (the standalone deliverable; the
		// same bytes ride his first `0x03` frame's staple — Rust's
		// `pending_outbound`). Alice joins on it.
		let welcomeB = try #require(try bob.standaloneWelcome())
		_ = try alice.processIncoming(welcomeB)

		// MARK: Steady-state `0x03` frames.
		// No-commit round: routine `Upd(self)` + app.
		_ = try alice.prepareToEncrypt()
		let noCommit = try alice.encrypt(payload).frame
		_ = try bob.processIncomingDecrypted(noCommit)

		// Folding commit: Bob proposes, Alice queues + folds — its staple is
		// the bare `0x00` fold commit.
		_ = try bob.prepareToEncrypt()
		let bobProposal = try bob.encrypt(Data("proposal".utf8)).frame
		let seen = try alice.processIncomingDecrypted(bobProposal)
		_ = try alice.queueProposal(digest: seen.queuedProposal.digest)
		let foldPrepare = try alice.prepareToEncrypt()
		#expect(foldPrepare.didCommit)
		let folding = try alice.encrypt(payload).frame
		_ = try bob.processIncomingDecrypted(folding)

		// Rotation: Alice proposes a successor; the staple is the classical
		// rotation commit (`0x00`), the proposal section its by-value
		// `Upd(sender)`.
		_ = try alice.prepareToEncrypt(rotating: Self.clientID("alice", 2))
		let rotation = try alice.encrypt(payload).frame

		let (rotStaple, rotProposal, rotApp) = try Self.sections(rotation, openedBy: bob)
		let rotFraming = rotation.count - rotStaple.count - rotProposal.count - rotApp.count
		let (rotBVCount, rotBVBytes) = try Self.byValueProposalBytes(rotStaple)
		#expect(
			rotBVBytes < 200,
			"rotation commit inlined a leaf-sized proposal (\(rotBVBytes) B) — the fold must be by reference"
		)

		// MARK: §A.3 PQ bootstrap side-band.
		var (bootAlice, bootBob) = try SessionTestSupport.establishedAndExchanged()
		let bootstrapKP = try bootAlice.pqBootstrapBegin().frame
		let bootstrapWelcome = try bootBob.pqBootstrapRespond(bootstrapKP).frame
		_ = try bootAlice.pqBootstrapJoin(bootstrapWelcome)

		// MARK: §A.4 PQ ratchet — fresh pair, turn on Bob after the A.3 bind.
		var (ratAlice, ratBob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try ratBob.prepareToEncrypt()
		_ = try ratBob.encrypt(Data("ratchet-open".utf8))
		let pqEK = try #require(ratBob.pqPendingOutbound())
		let pqCT = try ratAlice.pqRatchetRespond(pqEK).frame
		_ = try ratBob.pqRatchetBind(pqCT)
		let ratchetPrepare = try ratBob.prepareToEncrypt()
		#expect(ratchetPrepare.didCommit)
		let ratchetBindFrame = try ratBob.encrypt(payload).frame
		let (ratchetStaple, ratchetProposal, ratchetApp) = try Self.sections(
			ratchetBindFrame, openedBy: ratAlice)
		let (ratchetClassical, ratchetPQ) = try Frames.decodeAPQPrivateMessage(
			ratchetStaple)
		#expect(!ratchetProposal.isEmpty && !ratchetApp.isEmpty)

		// MARK: §A.5 PQ re-key side-band.
		var (rekAlice, rekBob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let rekeyUpd = try rekBob.pqRekeyBegin().frame
		let rekeyCommit = try rekAlice.pqRekeyRespond(rekeyUpd).frame
		// The unsealed `0x1D` frame is `[tag][Commit' MLSMessage]`; drop the tag
		// to match the bare `pq` section the bind staple carries.
		let rekeyCommitRaw = rekBob.openOrRaw(rekeyCommit).count - 1

		// MARK: `0x0B` born-dedicated establishment handoff.
		let dedicated = try SessionTestSupport.establishedDedicated()
		var dedicatedBob = dedicated.bob
		_ = try dedicatedBob.installEstablishmentEnvelope(
			Data("fake-signed-handoff".utf8))
		let handoff = dedicatedBob.currentStaple
		#expect(handoff.first == Frames.establishmentHandoffTag)

		// MARK: - Report

		print(
			"""

			=== TwoMLSPQ (Swift) ciphertext sizes — curve25519chaCha + ML-KEM-768, SwiftCrypto ===
			session profile              : \(alice.profile) (default — legacy/deployed-compatible)
			client id length             : \(Self.clientID("alice", 1).count) B (opaque)
			payload (plaintext)          : \(payload.count) B
			initial envelope A (§A.1)    : \(envelopeA.count) B
			pre-est app frame (bare)     : \(preEstBare.count) B
			pre-est app frame (payload)  : \(preEstPayload.count) B
			APQ welcome B (0x01, sealed) : \(welcomeB.count) B
			no-commit frame + app (0x03) : \(noCommit.count) B
			folding commit + app (0x03)  : \(folding.count) B
			rotation commit + app (0x03) : \(rotation.count) B
			overhead: no-commit=\(noCommit.count - payload.count) B, folding=\(folding.count - payload.count) B, rotation=\(rotation.count - payload.count) B (over payload)
			(no-commit is Alice's first post-join frame: it re-staples her full APQ welcome until her first commit — wire-format.md "Why re-stapling stays cheap")
			""")

		print(
			"""
			--- rotation frame (0x03) section split ---
			  staple(commit) : \(rotStaple.count) B  (\(rotBVCount) proposal(s) by value = \(rotBVBytes) B; peer Upd folded by reference)
			  proposal(Upd)  : \(rotProposal.count) B  (by value once; peer folds it by reference next round)
			  app            : \(rotApp.count) B
			  framing        : \(rotFraming) B
			--- vs wire-format.md (Rust/awslc, 43 B payload, ~30 B ids) ---
			  total          : \(rotation.count) B (documented \(Documented.total))
			  staple         : \(rotStaple.count) B (documented \(Documented.staple))
			  proposal       : \(rotProposal.count) B (documented \(Documented.proposal))
			  app            : \(rotApp.count) B (documented \(Documented.app))
			  framing        : \(rotFraming) B (documented \(Documented.framing))
			""")

		print(
			"""
			--- §A.3 PQ bootstrap ---
			PQ bootstrap KP (0x13, sealed)     : \(bootstrapKP.count) B
			PQ bootstrap welcome (0x15, sealed): \(bootstrapWelcome.count) B
			--- §A.4 PQ ratchet ---
			PQ EK message (0x17, sealed)  : \(pqEK.count) B
			PQ ct message (0x19, sealed)  : \(pqCT.count) B
			bind frame (0x03 + staple)    : \(ratchetBindFrame.count) B
			  APQPrivateMessage staple    : \(ratchetStaple.count) B
			  classical commit            : \(ratchetClassical.count) B
			  PQ partial-commit (no path) : \(ratchetPQ.count) B
			--- §A.5 PQ re-key ---
			PQ re-key Upd' (0x1B, sealed) : \(rekeyUpd.count) B
			PQ re-key Commit' (0x1D)      : \(rekeyCommit.count) B
			--- per-round PQ commit: full updatePath vs pathless PSK ---
			full PQ updatePath commit (0x1D, unsealed) : \(rekeyCommitRaw) B
			pathless PSK commit (bind pq section)      : \(ratchetPQ.count) B  (\(rekeyCommitRaw / max(ratchetPQ.count, 1))x smaller)
			--- §A.1 born-dedicated handoff ---
			establishment handoff (0x0B)  : \(handoff.count) B
			""")

		print(
			"""
			--- §A.1 envelope A interior (unsealed) ---
			\(Self.envelopeInterior(openedEnvelope))
			--- APQ welcome A halves ---
			  classical t half : \(welcomeAT.count) B  \(try Self.welcomeSummary(welcomeAT))
			  PQ half          : \(welcomeAPQ.count) B  \(try Self.welcomeSummary(welcomeAPQ))
			--- initiator send-group ratchet trees (the welcome's GroupInfo trees) ---
			\(Self.treeSummary("classical", alice.sendGroup?.classical))
			\(Self.treeSummary("pq", alice.sendGroup?.pq))
			""")

		// MARK: - Structural invariants

		// Framing is deterministic for the deployed suite: frame tag (1) +
		// three u32 section prefixes (12) + the plaintext frame-length prefix
		// seal strips on receipt (4, header-encryption.md:195) + header-seal
		// nonce (12) + tag (16). The book's documented 41 predates the
		// length prefix, hence the +4.
		#expect(rotFraming == 45)
		#expect(rotFraming == Documented.framing + 4)
		#expect(
			rotation.count == rotStaple.count + rotProposal.count + rotApp.count
				+ rotFraming)
		#expect(ratchetBindFrame.count > ratchetStaple.count)
		// Each side-band leg is header-sealed on the wire; open it on the
		// recipient to reach its own leading tag.
		#expect(bootBob.openOrRaw(bootstrapKP).first == Frames.pqBootstrapKPTag)
		#expect(bootAlice.openOrRaw(bootstrapWelcome).first == Frames.pqBootstrapWelcomeTag)
		#expect(ratAlice.openOrRaw(pqEK).first == Frames.pqEKTag)
		#expect(ratBob.openOrRaw(pqCT).first == Frames.pqCTTag)
		#expect(rekAlice.openOrRaw(rekeyUpd).first == Frames.pqRekeyUpdTag)
		#expect(rekBob.openOrRaw(rekeyCommit).first == Frames.pqRekeyCommitTag)
		#expect(!ratchetApp.isEmpty)
	}

	/// The envelope's inner section sizes (bare shape: a welcome and a
	/// classical return key package).
	private static func envelopeInterior(_ opened: OpenedInitial) -> String {
		guard case .establishment(let frame) = opened else {
			return "  (not an establishment vector)"
		}
		return """
			  welcome section  : \(frame.welcome?.count ?? 0) B
			  returnKeyPackage : \(frame.returnKeyPackage?.count ?? 0) B
			  appPayload       : \(frame.appPayload?.count ?? 0) B
			  stapledMessage   : \(frame.stapledMessage?.count ?? 0) B
			"""
	}

	/// Per-node sizes of a group's ratchet tree — what the welcome's GroupInfo
	/// `ratchet_tree` extension carries. A blank (nil) node costs 1 byte on the
	/// wire (the `optional` absent tag).
	@available(iOS 26, macOS 26, *)
	private static func treeSummary(_ label: String, _ group: MLS.RFC9420.Group?) -> String {
		guard let group else { return "  \(label): (no group)" }
		do {
			let nodes = try group.tree.nodes
			var parts: [String] = []
			var sum = 0
			for (i, node) in nodes.enumerated() {
				switch node {
				case nil:
					parts.append("\(i)=BLANK")
					sum += 1
				case .leaf(let leaf):
					let encoded = (try? leaf.mlsEncoded().count) ?? 0
					let pub = leaf.encryptionKey.data.count
					parts.append("\(i)=leaf(\(encoded),pub=\(pub))")
					sum += encoded
				case .parent(let parent):
					let encoded = (try? parent.mlsEncoded().count) ?? 0
					parts.append("\(i)=parent(\(encoded))")
					sum += encoded
				}
			}
			return
				"  \(label): nodes=\(nodes.count) sum=\(sum)  \(parts.joined(separator: " . "))"
		} catch {
			return "  \(label): error \(error)"
		}
	}

	/// Structural sizes of an MLSMessage-wrapped `Welcome` — the secret
	/// entries and the (opaque) encrypted GroupInfo, whose ratchet-tree
	/// extension would carry leaves' encryption keys.
	@available(iOS 26, macOS 26, *)
	private static func welcomeSummary(_ mlsMessage: Data) throws -> String {
		try withDeployedWireConventions {
			guard
				case .welcome(let welcome) = try MLS.RFC9420.Message(
					mlsEncoded: mlsMessage)
			else { return "(not a welcome)" }
			let secretCiphertexts = welcome.secrets.map {
				$0.encryptedGroupSecrets.ciphertext.count
			}
			return
				"secrets=\(welcome.secrets.count) secretCT=\(secretCiphertexts) encGroupInfo=\(welcome.encryptedGroupInfo.count)"
		}
	}

	/// Open a sealed `0x03` frame on the receiver and split its three
	/// sections (staple, proposal, app).
	@available(iOS 26, macOS 26, *)
	private static func sections(
		_ frame: Data, openedBy receiver: TwoMLSSession
	) throws -> (staple: Data, proposal: Data, app: Data) {
		try Frames.decodeMessageFrame(receiver.openOrRaw(frame))
	}

	/// The count and total encoded size of the commit's by-value proposals
	/// (its by-reference ones cost ~32 B each and are not counted).
	@available(iOS 26, macOS 26, *)
	private static func byValueProposalBytes(_ commit: Data) throws -> (Int, Int) {
		try withDeployedWireConventions {
			guard
				case .publicMessage(let pub) = try MLS.RFC9420.Message(
					mlsEncoded: commit)
			else { throw TwoMLSError.malformedSideBandMessage }
			guard case .commit(let commitBody) = pub.content.content else {
				throw TwoMLSError.malformedSideBandMessage
			}
			let sizes = try commitBody.proposals.compactMap { proposalOrRef -> Int? in
				guard case .proposal(let proposal) = proposalOrRef else {
					return nil
				}
				return try proposal.mlsEncoded().count
			}
			return (sizes.count, sizes.reduce(0, +))
		}
	}
}
