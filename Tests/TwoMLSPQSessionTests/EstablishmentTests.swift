import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import SecretBytes
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

@Suite struct EstablishmentTests {
	@available(iOS 26, macOS 26, *)
	@Test func bobEstablishedImmediatelyAliceOnlyAfterFirstFrame() throws {
		let (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		#expect(!alice.isEstablished)
		#expect(bob.isEstablished)

		let (aliceAfter, bobAfter) = try SessionTestSupport.establishedAndExchanged()
		#expect(aliceAfter.isEstablished)
		#expect(bobAfter.isEstablished)
	}

	/// Both init secrets are join-only: the responder's are spent joining
	/// Group_A and founding Group_B (both done inside `receive`), and the
	/// initiator's PQ one is spent founding Group_A's PQ half — all three
	/// are gone immediately. The initiator's classical one survives until
	/// she joins Group_B herself (the acceptor's first frame), at which
	/// point it too is cleared. An ESTABLISHED session archive never carries
	/// them; only a pre-establishment initiator archive carries its still-
	/// live classical one (this test restores only established bob).
	@available(iOS 26, macOS 26, *)
	@Test func initSecretsAreClearedOnceSpentAndNeverSurviveRestore() throws {
		let (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		#expect(bob.identity.classicalInitSecretKey == nil)
		#expect(bob.identity.pqInitSecretKey == nil)
		#expect(alice.identity.pqInitSecretKey == nil)
		#expect(
			alice.identity.classicalInitSecretKey != nil,
			"the initiator still needs it to join Group_B")

		let (aliceAfter, bobAfter) = try SessionTestSupport.establishedAndExchanged()
		#expect(aliceAfter.identity.classicalInitSecretKey == nil)
		#expect(aliceAfter.identity.pqInitSecretKey == nil)
		#expect(bobAfter.identity.classicalInitSecretKey == nil)
		#expect(bobAfter.identity.pqInitSecretKey == nil)

		var bobAfterMutable = bobAfter
		let checkpoint = try bobAfterMutable.stateUpdate(kind: .checkpoint).archive
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.identity.classicalInitSecretKey == nil)
		#expect(restored.identity.pqInitSecretKey == nil)
	}

	/// Group_A is a full pair: both halves carry a consistent `APQInfo`
	/// (the identity fields the combiner's own `verifyPair` compares, checked
	/// here via the public `APQInfo` fields directly — `verifyPair` itself
	/// already ran, and threw nothing, inside `joinFull`/`CombinerGroup.join`).
	@available(iOS 26, macOS 26, *)
	@Test func groupAFullPairAPQInfoIsConsistent() throws {
		let (_, bob, _, _, _, _) = try SessionTestSupport.established()
		let groupA = try #require(bob.recvGroup)
		let pq = try #require(groupA.pq)

		let classicalInfo = try #require(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: groupA.classical.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))
		let pqInfo = try #require(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: pq.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))

		#expect(classicalInfo.tSessionGroupID == pqInfo.tSessionGroupID)
		#expect(classicalInfo.pqSessionGroupID == pqInfo.pqSessionGroupID)
		#expect(classicalInfo.mode == pqInfo.mode)
		#expect(classicalInfo.tCipherSuite == pqInfo.tCipherSuite)
		#expect(classicalInfo.pqCipherSuite == pqInfo.pqCipherSuite)
		#expect(classicalInfo.tSessionGroupID == groupA.classical.context.groupID)
		#expect(classicalInfo.pqSessionGroupID == pq.context.groupID)
		#expect(classicalInfo.tEpoch == groupA.classical.context.epoch)
		#expect(pqInfo.pqEpoch == pq.context.epoch)

		#expect(groupA.classical.tree.nonBlankLeaves().count == 2)
		#expect(pq.tree.nonBlankLeaves().count == 2)
	}

	/// Group_B is classical-only: `pq == nil` on both the founder's (Bob) send
	/// group and the joiner's (Alice) receive group, and both rosters are 2.
	@available(iOS 26, macOS 26, *)
	@Test func groupBIsClassicalOnlyOnBothSides() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let bobGroupB = try #require(bob.sendGroup)
		let aliceGroupB = try #require(alice.recvGroup)

		#expect(bobGroupB.pq == nil)
		#expect(aliceGroupB.pq == nil)
		#expect(bobGroupB.classical.tree.nonBlankLeaves().count == 2)
		#expect(aliceGroupB.classical.tree.nonBlankLeaves().count == 2)
	}

	/// Epochs converge on both directional pairs: Bob's copy of Group_A
	/// matches Alice's, and (once Alice has joined it) Alice's copy of Group_B
	/// matches Bob's.
	@available(iOS 26, macOS 26, *)
	@Test func epochsConverge() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceGroupA = try #require(alice.sendGroup)
		let bobGroupA = try #require(bob.recvGroup)
		#expect(aliceGroupA.classical.context == bobGroupA.classical.context)
		#expect(aliceGroupA.pq?.context == bobGroupA.pq?.context)

		let bobGroupB = try #require(bob.sendGroup)
		let aliceGroupB = try #require(alice.recvGroup)
		#expect(bobGroupB.classical.context == aliceGroupB.classical.context)
	}

	/// The load-bearing cross-party binding proof: join Group_B's classical
	/// Welcome via the profile's `Group.joining` with an EMPTY PSK resolver —
	/// it must throw `unresolvedPreSharedKey`, proving Group_B's creation
	/// commit referenced the cross-party PSK the joiner is required to
	/// resolve. Mirrors the combiner's own `establishBindsFounderSideApqPsk`.
	/// Run inside `.uint32` component-id width so the `PreSharedKeyID` decodes
	/// at the deployed width — otherwise the join fails earlier, on a wire/parse
	/// error, not the asserted `unresolvedPreSharedKey`.
	@available(iOS 26, macOS 26, *)
	@Test func groupBWelcomeBindsCrossPartyPSK() throws {
		let (_, _, aliceIdentity, _, _, welcomeB) = try SessionTestSupport.established()
		let (classicalWelcomeBytes, pqWelcomeBytes) = try Frames.decodeAPQWelcome(welcomeB)
		#expect(pqWelcomeBytes == Data())
		let welcome = try EstablishmentMessages.decodeWelcome(classicalWelcomeBytes)

		// `PendingJoin` is `~Copyable`, so `XCTAssertThrowsError`'s `Copyable`-bound
		// generic cannot wrap this call — a plain do/catch instead.
		try withDeployedWireConventions {
			do {
				_ = try MLS.RFC9420.Group.joining(
					SessionTestSupport.classicalProvider, welcome: welcome,
					credentials: aliceIdentity.classicalJoinCredentials,
					psk: { _ in nil })
				Issue.record("expected unresolvedPreSharedKey")
			} catch let error as MLS.RFC9420.GroupError {
				#expect(error == .unresolvedPreSharedKey)
			}
		}

		// minor-3: pin the session layer's own cross-party PSK component id —
		// distinct from the combiner's `apq_psk` component (`0xFF01`).
		#expect(TwoMLSSession.crossPartyComponentID.rawValue == 0xFF02)
	}

	/// Once Alice has joined Group_B, a frame carrying a DIFFERENT
	/// welcome staple — a fresh, unrelated pair's Group_B welcome — must be
	/// rejected outright, not silently re-joined. The idempotent early-return
	/// in `joinGroupBIfNeeded` only covers a byte-identical restaple of the
	/// SAME welcome.
	@available(iOS 26, macOS 26, *)
	@Test func processIncomingRejectsADifferentWelcomeOnceEstablished() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()

		let (otherAlice, otherBobSession, _, _, _, _) =
			try SessionTestSupport
			.established(alice: "alice-intruder", bob: "bob-intruder")
		var otherBob = otherBobSession
		_ = try otherBob.prepareToEncrypt()
		let intruderFrame = try otherBob.encrypt(Data("intruder".utf8)).frame

		// `intruderFrame` is header-sealed under a key from a totally
		// unrelated pair — alice's `openOrRaw` cannot open it (none of her
		// window keys match) and falls back to passing the still-sealed
		// bytes straight through, so the sealed path fails at the frame
		// decode (a near-uniform random leading byte) rather than the
		// welcome-digest check this test originally pinned.
		#expect(throws: (any Error).self) {
			try alice.processIncomingDecrypted(intruderFrame)
		}

		// Restore the deterministic check via the documented `openOrRaw`
		// pass-through: `otherAlice` (the intruder pair's own recipient) can
		// open `intruderFrame` with her window key, recovering the plaintext
		// message frame with the intruder's `APQWelcome_B` staple. Feeding
		// that ALREADY-OPENED frame to `alice.processIncoming` exercises the
		// same `openOrRaw` fallback (it fails AEAD under every one of
		// alice's window keys and passes through raw), but this time the raw
		// bytes decode as a genuine frame, so processing reaches
		// `joinGroupBIfNeeded` and rejects the foreign welcome digest
		// deterministically.
		let raw = try #require(otherAlice.tryOpen(intruderFrame))
		#expect(throws: TwoMLSError.unexpectedWelcome) {
			try alice.processIncomingDecrypted(raw)
		}
	}

	/// minor-2: a staple welcome not already joined but carrying a non-empty
	/// pq slot — a full (Group_A-shaped) welcome — is a protocol state
	/// `processIncoming` cannot process; only the explicit `receive()` entry
	/// point joins those. The app section is a real sealed `privateMessage`
	/// (borrowed from an actual frame) so the check under test is actually
	/// reached, past the earlier `Message` decode.
	@available(iOS 26, macOS 26, *)
	@Test func processIncomingRejectsFullWelcomeStaple() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let realFrame = try bob.encrypt(Data("payload".utf8)).frame
		// Opened via `alice` (the recipient).
		let (_, _, appSection) = try Frames.decodeMessageFrame(alice.openOrRaw(realFrame))

		let fullWelcomeStaple = Frames.encodeAPQWelcome(
			t: Data("fake-t".utf8), pq: Data("fake-pq".utf8))
		let proposalSection = Frames.encodeProposalSection(
			proposing: Data("client".utf8), message: Data("dummy".utf8))
		let forgedFrame = Frames.encodeMessageFrame(
			staple: fullWelcomeStaple, proposal: proposalSection, app: appSection)

		#expect(throws: TwoMLSError.fullEstablishmentStapleUnsupported) {
			try alice.processIncomingDecrypted(forgedFrame)
		}
	}

	/// A `0x01` welcome whose halves are bare (unwrapped) `Welcome` structs —
	/// the framing no deployed peer emits — is refused, not silently accepted
	/// alongside the wrapped form. Covers both `receive()` (Group_A, via
	/// `Invitation.receive`) and the Group_B staple join: each rejection
	/// consumes no state, so re-feeding the genuine frame afterward still
	/// joins.
	@available(iOS 26, macOS 26, *)
	@Test func bareWelcomeHalvesAreRefused() throws {
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		guard let theirCombinerKP = invitation.combinerKeyPackage else {
			Issue.record("expected a combiner key package")
			return
		}
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)

		let (tBytes, pqBytes) = try Frames.decodeAPQWelcome(initiated.welcome)
		let bareWelcomeA = Frames.encodeAPQWelcome(
			t: try EstablishmentMessages.decodeWelcome(tBytes).mlsEncoded(),
			pq: try EstablishmentMessages.decodeWelcome(pqBytes).mlsEncoded())

		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		#expect(throws: TwoMLSError.malformedEstablishmentMessage) {
			try invitation.receive(
				welcome: bareWelcomeA,
				theirClassicalKeyPackage: initiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				spawnToken: spawnToken)
		}

		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken)
		#expect(received.session.isEstablished)

		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let genuineFrame = try bob.encrypt(Data("genuine".utf8)).frame
		let (staple, _, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(genuineFrame))
		let (classicalWelcomeBytes, _) = try Frames.decodeAPQWelcome(staple)
		let bareClassicalWelcome = try EstablishmentMessages.decodeWelcome(
			classicalWelcomeBytes
		)
		.mlsEncoded()
		let bareStaple = Frames.encodeAPQWelcome(t: bareClassicalWelcome, pq: Data())
		let proposalSection = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: Data("dummy-upd".utf8))
		let forgedFrame = Frames.encodeMessageFrame(
			staple: bareStaple, proposal: proposalSection, app: appSection)

		#expect(throws: TwoMLSError.malformedEstablishmentMessage) {
			try alice.processIncomingDecrypted(forgedFrame)
		}
		#expect(!alice.isEstablished)
		#expect(alice.recvGroup == nil)

		_ = try alice.processIncomingDecrypted(genuineFrame)
		#expect(alice.isEstablished)
	}

	/// A well-formed `MLSMessage` of the wrong case (a `KeyPackage`) in a
	/// welcome slot is refused with the same precise error as a bare struct —
	/// at both `receive()` (Group_A) and the Group_B staple join.
	@available(iOS 26, macOS 26, *)
	@Test func welcomeSlotRejectsANonWelcomeMessage() throws {
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		guard let theirCombinerKP = invitation.combinerKeyPackage else {
			Issue.record("expected a combiner key package")
			return
		}
		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)

		let (_, pqBytes) = try Frames.decodeAPQWelcome(initiated.welcome)
		let keyPackageInWelcomeSlot = try EstablishmentMessages.encodeKeyPackage(
			initiated.session.identity.keyPackage.classical)
		let wrongCaseWelcomeA = Frames.encodeAPQWelcome(
			t: keyPackageInWelcomeSlot, pq: pqBytes)

		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		#expect(throws: TwoMLSError.malformedEstablishmentMessage) {
			try invitation.receive(
				welcome: wrongCaseWelcomeA,
				theirClassicalKeyPackage: initiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				spawnToken: spawnToken)
		}

		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let genuineFrame = try bob.encrypt(Data("genuine".utf8)).frame
		let (_, _, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(genuineFrame))
		let wrongCaseStaple = Frames.encodeAPQWelcome(
			t: try EstablishmentMessages.encodeKeyPackage(
				initiated.session.identity.keyPackage.classical), pq: Data())
		let proposalSection = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: Data("dummy-upd".utf8))
		let forgedFrame = Frames.encodeMessageFrame(
			staple: wrongCaseStaple, proposal: proposalSection, app: appSection)

		#expect(throws: TwoMLSError.malformedEstablishmentMessage) {
			try alice.processIncomingDecrypted(forgedFrame)
		}
	}

	// MARK: - Group_B join gates: cross-party PSK + creator pin, parse-then-export

	/// A forged Group_B welcome: a classical-only creation commit under
	/// `creatorName`'s fresh identity (a solid `TwoMLSIdentity`, so the commit
	/// and Welcome are genuinely signed — Basic credentials carry no proof,
	/// which is the point), deferred-shape `APQInfo`, `Add(joinerKP)` — and,
	/// unless `crossPSK` is supplied, NO cross-party PSK. Hand-rolled rather
	/// than `APQGroup.establishClassicalOnly`, which always binds the PSK.
	@available(iOS 26, macOS 26, *)
	private func forgedGroupBWelcome(
		creatorName: String,
		adding joinerKP: MLS.RFC9420.KeyPackage,
		crossPSK: MLS.Combiner.ExportedPsk? = nil
	) throws -> Data {
		let creator = try SessionTestSupport.identity(creatorName)
		let provider = SessionTestSupport.classicalProvider
		return try withDeployedWireConventions {
			let info = MLS.Combiner.APQInfo(
				tSessionGroupID: provider.randomBytes(provider.hashSize),
				pqSessionGroupID: provider.randomBytes(provider.hashSize),
				mode: 0,
				tCipherSuite: provider.cipherSuite,
				pqCipherSuite: SessionTestSupport.pqProvider.cipherSuite,
				tEpoch: 1,
				pqEpoch: epochUnbound)
			let infoExtension = try info.asExtension(
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType)

			var pskStore = MLS.Combiner.PSKStore()
			if let crossPSK { pskStore.register(crossPSK) }

			let epoch0 = try MLS.RFC9420.Group.create(
				provider, groupID: provider.randomBytes(provider.hashSize),
				leafNode: creator.keyPackage.classical.leafNode,
				leafSecretKey: creator.classicalLeafSecretKey,
				extensions: [infoExtension],
				epochSecret: SecretBytes(randomByteCount: provider.hashSize))
			var proposals: [MLS.RFC9420.ProposalOrRef] = [.proposal(.add(joinerKP))]
			if let crossPSK {
				proposals.append(
					.proposal(
						crossPSK.proposal(
							nonce: provider.randomBytes(
								provider.hashSize))))
			}
			try TwoPartyRules.validateCreationProposals(proposals)
			let transition = try epoch0.committing(
				provider, proposals: proposals, signingKey: creator.signingKey,
				randomness: try .generate(provider), psk: pskStore.resolver())
			let sent = transition.takeOutput()
			guard let welcome = sent.welcome else {
				throw MLS.Combiner.Error.missingWelcome
			}
			return Frames.encodeAPQWelcome(
				t: try EstablishmentMessages.encodeWelcome(welcome), pq: Data())
		}
	}

	/// Frame `staple` as a `0x03` message frame with a real sealed (borrowed)
	/// app section — the app must decode as a `.privateMessage` before
	/// `handleStaple` runs, so a rejected welcome staple still reaches the
	/// code under test.
	private func forgedWelcomeFrame(staple: Data, app: Data) -> Data {
		let proposalSection = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: Data("dummy-upd".utf8))
		return Frames.encodeMessageFrame(
			staple: staple, proposal: proposalSection, app: app)
	}

	/// An unwelcome welcome must be refused, not joined: a forged Group_B
	/// welcome naming NO cross-party PSK — even under the creator id Alice
	/// expects (an impersonation that pre-fix joined and returned the
	/// attacker's plaintext) — is rejected with `.missingCrossPartyPSK`, and
	/// Alice stays unestablished.
	@available(iOS 26, macOS 26, *)
	@Test func groupBJoinRejectsAWelcomeWithoutTheCrossPartyPSK() throws {
		var (alice, bob, aliceIdentity, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let genuineFrame = try bob.encrypt(Data("genuine".utf8)).frame
		// Opened via `alice` (the recipient).
		let (_, _, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(genuineFrame))

		let forgedStaple = try forgedGroupBWelcome(
			creatorName: "bob", adding: aliceIdentity.keyPackage.classical)
		let forgedFrame = forgedWelcomeFrame(staple: forgedStaple, app: appSection)

		#expect(throws: TwoMLSError.missingCrossPartyPSK) {
			try alice.processIncomingDecrypted(forgedFrame)
		}
		#expect(!alice.isEstablished)
		#expect(alice.recvGroup == nil)
		#expect(alice.joinedWelcomeDigest == nil)
	}

	/// The creator-identity half: a forged Group_B welcome carrying a VALID
	/// cross-party PSK (Alice's own, exported off a copy of her Group_A) but
	/// created under a different identity ("mallory", not the "bob" Alice is
	/// established against) passes the PSK gate and is caught by the creator
	/// pin. A `.bare`-mode creator mismatch is no longer
	/// distinguishable from an un-approved born-dedicated welcome, so this
	/// now throws `.establishmentEnvelopeRequired` rather than
	/// `.remoteIdentityMismatch` (which stays reserved for `receive`'s own
	/// KP≡creator binding check). This is the only route to the creator
	/// gate: a foreign welcome without the PSK never gets here.
	@available(iOS 26, macOS 26, *)
	@Test func groupBJoinRejectsAWelcomeFromAnUnexpectedCreator() throws {
		var (alice, bob, aliceIdentity, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let genuineFrame = try bob.encrypt(Data("genuine".utf8)).frame
		// Opened via `alice` (the recipient).
		let (_, _, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(genuineFrame))

		var groupACopy = try #require(alice.sendGroup)
		let crossPSK = try MLS.Combiner.ExportedPsk.export(
			from: &groupACopy.classical, SessionTestSupport.classicalProvider,
			componentID: TwoMLSSession.crossPartyComponentID)
		let forgedStaple = try forgedGroupBWelcome(
			creatorName: "mallory", adding: aliceIdentity.keyPackage.classical,
			crossPSK: crossPSK)
		let forgedFrame = forgedWelcomeFrame(staple: forgedStaple, app: appSection)

		#expect(throws: TwoMLSError.establishmentEnvelopeRequired) {
			try alice.processIncomingDecrypted(forgedFrame)
		}
		#expect(!alice.isEstablished)
		#expect(alice.recvGroup == nil)
		#expect(alice.joinedWelcomeDigest == nil)
	}

	/// One malformed — or well-formed-but-foreign — welcome staple must not
	/// permanently wedge the initiator: the one-shot `0xFF02` exporter leaf is
	/// consumed only after the Welcome parses, all writes land on locals, and
	/// a failed join writes nothing back — so Bob's genuine first frame still
	/// joins afterward.
	@available(iOS 26, macOS 26, *)
	@Test func malformedWelcomeStapleLeavesTheGenuineOneJoinable() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let genuineFrame = try bob.encrypt(Data("genuine".utf8)).frame
		// Opened via `alice` (the recipient).
		let (_, _, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(genuineFrame))

		// (a) A `0x01` welcome staple whose classical `t` slot is garbage — the
		// Welcome fails to parse, before any exporter leaf is consumed.
		let garbageStaple = Frames.encodeAPQWelcome(
			t: Data("not-a-welcome".utf8), pq: Data())
		#expect(throws: (any Error).self) {
			try alice.processIncomingDecrypted(
				forgedWelcomeFrame(staple: garbageStaple, app: appSection))
		}
		#expect(alice.sendCrossPSKLedger.isEmpty)
		#expect(!alice.isEstablished)

		// (b) A well-formed but FOREIGN welcome — another pair's real Group_B
		// welcome. It dies inside `Welcome.decryptGroupSecrets` (a
		// `GroupError`, not a `TwoMLSError` — asserted accordingly), again
		// without touching Alice's exporter leaf.
		var (otherAlice, otherBob, _, _, _, otherWelcomeB) =
			try SessionTestSupport.established(
				alice: "alice-other", bob: "bob-other")
		_ = try otherBob.prepareToEncrypt()
		let otherGenuineFrame = try otherBob.encrypt(Data("other".utf8)).frame
		// Opened via `otherAlice` (the recipient in that OTHER pair).
		let (_, _, otherAppSection) = try Frames.decodeMessageFrame(
			otherAlice.openOrRaw(otherGenuineFrame))
		#expect(throws: MLS.RFC9420.GroupError.noMatchingWelcomeSecret) {
			try alice.processIncomingDecrypted(
				forgedWelcomeFrame(staple: otherWelcomeB, app: otherAppSection))
		}
		#expect(alice.sendCrossPSKLedger.isEmpty)
		#expect(!alice.isEstablished)

		// Bob's genuine first frame now joins cleanly — no wedge.
		_ = try bob.prepareToEncrypt()
		let realFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(realFrame)
		#expect(decrypted.applicationMessage == Data("bob-hello".utf8))
		#expect(alice.isEstablished)
	}

	// MARK: - AS establishment identity binding

	/// `receive` must reject a caller-supplied `theirClassicalKeyPackage` that
	/// names a third party rather than the creator the Welcome actually joined.
	@available(iOS 26, macOS 26, *)
	@Test func receiveRejectsWrongPeerKeyPackage() throws {
		let alice = try SessionTestSupport.identity("as-alice")
		let bob = try SessionTestSupport.identity("as-bob")
		let carol = try SessionTestSupport.identity("as-carol")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(throws: TwoMLSError.remoteIdentityMismatch) {
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: carol.keyPackage.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	/// The self-id case: Bob's OWN KeyPackage passed as the peer's must be
	/// rejected — the check is equality with the joined creator, not mere
	/// membership (Bob's own id is "known" via `mine`, but is not the creator).
	@available(iOS 26, macOS 26, *)
	@Test func receiveRejectsSelfIdentityKeyPackage() throws {
		let alice = try SessionTestSupport.identity("as-alice-2")
		let bob = try SessionTestSupport.identity("as-bob-2")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(throws: TwoMLSError.remoteIdentityMismatch) {
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: bob.keyPackage.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	/// `initiate` must reject a peer whose classical and PQ `KeyPackage` halves
	/// present different identities.
	@available(iOS 26, macOS 26, *)
	@Test func initiateRejectsMismatchedPeerHalves() throws {
		let alice = try SessionTestSupport.identity("as-alice-3")
		let bob = try SessionTestSupport.identity("as-bob-3")
		let carol = try SessionTestSupport.identity("as-carol-3")
		let mismatched = CombinerKeyPackage(
			classical: bob.keyPackage.classical, pq: carol.keyPackage.pq)
		#expect(throws: TwoMLSError.remoteIdentityMismatch) {
			try TwoMLSSession.initiate(
				identity: alice, their: mismatched,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}
}
