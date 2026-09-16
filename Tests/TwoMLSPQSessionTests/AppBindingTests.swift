import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// The optional `AppBinding` GroupContext extension (`0xF0A2`, book
/// group-rules.md rule 8): written once into both classical halves at
/// creation, mirrored onto Group_B by the acceptor, verified exactly and
/// symmetrically at every join, and never carried on a PQ half. Mirrors the
/// Rust reference's `two-mls-pq/src/session/tests.rs` AppBinding block
/// (`test_app_binding_survives_archive_restore`,
/// `test_return_welcome_without_app_binding_rejected`,
/// `test_initiate_rejects_empty_app_binding`,
/// `test_welcome_with_pq_half_binding_rejected`), ported to this module's own
/// identity-based establishment primitives.
@available(iOS 26, macOS 26, *)
final class AppBindingTests: XCTestCase {
	private static let binding = Data("relationship-digest".utf8)

	// MARK: - Codec

	/// `AppBinding`'s wire shape is `opaque<V>(data)` — a varint length prefix
	/// then the bytes — NOT the raw digest with no length prefix. For a
	/// length under 64 the varint is one byte (top two bits `00`), so a
	/// 3-byte payload round-trips as exactly 4 bytes, byte-matching the Rust
	/// reference's `AppBinding { data: Vec<u8> }` (`mls_rs_codec::byte_vec`
	/// uses the same varint-length-prefixed encoding).
	func testAppBindingWireShapeIsLengthPrefixedNotRawDigest() throws {
		let encoded = try AppBinding(data: Data([1, 2, 3])).mlsEncoded()
		XCTAssertEqual(encoded, Data([3, 1, 2, 3]))

		var reader = MLS.Reader(encoded)
		let decoded = try AppBinding(from: &reader)
		try reader.finish()
		XCTAssertEqual(decoded.data, Data([1, 2, 3]))
	}

	/// `AppBinding.read`: `nil` when absent, the bytes when present, and
	/// NEVER `nil` for a corrupt extension — trailing bytes throw
	/// `.appBindingMismatch` rather than silently reading back as "unbound"
	/// (mirrors `APQInfo.read`'s same rule).
	func testAppBindingReadIsNilWhenAbsentAndNeverNilWhenCorrupt() throws {
		let emptyContext = MLS.RFC9420.GroupContext(
			version: .mls10,
			cipherSuite: SessionTestSupport.classicalProvider.cipherSuite,
			groupID: Data([1]), epoch: 0, treeHash: Data(),
			confirmedTranscriptHash: Data(),
			extensions: [])
		XCTAssertNil(try AppBinding.read(fromExtensionsOf: emptyContext))

		let goodExtension = try AppBinding(data: Self.binding).asExtension()
		var boundContext = emptyContext
		boundContext.extensions = [goodExtension]
		XCTAssertEqual(try AppBinding.read(fromExtensionsOf: boundContext), Self.binding)

		// Trailing bytes after the declared opaque length: undecodable, not absent.
		var truncatedExtension = goodExtension
		truncatedExtension.data.append(0xFF)
		var corruptContext = emptyContext
		corruptContext.extensions = [truncatedExtension]
		XCTAssertThrowsError(try AppBinding.read(fromExtensionsOf: corruptContext)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}

		// A duplicate `0xF0A2` extension is not a legitimate shape either.
		var duplicateContext = emptyContext
		duplicateContext.extensions = [goodExtension, goodExtension]
		XCTAssertThrowsError(try AppBinding.read(fromExtensionsOf: duplicateContext)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}
	}

	// MARK: - `verifyAppBinding` / `verifyPQHalfUnbound`

	func testVerifyAppBindingIsExactAndSymmetric() throws {
		let solo = try SessionTestSupport.identity("solo-verify")
		let provider = SessionTestSupport.classicalProvider

		let boundGroup = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: solo.keyPackage.classical.leafNode,
			leafSecretKey: solo.classicalLeafSecretKey,
			extensions: [try AppBinding(data: Self.binding).asExtension()],
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))
		XCTAssertNoThrow(try verifyAppBinding(boundGroup, expected: Self.binding))
		XCTAssertThrowsError(try verifyAppBinding(boundGroup, expected: Data("other".utf8)))
		{
			XCTAssertEqual($0 as? TwoMLSError, .appBindingMismatch)
		}
		XCTAssertThrowsError(try verifyAppBinding(boundGroup, expected: nil)) {
			XCTAssertEqual($0 as? TwoMLSError, .appBindingMismatch)
		}

		let unboundGroup = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: solo.keyPackage.classical.leafNode,
			leafSecretKey: solo.classicalLeafSecretKey, extensions: [],
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))
		XCTAssertNoThrow(try verifyAppBinding(unboundGroup, expected: nil))
		XCTAssertThrowsError(try verifyAppBinding(unboundGroup, expected: Self.binding)) {
			XCTAssertEqual($0 as? TwoMLSError, .appBindingMismatch)
		}
	}

	/// `verifyPQHalfUnbound` on a hand-built PQ `Group` carrying a smuggled
	/// `0xF0A2` extension — even one equal to a legitimate classical binding —
	/// is rejected; `nil` (a deferred, not-yet-founded PQ half) and a clean PQ
	/// group both pass. Mirrors Rust's `test_welcome_with_pq_half_binding_rejected`
	/// at the level of the primitive it turns on, per the brief: "construct a
	/// Group with a 0xF0A2 on a PQ half."
	func testVerifyPQHalfUnboundRejectsASmuggledBinding() throws {
		let solo = try SessionTestSupport.identity("solo-pq")
		let provider = SessionTestSupport.pqProvider

		let smuggledExtension = try AppBinding(data: Self.binding).asExtension()
		let smuggledGroup = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: solo.keyPackage.pq.leafNode, leafSecretKey: solo.pqLeafSecretKey,
			extensions: [smuggledExtension],
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))
		XCTAssertThrowsError(try verifyPQHalfUnbound(smuggledGroup)) { error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}

		let cleanGroup = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: solo.keyPackage.pq.leafNode, leafSecretKey: solo.pqLeafSecretKey,
			extensions: [], epochSecret: SecretBytes(randomByteCount: provider.hashSize)
		)
		XCTAssertNoThrow(try verifyPQHalfUnbound(cleanGroup))
		XCTAssertNoThrow(try verifyPQHalfUnbound(nil))
	}

	/// End-to-end counterpart of the unit test above: a crafted `APQWelcome`
	/// whose PQ half ALSO carries the `AppBinding` (the classical half
	/// carries the real, matching one) is rejected by the ACTUAL join path
	/// (`TwoMLSSession.receive`) — not just `verifyPQHalfUnbound` in
	/// isolation — proving the guard is wired into production. Mirrors the
	/// Rust reference's `test_welcome_with_pq_half_binding_rejected`,
	/// port-natively: both halves are hand-rolled the same way
	/// `APQGroup.establishClassicalOnly`/`foundPQHalf` do (`Group.create` +
	/// `.committing`, never `CombinerGroup.establish` — its public API only
	/// exposes `classicalExtraExtensions`, with no PQ-half seam a wired
	/// caller could ever misuse this way), so the smuggled shape is one a
	/// wired initiator can never itself produce.
	func testReceiveRejectsAWelcomeWithASmuggledPQHalfBinding() throws {
		let alice = try SessionTestSupport.identity("pq-smuggle-alice")
		let bob = try SessionTestSupport.identity("pq-smuggle-bob")
		let classicalProvider = SessionTestSupport.classicalProvider
		let pqProvider = SessionTestSupport.pqProvider
		let deployedCodepoints = MLS.Combiner.Codepoints.deployed

		try withDeployedWireConventions {
			let tGroupID = classicalProvider.randomBytes(classicalProvider.hashSize)
			let pqGroupID = pqProvider.randomBytes(pqProvider.hashSize)
			let info = MLS.Combiner.APQInfo(
				tSessionGroupID: tGroupID, pqSessionGroupID: pqGroupID, mode: 0,
				tCipherSuite: classicalProvider.cipherSuite,
				pqCipherSuite: pqProvider.cipherSuite, tEpoch: 1, pqEpoch: 1)
			let infoExtension = try info.asExtension(
				type: deployedCodepoints.apqInfoExtensionType)
			let bindingExtension = try AppBinding(data: Self.binding).asExtension()
			let attestationProposal = MLS.RFC9420.ProposalOrRef.proposal(
				try MLS.Combiner.ApqInfoUpdate(tEpoch: 1, pqEpoch: 1).proposal(
					componentID: deployedCodepoints.apqComponentID))

			// PQ half FIRST, carrying the smuggled binding too — the crafted
			// shape `CombinerGroup.establish` can never itself produce.
			let pqEpoch0 = try MLS.RFC9420.Group.create(
				pqProvider, groupID: pqGroupID,
				leafNode: alice.keyPackage.pq.leafNode,
				leafSecretKey: alice.pqLeafSecretKey,
				extensions: [infoExtension, bindingExtension],
				epochSecret: SecretBytes(randomByteCount: pqProvider.hashSize))
			let pqTransition = try pqEpoch0.committing(
				pqProvider,
				proposals: [
					.proposal(.add(bob.keyPackage.pq)), attestationProposal,
				],
				signingKey: alice.signingKey, randomness: try .generate(pqProvider),
				psk: { _ in nil })
			let pqAdopted = pqTransition.group
			let pqSent = pqTransition.takeOutput()
			let pqWelcome = try XCTUnwrap(pqSent.welcome)
			var pqGroup = try pqSent.takePending().apply(onto: pqAdopted).group

			let apqPSK = try MLS.Combiner.ExportedPsk.export(
				from: &pqGroup, pqProvider,
				componentID: deployedCodepoints.apqComponentID)
			var pskStore = MLS.Combiner.PSKStore()
			pskStore.register(apqPSK)
			let nonce = classicalProvider.randomBytes(classicalProvider.hashSize)

			// Classical half, carrying the SAME (real, matching) binding.
			let tEpoch0 = try MLS.RFC9420.Group.create(
				classicalProvider, groupID: tGroupID,
				leafNode: alice.keyPackage.classical.leafNode,
				leafSecretKey: alice.classicalLeafSecretKey,
				extensions: [infoExtension, bindingExtension],
				epochSecret: SecretBytes(
					randomByteCount: classicalProvider.hashSize))
			let tTransition = try tEpoch0.committing(
				classicalProvider,
				proposals: [
					.proposal(.add(bob.keyPackage.classical)),
					.proposal(apqPSK.proposal(nonce: nonce)),
					attestationProposal,
				],
				signingKey: alice.signingKey,
				randomness: try .generate(classicalProvider),
				psk: pskStore.resolver())
			let tAdopted = tTransition.group
			let tSent = tTransition.takeOutput()
			let tWelcome = try XCTUnwrap(tSent.welcome)
			_ = try tSent.takePending().apply(onto: tAdopted)

			let crafted = Frames.encodeAPQWelcome(
				t: try tWelcome.mlsEncoded(), pq: try pqWelcome.mlsEncoded())

			// The REAL join path — not just `verifyPQHalfUnbound` in isolation.
			XCTAssertThrowsError(
				try TwoMLSSession.receive(
					identity: bob, welcome: crafted,
					theirClassicalKeyPackage: alice.keyPackage.classical,
					bootstrapKPCommitment: Data(repeating: 0, count: 32),
					classicalProvider: classicalProvider,
					pqProvider: pqProvider,
					expectedAppBinding: Self.binding)
			) { error in
				XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
			}
		}
	}

	// MARK: - Leaf advertisement (port-side defense in depth)

	/// `ensureAppBindingLeafAdvert`/`ensureAppBindingCreatorLeafAdvert` reject
	/// a leaf whose `Capabilities.extensions` lacks `0xF0A2` — a
	/// pre-AppBinding-cut key package — and accept this module's own leaves
	/// (which always advertise it, `TwoMLSIdentity.leafCapabilities`).
	func testLeafAdvertHelpersRejectAnUncapableLeaf() throws {
		let capable = try SessionTestSupport.identity("capable")
		let rogue = try Self.rogueClassicalKeyPackage(clientID: Data("rogue".utf8))

		XCTAssertNoThrow(
			try ensureAppBindingLeafAdvert(
				founder: capable.keyPackage.classical.leafNode,
				peer: capable.keyPackage.classical.leafNode))
		XCTAssertThrowsError(
			try ensureAppBindingLeafAdvert(
				founder: capable.keyPackage.classical.leafNode, peer: rogue.leafNode
			)
		) { XCTAssertEqual($0 as? TwoMLSError, .appBindingLeafUnadvertised) }

		XCTAssertNoThrow(
			try ensureAppBindingCreatorLeafAdvert(capable.keyPackage.classical.leafNode)
		)
		XCTAssertThrowsError(try ensureAppBindingCreatorLeafAdvert(rogue.leafNode)) {
			XCTAssertEqual($0 as? TwoMLSError, .appBindingLeafUnadvertised)
		}
	}

	/// End-to-end: `initiate` with a non-nil `appBinding` refuses to found
	/// Group_A when the peer's classical key package does not advertise
	/// `0xF0A2` — an old-capability key package cannot be added to a
	/// binding-carrying group (item 10 of the brief; swift-mls does not
	/// enforce this the way mls-rs's per-client extension registration does).
	/// The same peer key package is perfectly fine for an UNBOUND session
	/// (`appBinding: nil`), matching Rust's
	/// `test_binding_group_rejects_uncapable_key_package`'s "control" case.
	func testInitiateRejectsAPeerKeyPackageNotAdvertisingAppBindingOnlyWhenBound() throws {
		let alice = try SessionTestSupport.identity("as-alice-rogue-peer")
		let rogueClassical = try Self.rogueClassicalKeyPackage(
			clientID: Data("rogue-bob".utf8))
		let rogueBob = try SessionTestSupport.identity("rogue-bob")
		let theirs = CombinerKeyPackage(
			classical: rogueClassical, pq: rogueBob.keyPackage.pq)

		XCTAssertThrowsError(
			try TwoMLSSession.initiate(
				identity: alice, their: theirs,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider, appBinding: Self.binding)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingLeafUnadvertised)
		}

		// Control: the very same rogue peer key package still founds a bare
		// (unbound) Group_A just fine.
		XCTAssertNoThrow(
			try TwoMLSSession.initiate(
				identity: alice, their: theirs,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider))
	}

	/// Rule 8's tail (group-rules.md:77-78): "Leaves advertise the extension
	/// type, so a binding-carrying group can only ever contain
	/// capability-bearing leaves." The checks above cover creation and join;
	/// this covers the one gap left — a PEER's Update proposal folding in a
	/// REPLACEMENT leaf that lacks `0xF0A2`, on the CLASSICAL update path
	/// (`queueProposal`/`validateOfferedUpdate`). Hand-forges the Update the
	/// way `EstablishmentTests.forgedGroupBWelcome` hand-rolls a welcome:
	/// `Group.verifying(proposal:)` authenticates only the ENCLOSING framing
	/// (the current occupant's signature + membership tag), never the
	/// embedded leaf's own shape (its own doc comment says so), so a validly
	/// framed proposal can carry any leaf at all — exactly the gap this gate
	/// closes. A BOUND acceptor's own send group (Group_B, which mirrors the
	/// binding) rejects it; the identical forgery into an UNBOUND acceptor's
	/// send group is accepted — the gate is binding-conditional, not
	/// unconditional.
	func testQueueProposalRejectsAnUncapableReplacementLeafOnlyWhenGroupIsBound() throws {
		let bound = try Self.forgedUncapableUpdate(
			appBinding: Self.binding, suffix: "bound")
		var boundCommitter = bound.committer
		boundCommitter.offeredProposal = (
			digest: bound.digest, proposing: bound.proposingID, message: bound.message
		)
		XCTAssertThrowsError(try boundCommitter.queueProposal(digest: bound.digest)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingLeafUnadvertised)
		}

		let unbound = try Self.forgedUncapableUpdate(appBinding: nil, suffix: "unbound")
		var unboundCommitter = unbound.committer
		unboundCommitter.offeredProposal = (
			digest: unbound.digest, proposing: unbound.proposingID,
			message: unbound.message
		)
		XCTAssertNoThrow(try unboundCommitter.queueProposal(digest: unbound.digest))
	}

	// MARK: - Establishment round trip

	/// The headline case: `initiate(appBinding:)` welds the binding into
	/// Group_A's classical half; `receive(expectedAppBinding:)` verifies it,
	/// mirrors it onto Group_B; once the initiator joins Group_B off the
	/// acceptor's re-stapled first frame, both sides' `appBinding()` read
	/// back the same bytes (mirrors Rust's `app_binding` round-trip, and
	/// exercises the initiator's return-welcome verification, book
	/// group-rules.md rule 8).
	func testAppBindingRoundTripsThroughEstablishmentAndExchange() throws {
		let alice = try SessionTestSupport.identity("bound-alice")
		let bob = try SessionTestSupport.identity("bound-bob")

		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider, appBinding: Self.binding)
		let received = try TwoMLSSession.receive(
			identity: bob, welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider, expectedAppBinding: Self.binding)

		var aliceSession = initiated.session
		var bobSession = received.session
		XCTAssertEqual(try bobSession.appBinding(), Self.binding)

		_ = try bobSession.prepareToEncrypt()
		let bobFrame = try bobSession.encrypt(Data("bob-hello".utf8)).frame
		_ = try aliceSession.processIncomingDecrypted(bobFrame)
		XCTAssertTrue(aliceSession.isEstablished)
		XCTAssertEqual(try aliceSession.appBinding(), Self.binding)
	}

	/// The control case: no `appBinding` on either side reads back `nil` on
	/// both, and establishment/exchange proceeds exactly as an ordinary
	/// unbound session.
	func testUnboundSessionReadsBackNilOnBothSides() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged(
			alice: "unbound-alice", bob: "unbound-bob")
		XCTAssertNil(try alice.appBinding())
		XCTAssertNil(try bob.appBinding())
	}

	// MARK: - `receive`/`Invitation.receive` verification

	/// A mismatched expectation is rejected before any invitation state is
	/// claimed — the invitation stays fully reusable, and a subsequent
	/// honest `receive` with the correct expectation still succeeds (book
	/// group-rules.md rule 8, "raised before any invitation state is
	/// claimed").
	func testInvitationReceiveRejectsMismatchBeforeConsumptionAndStaysReusable() throws {
		let alicePrincipal = try Principal.generate(
			clientID: Data("mismatch-alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("mismatch-bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		let theirCombinerKP = try XCTUnwrap(invitation.combinerKeyPackage)

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP, appBinding: Self.binding)
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)

		XCTAssertThrowsError(
			try invitation.receive(
				welcome: initiated.welcome,
				theirClassicalKeyPackage: initiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				spawnToken: spawnToken,
				expectedAppBinding: Data("wrong-digest".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}
		// CODE FIX 2: `generateInvitation(lastResort: true)` never nils
		// `identity`, so `combinerKeyPackage != nil` would pass here
		// regardless of whether `receive` actually claimed anything — assert
		// the invitation's OWN tables instead: neither the digest-keyed nor
		// the token-keyed table a successful `receive` would have written
		// got written.
		XCTAssertNil(
			invitation.processedWelcomeGroupID(welcome: initiated.welcome),
			"a rejected welcome must not be recorded as processed")
		XCTAssertNil(
			invitation.forwardGroupID(spawnToken: spawnToken),
			"a rejected welcome must not claim its spawn token")

		// The same welcome, now with the CORRECT expectation, still receives.
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken, expectedAppBinding: Self.binding)
		XCTAssertTrue(received.session.isEstablished)
		XCTAssertEqual(try received.session.appBinding(), Self.binding)
	}

	/// The `lastResort` invitation above can never tell a claim-nothing
	/// rejection from a successful `receive` via `combinerKeyPackage` alone
	/// (last-resort never nils `identity`, full stop). A SINGLE-USE
	/// invitation's `combinerKeyPackage` DOES go `nil` on a successful
	/// `receive` (`Invitation.receive`'s `if !lastResort { next.identity =
	/// nil }`) — so asserting it stays non-nil after a REJECTED one here
	/// actually proves the KP was never consumed.
	func testInvitationReceiveRejectsMismatchLeavesASingleUseKeyPackageUnconsumed() throws {
		let alicePrincipal = try Principal.generate(
			clientID: Data("single-use-mismatch-alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("single-use-mismatch-bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let theirCombinerKP = try XCTUnwrap(invitation.combinerKeyPackage)

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP, appBinding: Self.binding)
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)

		XCTAssertThrowsError(
			try invitation.receive(
				welcome: initiated.welcome,
				theirClassicalKeyPackage: initiated.session.identity.keyPackage
					.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				spawnToken: spawnToken,
				expectedAppBinding: Data("wrong-digest".utf8))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}
		XCTAssertNotNil(
			invitation.combinerKeyPackage,
			"a single-use invitation's KP must remain unconsumed by a rejected receive"
		)

		// The same welcome, now with the CORRECT expectation, consumes the KP.
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken, expectedAppBinding: Self.binding)
		XCTAssertTrue(received.session.isEstablished)
		XCTAssertNil(invitation.combinerKeyPackage)
	}

	/// `Some` expected, welcome carries none — rejected.
	func testReceiveRejectsMissingWhenExpected() throws {
		let alice = try SessionTestSupport.identity("missing-alice")
		let bob = try SessionTestSupport.identity("missing-bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider,
				expectedAppBinding: Self.binding)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}
	}

	/// Welcome carries a binding, expected `None` — rejected: a binding the
	/// caller did not state is never silently accepted.
	func testReceiveRejectsUnexpectedBinding() throws {
		let alice = try SessionTestSupport.identity("unexpected-alice")
		let bob = try SessionTestSupport.identity("unexpected-bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider, appBinding: Self.binding)

		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}
	}

	/// An EMPTY expectation is rejected UP FRONT — before any welcome decode
	/// or join is even attempted, never merely because the eventual verifier
	/// happens to reject it too. Proven by pairing it with an UNDECODABLE
	/// welcome: if the up-front guard did not fire first, decoding garbage
	/// would throw `.unsupportedStapleTag` (or similar), never
	/// `.appBindingMismatch` — so this welcome and key package are never even
	/// real ones (CODE FIX 4: the old version used a genuine welcome, which
	/// the verifier would ALSO have rejected for the same error, so it could
	/// not tell the two guards apart).
	func testReceiveRejectsEmptyExpectation() throws {
		let bob = try SessionTestSupport.identity("empty-expect-bob")

		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: bob, welcome: Data("not-a-real-welcome".utf8),
				theirClassicalKeyPackage: bob.keyPackage.classical,
				bootstrapKPCommitment: Data(repeating: 0, count: 32),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider,
				expectedAppBinding: Data())
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}
	}

	// MARK: - `initiate` empty rejection

	/// An EMPTY `appBinding` is rejected at `initiate`, before any group is
	/// built — `None` is the deliberate unbound state, not an empty digest.
	func testInitiateRejectsEmptyAppBinding() throws {
		let alice = try SessionTestSupport.identity("empty-initiate-alice")
		let bob = try SessionTestSupport.identity("empty-initiate-bob")

		XCTAssertThrowsError(
			try TwoMLSSession.initiate(
				identity: alice, their: bob.keyPackage,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider, appBinding: Data())
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}
		// The same identity/peer pair still establishes with a real binding.
		XCTAssertNoThrow(
			try TwoMLSSession.initiate(
				identity: alice, their: bob.keyPackage,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider, appBinding: Self.binding)
		)
	}

	// MARK: - Initiator return-welcome join

	/// The acceptor is required to mirror the (verified) incoming binding
	/// onto Group_B: a hand-rolled return welcome that STRIPS it — a
	/// downgrade a wired acceptor can never itself produce — is refused at
	/// the initiator's return-welcome join, and the receive side stays
	/// unjoined (mirrors Rust's
	/// `test_return_welcome_without_app_binding_rejected`; hand-rolling below
	/// mirrors `EstablishmentTests.forgedGroupBWelcome`'s technique).
	func testReturnWelcomeWithoutAppBindingRejectedOnInitiatorSide() throws {
		let alice = try SessionTestSupport.identity("strip-alice")
		let bob = try SessionTestSupport.identity("strip-bob")
		let provider = SessionTestSupport.classicalProvider

		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: provider, pqProvider: SessionTestSupport.pqProvider,
			appBinding: Self.binding)
		let received = try TwoMLSSession.receive(
			identity: bob, welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			classicalProvider: provider, pqProvider: SessionTestSupport.pqProvider,
			expectedAppBinding: Self.binding)
		var aliceSession = initiated.session

		// Bob's genuine first frame, borrowed only for its real sealed app
		// section — the forged staple below replaces its welcome.
		var bobSession = received.session
		_ = try bobSession.prepareToEncrypt()
		let genuineFrame = try bobSession.encrypt(Data("genuine".utf8)).frame
		let (_, _, appSection) = try Frames.decodeMessageFrame(
			aliceSession.openOrRaw(genuineFrame))

		// A fresh "bob" identity (same clientID Alice expects, different
		// keys — Basic credentials carry no proof, which is the point) founds
		// a classical-only Group_B with Alice's REAL cross-party PSK
		// (exported off a copy of her live Group_A, so the export leaf isn't
		// consumed) but NO AppBinding — the strip a wired acceptor can never
		// itself produce.
		var groupACopy = try XCTUnwrap(aliceSession.sendGroup)
		let crossPSK = try MLS.Combiner.ExportedPsk.export(
			from: &groupACopy.classical, provider,
			componentID: TwoMLSSession.crossPartyComponentID)
		let strippedBob = try SessionTestSupport.identity("strip-bob")
		let founderHalf = MLS.Combiner.HalfCreation(
			groupID: provider.randomBytes(provider.hashSize),
			leafNode: strippedBob.keyPackage.classical.leafNode,
			leafSecretKey: strippedBob.classicalLeafSecretKey,
			signingKey: strippedBob.signingKey,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize),
			randomness: try .generate(provider),
			peerKeyPackage: alice.keyPackage.classical)
		let (_, strippedWelcome) = try APQGroup.establishClassicalOnly(
			founder: founderHalf, pqGroupID: provider.randomBytes(provider.hashSize),
			crossPSK: crossPSK, nonce: provider.randomBytes(provider.hashSize),
			provider: provider, appBinding: nil)
		let strippedStaple = Frames.encodeAPQWelcome(
			t: try strippedWelcome.mlsEncoded(), pq: Data())

		let proposalSection = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: Data("dummy-upd".utf8))
		let forgedFrame = Frames.encodeMessageFrame(
			staple: strippedStaple, proposal: proposalSection, app: appSection)

		XCTAssertThrowsError(try aliceSession.processIncomingDecrypted(forgedFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .appBindingMismatch)
		}
		XCTAssertNil(aliceSession.recvGroup)
		XCTAssertNil(aliceSession.joinedWelcomeDigest)

		// Bob's real, un-stripped first frame still joins cleanly afterward —
		// value semantics leave nothing wedged (mirrors
		// `testMalformedWelcomeStapleLeavesTheGenuineOneJoinable`).
		let decrypted = try aliceSession.processIncomingDecrypted(genuineFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("genuine".utf8))
		XCTAssertTrue(aliceSession.isEstablished)
	}

	// MARK: - Archive restore

	/// The AppBinding rides the persisted group state: a bound session's
	/// `appBinding()` reads back the same bytes after a restore, on both
	/// roles; an unbound session's restore still reads back `nil` (mirrors
	/// Rust's `test_app_binding_survives_archive_restore`).
	func testAppBindingSurvivesArchiveRestore() throws {
		let alice = try SessionTestSupport.identity("restore-alice")
		let bob = try SessionTestSupport.identity("restore-bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider, appBinding: Self.binding)
		let received = try TwoMLSSession.receive(
			identity: bob, welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider, expectedAppBinding: Self.binding)

		var bobSession = received.session
		let checkpoint = try bobSession.stateUpdate(kind: .checkpoint).archive
		let restoredBob = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertEqual(try restoredBob.appBinding(), Self.binding)

		// An unbound session's restore reads back `nil` on the same getter.
		let (_, unboundBob, _, _, _, _) = try SessionTestSupport.established(
			alice: "restore-unbound-alice", bob: "restore-unbound-bob")
		var unboundBobMutable = unboundBob
		let unboundCheckpoint = try unboundBobMutable.stateUpdate(kind: .checkpoint).archive
		let restoredUnbound = try TwoMLSSession.restore(
			core: nil, checkpoint: unboundCheckpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertNil(try restoredUnbound.appBinding())
	}

	// MARK: - Test helpers

	/// Capabilities matching a pre-AppBinding-cut leaf: both suites,
	/// `APQInfo`, and `AppDataUpdate`, but NOT `0xF0A2` — standing in for an
	/// old client build, shared by every rogue-leaf helper below.
	private static let preCutCapabilities = MLS.RFC9420.Capabilities(
		versions: [.mls10],
		cipherSuites: [TwoMLSSuite.classical, TwoMLSSuite.pq],
		extensions: [MLS.Combiner.Codepoints.deployed.apqInfoExtensionType],
		proposals: [MLS.RFC9420.ProposalType(.appDataUpdate)],
		credentials: [MLS.RFC9420.CredentialType(.basic)])

	/// A classical `KeyPackage` for `clientID` with `preCutCapabilities` —
	/// mirrors `TwoMLSIdentity`'s private `signedKeyPackage`, with a
	/// restricted capability set standing in for an old client build. Basic
	/// credentials carry no proof (the leaf's signing key need not match any
	/// real identity's), matching `EstablishmentTests.forgedGroupBWelcome`'s
	/// same technique.
	private static func rogueClassicalKeyPackage(clientID: Data) throws
		-> MLS.RFC9420.KeyPackage
	{
		let provider = SessionTestSupport.classicalProvider
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (_, leafPublicKey) = try provider.hpkeGenerateKeyPair()
		let (_, initPublicKey) = try provider.hpkeGenerateKeyPair()

		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublicKey, signatureKey: signatureKey,
			credential: .basic(identity: clientID), capabilities: preCutCapabilities,
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)), extensions: [],
			signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: provider.cipherSuite, initKey: initPublicKey,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return keyPackage
	}

	/// Builds a fresh (initiator, acceptor) pair — bound when `appBinding` is
	/// non-nil — and hand-forges a validly-FRAMED "Alice Update" targeting
	/// the acceptor's own send group (Group_B): the enclosing proposal is
	/// signed under Alice's REAL, currently-occupying classical key (so
	/// `Group.verifying(proposal:)` accepts the framing), but the embedded
	/// replacement leaf swaps in `preCutCapabilities` (missing `0xF0A2`) —
	/// credential and signature key stay identical to Alice's real leaf, so
	/// this is a plain non-rotating Update, never touching AS/successor
	/// logic. Mirrors `EstablishmentTests.forgedGroupBWelcome`'s hand-rolling
	/// technique one level down (a proposal instead of a welcome).
	private static func forgedUncapableUpdate(appBinding: Data?, suffix: String) throws -> (
		committer: TwoMLSSession, message: Data, digest: Data, proposingID: Data
	) {
		let provider = SessionTestSupport.classicalProvider
		let alice = try SessionTestSupport.identity("update-leaf-alice-\(suffix)")
		let bob = try SessionTestSupport.identity("update-leaf-bob-\(suffix)")

		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage, classicalProvider: provider,
			pqProvider: SessionTestSupport.pqProvider, appBinding: appBinding)
		let received = try TwoMLSSession.receive(
			identity: bob, welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			classicalProvider: provider, pqProvider: SessionTestSupport.pqProvider,
			expectedAppBinding: appBinding)

		let committerSend = try XCTUnwrap(received.session.sendGroup).classical
		let aliceLeafIndex = try XCTUnwrap(
			committerSend.tree.nonBlankLeaves()
				.first { $0.index != committerSend.myLeafIndex }?.index)
		let realLeafRecord = try XCTUnwrap(committerSend.tree.leaf(at: aliceLeafIndex))
		let realLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: realLeafRecord.encoded)

		let (_, rogueEncryptionKey) = try provider.hpkeGenerateKeyPair()
		var rogueLeaf = realLeaf
		rogueLeaf.encryptionKey = rogueEncryptionKey
		rogueLeaf.capabilities = preCutCapabilities
		rogueLeaf.source = .update
		rogueLeaf.signature = try MLS.signWithLabel(
			provider, privateKey: alice.signingKey, label: "LeafNodeTBS",
			content: try rogueLeaf.toBeSigned(
				placement: .inGroup(
					groupID: committerSend.context.groupID,
					leafIndex: aliceLeafIndex)))

		let content = MLS.RFC9420.FramedContent(
			groupID: committerSend.context.groupID, epoch: committerSend.context.epoch,
			sender: .member(aliceLeafIndex), authenticatedData: Data(),
			content: .proposal(.update(rogueLeaf)))
		let forged = try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: committerSend.context,
			confirmationTag: nil, signingKey: alice.signingKey,
			membershipKey: committerSend.epoch.membershipKey)
		let message = try MLS.RFC9420.Message.publicMessage(forged).mlsEncoded()

		return (
			committer: received.session, message: message,
			digest: provider.randomBytes(8), proposingID: alice.clientID
		)
	}
}
