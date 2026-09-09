import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import XCTest

@testable import TwoMLSPQSession

/// A hand-rolled single-suite member for the integration test below — the
/// same recipe as `TwoMLSIdentity.signedKeyPackage`, but free of
/// `@available(iOS 26, macOS 26)`: that gate exists only for the ML-KEM PQ
/// half, which this test never touches.
private struct RotationMember {
	let identity: Data
	let signingKey: MLS.SignatureSecretKey
	let signatureKey: MLS.SignaturePublicKey
	let leafSecretKey: MLS.HpkeSecretKey
	let initSecretKey: MLS.HpkeSecretKey
	let keyPackage: MLS.RFC9420.KeyPackage

	var joinCredentials: MLS.RFC9420.Group.JoinerCredentials {
		.init(keyPackage: keyPackage, initKey: initSecretKey, encryptionKey: leafSecretKey)
	}
}

private func makeRotationMember(
	_ name: String, provider: any MLS.CipherSuiteProvider
) throws -> RotationMember {
	let signingPrivateKey = Curve25519.Signing.PrivateKey()
	let signingKey = try MLS.SignatureSecretKey(signingPrivateKey.rawRepresentation)
	let signatureKey = MLS.SignaturePublicKey(signingPrivateKey.publicKey.rawRepresentation)
	let (leafSecretKey, leafPublicKey) = try provider.hpkeGenerateKeyPair()
	let (initSecretKey, initPublicKey) = try provider.hpkeGenerateKeyPair()
	let identity = Data(name.utf8)

	var leaf = MLS.RFC9420.LeafNode(
		encryptionKey: leafPublicKey, signatureKey: signatureKey,
		credential: .basic(identity: identity),
		capabilities: MLS.RFC9420.Capabilities(
			versions: [.mls10], cipherSuites: [provider.cipherSuite],
			extensions: [], proposals: [],
			credentials: [MLS.RFC9420.CredentialType(.basic)]),
		source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
		extensions: [], signature: Data())
	leaf.signature = try MLS.signWithLabel(
		provider, privateKey: signingKey, label: "LeafNodeTBS",
		content: try leaf.toBeSigned(placement: .keyPackage))

	var keyPackage = MLS.RFC9420.KeyPackage(
		version: .mls10, cipherSuite: provider.cipherSuite, initKey: initPublicKey,
		leafNode: leaf, extensions: [], signature: Data())
	keyPackage.signature = try MLS.signWithLabel(
		provider, privateKey: signingKey, label: "KeyPackageTBS",
		content: try keyPackage.toBeSigned())

	return RotationMember(
		identity: identity, signingKey: signingKey, signatureKey: signatureKey,
		leafSecretKey: leafSecretKey, initSecretKey: initSecretKey, keyPackage: keyPackage)
}

/// `PartySequence`/`AuthCore` — pure `Data`, no `@available`: the AS
/// mechanism itself needs no OS-26 dependency (only `TwoMLSSuite`'s PQ suite
/// does). Each cluster notes, in a comment, which single line — if broken —
/// makes ONLY that test fail (mutation-verification).
final class CredentialAuthenticationTests: XCTestCase {
	private func id(_ s: String) -> Data { Data(s.utf8) }

	// MARK: - commit()

	func testCommitAppendsAndAdvancesCurrent() throws {
		var sequence = PartySequence.seeded(id("a"))
		XCTAssertEqual(sequence.current, id("a"))
		sequence.commit(id("b"))
		XCTAssertEqual(sequence.current, id("b"))
		XCTAssertEqual(sequence.history, [id("a"), id("b")])
	}

	/// `[A,B,C].commit(A)` ⇒ history `[B,C,A]`, current `A`, no dup. Mutation:
	/// dropping `history.removeAll { $0 == id }` is the ONLY line that makes
	/// this fail — without the dedupe/move-to-newest step, `commit(A)` would
	/// append a second `A` instead of relocating the existing one.
	func testCommitDedupesAndMovesToNewest() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.commit(id("b"))
		sequence.commit(id("c"))
		XCTAssertEqual(sequence.history, [id("a"), id("b"), id("c")])

		sequence.commit(id("a"))
		XCTAssertEqual(sequence.history, [id("b"), id("c"), id("a")])
		XCTAssertEqual(sequence.current, id("a"))
		XCTAssertTrue(sequence.validSuccessor(pred: id("b"), succ: id("a")))
	}

	/// Mutation: moving `authorizedNext.removeAll()` to run BEFORE the
	/// `current == id` no-op check is the ONLY change that makes this fail —
	/// a re-commit of the already-current id must preserve an authorization
	/// already in flight for the NEXT step.
	func testCommitOfCurrentPreservesAuthorizedNext() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.authorize(id("b"))
		sequence.commit(id("a"))  // no-op: already current
		XCTAssertTrue(sequence.validSuccessor(pred: id("a"), succ: id("b")))
	}

	// MARK: - validSuccessor: same-id / authorized / catch-up / non-successor

	func testSameIDIsAlwaysAValidSuccessor() throws {
		let sequence = PartySequence.seeded(id("a"))
		XCTAssertTrue(sequence.validSuccessor(pred: id("a"), succ: id("a")))
		XCTAssertTrue(sequence.validSuccessor(pred: id("z"), succ: id("z")))
	}

	func testAuthorizedStepIsAcceptedAsSuccessor() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.authorize(id("b"))
		XCTAssertTrue(sequence.validSuccessor(pred: id("a"), succ: id("b")))
	}

	/// Catch-up: a lagging leaf (still on an older, but still-in-history,
	/// credential) may fast-forward to any newer history element with no
	/// separate authorization.
	func testCatchUpToNewerHistoryElementIsAccepted() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.commit(id("b"))
		sequence.commit(id("c"))
		XCTAssertTrue(sequence.validSuccessor(pred: id("a"), succ: id("c")))
	}

	/// A `succ` unrelated to `pred` (not authorized, not newer in history) is
	/// the case a real `validateSuccession` call throws `.invalidSuccession`
	/// for (exercised for real in the integration test below).
	func testUnrelatedSuccessorIsRejected() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.commit(id("b"))
		XCTAssertFalse(sequence.validSuccessor(pred: id("b"), succ: id("z")))
	}

	// MARK: - validSuccessor: gate ordering (HIGH)

	/// Gate ordering: an unknown `pred` must be rejected BEFORE the
	/// authorized-`succ` check runs. Mutation: swapping the two guards
	/// (checking `authorizedNext.contains(succ)` first) is the ONLY change
	/// that makes this fail — it would accept an authorized `succ` even from
	/// a `pred` this sequence never held.
	func testUnknownPredWithAuthorizedSuccessorIsStillRejected() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.authorize(id("b"))
		XCTAssertFalse(sequence.validSuccessor(pred: id("unknown"), succ: id("b")))
	}

	/// A `pred` that is pinned-only (absent from `history`) IS known, so the
	/// same authorized `succ` is accepted from it.
	func testPinnedOnlyPredWithAuthorizedSuccessorIsAccepted() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.pin(id("old"))
		sequence.authorize(id("b"))
		XCTAssertTrue(sequence.validSuccessor(pred: id("old"), succ: id("b")))
	}

	/// No-downgrade (HIGH), in one test: a pinned id absent from `history` is
	/// admissible as an OLDEST `pred`, but never a valid `succ` — it can
	/// never authorize a downgrade back onto itself. Mutation: making
	/// `(nil, _?)` return anything but a fixed direction (or admitting a
	/// pinned id into `position(succ)`) is what this test pins down.
	func testPinnedIDNeverAuthorizesADowngrade() throws {
		var sequence = PartySequence.seeded(id("current"))
		sequence.pin(id("ancient"))
		XCTAssertFalse(sequence.validSuccessor(pred: id("current"), succ: id("ancient")))
		XCTAssertTrue(sequence.validSuccessor(pred: id("ancient"), succ: id("current")))
	}

	// MARK: - History window

	/// Mutation: relaxing `history.count > Self.credentialHistoryWindow` (or
	/// dropping the evict loop entirely) is the ONLY change that makes the
	/// count assertion fail.
	func testWindowEvictsOldestPastCapacity() throws {
		var sequence = PartySequence.seeded(id("id-0"))
		for i in 1...PartySequence.credentialHistoryWindow {
			sequence.commit(id("id-\(i)"))
		}
		XCTAssertEqual(sequence.history.count, PartySequence.credentialHistoryWindow)
		XCTAssertFalse(sequence.contains(id("id-0")))
		XCTAssertTrue(sequence.contains(id("id-1")))
	}

	/// An evicted id is no longer a valid `pred` UNLESS pinned.
	func testEvictedIDIsNoLongerAValidPredUnlessPinned() throws {
		var sequence = PartySequence.seeded(id("id-0"))
		for i in 1...PartySequence.credentialHistoryWindow {
			sequence.commit(id("id-\(i)"))
		}
		let newest = id("id-\(PartySequence.credentialHistoryWindow)")
		XCTAssertFalse(sequence.validSuccessor(pred: id("id-0"), succ: newest))

		sequence.pin(id("id-0"))
		XCTAssertTrue(sequence.validSuccessor(pred: id("id-0"), succ: newest))
	}

	// MARK: - knownIDs / AuthCore.knows / validateMember

	/// Mutation: dropping any ONE of the three `knownIDs` sources (`history`,
	/// `authorizedNext`, `pinned`) makes exactly the corresponding element
	/// below missing from this set.
	func testKnownIDsChainsAllThreeSources() throws {
		var sequence = PartySequence.seeded(id("history-id"))
		sequence.authorize(id("authorized-id"))
		sequence.pin(id("pinned-id"))
		XCTAssertEqual(
			Set(sequence.knownIDs),
			Set([id("history-id"), id("authorized-id"), id("pinned-id")]))
	}

	func testValidateMemberRejectsUnknownIdentity() throws {
		let auth = AuthCore(mine: .seeded(id("me")), theirs: .seeded(id("them")))
		XCTAssertThrowsError(try auth.validateMember(.basic(identity: id("stranger")))) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .unknownIdentity)
		}
	}

	func testValidateMemberAdmitsAuthorizedOnlyIdentity() throws {
		var auth = AuthCore(mine: .seeded(id("me")), theirs: .seeded(id("them")))
		auth.theirs.authorize(id("their-next"))
		XCTAssertNoThrow(try auth.validateMember(.basic(identity: id("their-next"))))
	}

	func testValidateMemberAdmitsPinnedEvictedIdentity() throws {
		var sequence = PartySequence.seeded(id("id-0"))
		for i in 1...PartySequence.credentialHistoryWindow {
			sequence.commit(id("id-\(i)"))
		}
		XCTAssertFalse(sequence.contains(id("id-0")))
		sequence.pin(id("id-0"))
		let auth = AuthCore(mine: .seeded(id("me")), theirs: sequence)
		XCTAssertNoThrow(try auth.validateMember(.basic(identity: id("id-0"))))
	}

	func testValidateMemberRejectsEvictedAndUnpinnedIdentity() throws {
		var sequence = PartySequence.seeded(id("id-0"))
		for i in 1...PartySequence.credentialHistoryWindow {
			sequence.commit(id("id-\(i)"))
		}
		let auth = AuthCore(mine: .seeded(id("me")), theirs: sequence)
		XCTAssertThrowsError(try auth.validateMember(.basic(identity: id("id-0")))) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .unknownIdentity)
		}
	}

	func testValidateMemberRejectsUnsupportedCredentialType() throws {
		let auth = AuthCore(mine: .seeded(id("me")), theirs: .seeded(id("them")))
		XCTAssertThrowsError(
			try auth.validateMember(
				.other(type: MLS.RFC9420.CredentialType(.x509), data: Data()))
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .unsupportedCredential)
		}
	}

	// MARK: - Same-id / new-signature-key: accepted by design

	/// The AS tracks Basic-credential IDENTIFIERS only (faithful to the Rust
	/// reference's `basic_id`): `validSuccessor` never inspects a signature
	/// key, so a same-id "successor" is accepted regardless of any key change
	/// underneath it. Continuity of the identity↔key binding across a rotation
	/// is enforced elsewhere — the rotation is framed/signed under the OLD key
	/// (ADR 0002 `signingClosure(current:new:)`) and the peer identity is bound
	/// at establishment — a deliberate Germ scope boundary, not this AS's job.
	func testSameIdentifierIsAcceptedByDesignRegardlessOfKeyChange() throws {
		let sequence = PartySequence.seeded(id("stable-id"))
		XCTAssertTrue(sequence.validSuccessor(pred: id("stable-id"), succ: id("stable-id")))
	}

	// MARK: - Integration (ungated): a real rotation through `adjudicate`

	/// Hand-rolls a 2-member classical MLS group (no `TwoMLSSession`/
	/// `TwoMLSIdentity` — those are `@available(iOS 26, macOS 26)` solely for
	/// the ML-KEM PQ half; this test proves the AS mechanism itself needs
	/// none of that), drives a REAL credential rotation through swift-mls's
	/// public authoring API (`proposeUpdate` + `signingClosure(current:new:)`
	/// + `committing([.reference(...)])`), and feeds the genuine resulting
	/// `CommitEffects` — never a hand-built one, since `CommitEffects.init`
	/// and `CredentialPresentation.init` are both `internal` to
	/// `MLSProfileRFC9420` — to `AuthCore.adjudicate`.
	func testAdjudicateAcceptsAuthorizedRotationAndRejectsUnauthorizedOne() throws {
		let provider = SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519ChaCha)!

		let alice = try makeRotationMember("alice", provider: provider)
		let bob = try makeRotationMember("bob", provider: provider)

		// Found the group: Alice creates, adds Bob.
		let epoch0 = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: alice.keyPackage.leafNode, leafSecretKey: alice.leafSecretKey,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))
		let creation = try epoch0.committing(
			provider, proposals: [.proposal(.add(bob.keyPackage))],
			signingKey: alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		let creationBase = creation.group
		let creationSent = creation.takeOutput()
		let welcome = try XCTUnwrap(creationSent.welcome)
		let creationPending = creationSent.takePending()
		let foundingEffects = creationPending.effects
		let creationAdvanced = try creationPending.apply(onto: creationBase)
		let aliceGroup = creationAdvanced.group

		let bobPendingJoin = try MLS.RFC9420.Group.joining(
			provider, welcome: welcome, credentials: bob.joinCredentials,
			psk: { _ in nil })
		var bobGroup = bobPendingJoin.apply().group
		let bobLeaf = bobGroup.myLeafIndex

		// Bob authors a real rotation; Alice commits it by reference.
		let rotated = try makeRotationMember("bob-rotated", provider: provider)
		let newIdentity = MLS.RFC9420.NewSigningIdentity(
			credential: .basic(identity: rotated.identity),
			signatureKey: rotated.signatureKey)

		let (message, ref) = try bobGroup.proposeUpdate(
			provider,
			sign: MLS.RFC9420.signingClosure(
				provider, current: bob.signingKey, new: rotated.signingKey),
			framing: .publicMessage, newIdentity: newIdentity)
		guard case .publicMessage(let proposalPub) = message else {
			return XCTFail("expected a public proposal message")
		}
		let verifiedProposal = try aliceGroup.verifying(provider, proposal: proposalPub)
		var store = MLS.RFC9420.ProposalStore()
		_ = try store.insert(verifiedProposal, provider)

		let rotation = try aliceGroup.committing(
			provider, proposals: [.reference(ref)], proposalStore: store,
			signingKey: alice.signingKey, randomness: .generate(provider),
			framing: .publicMessage)
		let rotationBase = rotation.group
		let rotationPending = rotation.takeOutput().takePending()
		let rotationEffects = rotationPending.effects
		_ = try rotationPending.apply(onto: rotationBase)

		guard
			let credentialReplaced = rotationEffects.events.first(where: {
				if case .credentialReplaced = $0 { return true }
				return false
			}), case .credentialReplaced(let leaf, _, let new) = credentialReplaced
		else {
			return XCTFail("expected a credentialReplaced effect")
		}
		XCTAssertEqual(leaf, bobLeaf)
		XCTAssertEqual(new.credential, newIdentity.credential)

		// `adjudicate`'s `.added` arm is real: the founding commit carries a
		// genuine `.added(bob)` `CredentialPresentation` (not a hand-built one).
		XCTAssertTrue(
			foundingEffects.events.contains {
				if case .added = $0 { return true }
				return false
			})

		// Accept: the rotated id was authorized in the AS beforehand. Also
		// exercises `adjudicate`'s `.added` arm (`validateMember(presentation:)`)
		// against the founding commit's real `CredentialPresentation`.
		var acceptingAuth = AuthCore(
			mine: .seeded(alice.identity), theirs: .seeded(bob.identity))
		acceptingAuth.theirs.authorize(rotated.identity)
		XCTAssertNoThrow(try acceptingAuth.adjudicate(foundingEffects))
		XCTAssertNoThrow(try acceptingAuth.adjudicate(rotationEffects))

		// Reject: a fresh AS that never authorized (or caught up to) the
		// rotated id — the profile already rejects a forged credential
		// before this AS ever sees it, so "unauthorized" here means an id
		// this AS's state never admits, not tampered bytes.
		let rejectingAuth = AuthCore(
			mine: .seeded(alice.identity), theirs: .seeded(bob.identity))
		XCTAssertThrowsError(try rejectingAuth.adjudicate(rotationEffects)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}

		// Reject via the `.added` arm: an AS whose `theirs` never knew Bob's id
		// rejects the founding commit's `.added(bob)` — pins that `adjudicate`
		// validates added members, not only credential replacements. Mutation:
		// turning the `.added` case into `break` makes ONLY this assertion fail.
		let strangerAuth = AuthCore(
			mine: .seeded(alice.identity), theirs: .seeded(Data("not-bob".utf8)))
		XCTAssertThrowsError(try strangerAuth.adjudicate(foundingEffects)) { error in
			XCTAssertEqual(error as? TwoMLSError, .unknownIdentity)
		}
	}
}
