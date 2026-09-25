import Crypto
import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing

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
@Suite struct CredentialAuthenticationTests {
	private func id(_ s: String) -> Data { Data(s.utf8) }

	// MARK: - commit()

	@Test func commitAppendsAndAdvancesCurrent() throws {
		var sequence = PartySequence.seeded(id("a"))
		#expect(sequence.current == id("a"))
		try sequence.commit(id("b"))
		#expect(sequence.current == id("b"))
		#expect(sequence.history == [id("a"), id("b")])
	}

	/// Rollback is an error: re-committing an id that is in `history` but no
	/// longer current throws `.credentialRollback` and leaves history untouched
	/// (identities are always freshly generated, so a recurrence is never
	/// convergence). Mutation: restoring the old move-to-newest
	/// (`history.removeAll { $0 == id }` + append, instead of the throw) is the
	/// ONLY change that makes this fail.
	@Test func commitRejectsRollbackToRetiredID() throws {
		var sequence = PartySequence.seeded(id("a"))
		try sequence.commit(id("b"))
		try sequence.commit(id("c"))
		#expect(throws: TwoMLSError.credentialRollback) {
			try sequence.commit(id("a"))
		}
		#expect(sequence.history == [id("a"), id("b"), id("c")])
		#expect(sequence.current == id("c"))
	}

	/// `commit` also rejects re-committing a `pinned` (retired-but-held) id, not
	/// just one still in the live window. Mutation: dropping `|| pinned.contains(id)`
	/// makes this fail.
	@Test func commitRejectsRollbackToPinnedID() throws {
		var sequence = PartySequence.seeded(id("c0"))
		try sequence.commit(id("c1"))
		sequence.pin(id("retired"))
		#expect(throws: TwoMLSError.credentialRollback) {
			try sequence.commit(id("retired"))
		}
	}

	/// Mutation: moving `authorizedNext.removeAll()` to run BEFORE the
	/// `current == id` no-op check is the ONLY change that makes this fail —
	/// a re-commit of the already-current id must preserve an authorization
	/// already in flight for the NEXT step.
	@Test func commitOfCurrentPreservesAuthorizedNext() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.authorize(id("b"))
		try sequence.commit(id("a"))  // no-op: already current
		#expect(sequence.validSuccessor(pred: id("a"), succ: id("b")))
	}

	// MARK: - validSuccessor: same-id / authorized / catch-up / non-successor

	@Test func sameIDIsAlwaysAValidSuccessor() throws {
		let sequence = PartySequence.seeded(id("a"))
		#expect(sequence.validSuccessor(pred: id("a"), succ: id("a")))
		#expect(sequence.validSuccessor(pred: id("z"), succ: id("z")))
	}

	@Test func authorizedStepIsAcceptedAsSuccessor() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.authorize(id("b"))
		#expect(sequence.validSuccessor(pred: id("a"), succ: id("b")))
	}

	/// Catch-up: a lagging leaf (still on an older, but still-in-history,
	/// credential) may fast-forward to any newer history element with no
	/// separate authorization.
	@Test func catchUpToNewerHistoryElementIsAccepted() throws {
		var sequence = PartySequence.seeded(id("a"))
		try sequence.commit(id("b"))
		try sequence.commit(id("c"))
		#expect(sequence.validSuccessor(pred: id("a"), succ: id("c")))
	}

	/// A `succ` unrelated to `pred` (not authorized, not newer in history) is
	/// the case a real `validateSuccession` call throws `.invalidSuccession`
	/// for (exercised for real in the integration test below).
	@Test func unrelatedSuccessorIsRejected() throws {
		var sequence = PartySequence.seeded(id("a"))
		try sequence.commit(id("b"))
		#expect(!sequence.validSuccessor(pred: id("b"), succ: id("z")))
	}

	// MARK: - validSuccessor: gate ordering (HIGH)

	/// Gate ordering: an unknown `pred` must be rejected BEFORE the
	/// authorized-`succ` check runs. Mutation: swapping the two guards
	/// (checking `authorizedNext.contains(succ)` first) is the ONLY change
	/// that makes this fail — it would accept an authorized `succ` even from
	/// a `pred` this sequence never held.
	@Test func unknownPredWithAuthorizedSuccessorIsStillRejected() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.authorize(id("b"))
		#expect(!sequence.validSuccessor(pred: id("unknown"), succ: id("b")))
	}

	/// A `pred` that is pinned-only (absent from `history`) IS known, so the
	/// same authorized `succ` is accepted from it.
	@Test func pinnedOnlyPredWithAuthorizedSuccessorIsAccepted() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.pin(id("old"))
		sequence.authorize(id("b"))
		#expect(sequence.validSuccessor(pred: id("old"), succ: id("b")))
	}

	/// No-downgrade (HIGH), in one test: a pinned id absent from `history` is
	/// admissible as an OLDEST `pred`, but never a valid `succ` — it can
	/// never authorize a downgrade back onto itself. Mutation: making
	/// `(nil, _?)` return anything but a fixed direction (or admitting a
	/// pinned id into `position(succ)`) is what this test pins down.
	@Test func pinnedIDNeverAuthorizesADowngrade() throws {
		var sequence = PartySequence.seeded(id("current"))
		sequence.pin(id("ancient"))
		#expect(!sequence.validSuccessor(pred: id("current"), succ: id("ancient")))
		#expect(sequence.validSuccessor(pred: id("ancient"), succ: id("current")))
	}

	/// A rollback dressed as an authorization is still rejected: authorizing an
	/// id already retired in `history` does NOT make it a valid successor — the
	/// authorization shortcut admits only genuinely new ids. Mutation: dropping
	/// the `!history.contains(succ)` guard on the authorized arm makes this fail.
	@Test func authorizingARetiredIDDoesNotResurrectIt() throws {
		var sequence = PartySequence.seeded(id("c0"))
		try sequence.commit(id("c1"))
		try sequence.commit(id("c2"))
		sequence.authorize(id("c0"))  // app error: c0 is retired
		#expect(!sequence.validSuccessor(pred: id("c2"), succ: id("c0")))
		#expect(!sequence.validSuccessorOfCurrent(id("c0")))
	}

	/// Same for a `pinned` (evicted) id: authorizing it does not make it a valid
	/// `succ`, so the no-downgrade guarantee holds even against an authorization.
	/// Mutation: dropping the `!pinned.contains(succ)` guard makes this fail.
	@Test func authorizingAPinnedIDDoesNotMakeItAValidSuccessor() throws {
		var sequence = PartySequence.seeded(id("current"))
		sequence.pin(id("ancient"))
		sequence.authorize(id("ancient"))
		#expect(!sequence.validSuccessor(pred: id("current"), succ: id("ancient")))
	}

	// MARK: - History window

	/// Mutation: relaxing `history.count > Self.credentialHistoryWindow` (or
	/// dropping the evict loop entirely) is the ONLY change that makes the
	/// count assertion fail.
	@Test func windowEvictsOldestPastCapacity() throws {
		var sequence = PartySequence.seeded(id("id-0"))
		for i in 1...PartySequence.credentialHistoryWindow {
			try sequence.commit(id("id-\(i)"))
		}
		#expect(sequence.history.count == PartySequence.credentialHistoryWindow)
		#expect(!sequence.contains(id("id-0")))
		#expect(sequence.contains(id("id-1")))
	}

	/// An evicted id is no longer a valid `pred` UNLESS pinned.
	@Test func evictedIDIsNoLongerAValidPredUnlessPinned() throws {
		var sequence = PartySequence.seeded(id("id-0"))
		for i in 1...PartySequence.credentialHistoryWindow {
			try sequence.commit(id("id-\(i)"))
		}
		let newest = id("id-\(PartySequence.credentialHistoryWindow)")
		#expect(!sequence.validSuccessor(pred: id("id-0"), succ: newest))

		sequence.pin(id("id-0"))
		#expect(sequence.validSuccessor(pred: id("id-0"), succ: newest))
	}

	// MARK: - knownIDs / AuthCore.knows / validateMember

	/// Mutation: dropping any ONE of the three `knownIDs` sources (`history`,
	/// `authorizedNext`, `pinned`) makes exactly the corresponding element
	/// below missing from this set.
	@Test func knownIDsChainsAllThreeSources() throws {
		var sequence = PartySequence.seeded(id("history-id"))
		sequence.authorize(id("authorized-id"))
		sequence.pin(id("pinned-id"))
		#expect(
			Set(sequence.knownIDs)
				== Set([id("history-id"), id("authorized-id"), id("pinned-id")]))
	}

	@Test func validateMemberRejectsUnknownIdentity() throws {
		let auth = AuthCore(mine: .seeded(id("me")), theirs: .seeded(id("them")))
		#expect(throws: TwoMLSError.unknownIdentity) {
			try auth.validateMember(.basic(identity: id("stranger")))
		}
	}

	@Test func validateMemberAdmitsAuthorizedOnlyIdentity() throws {
		var auth = AuthCore(mine: .seeded(id("me")), theirs: .seeded(id("them")))
		auth.theirs.authorize(id("their-next"))
		#expect(throws: Never.self) {
			try auth.validateMember(.basic(identity: id("their-next")))
		}
	}

	@Test func validateMemberAdmitsPinnedEvictedIdentity() throws {
		var sequence = PartySequence.seeded(id("id-0"))
		for i in 1...PartySequence.credentialHistoryWindow {
			try sequence.commit(id("id-\(i)"))
		}
		#expect(!sequence.contains(id("id-0")))
		sequence.pin(id("id-0"))
		let auth = AuthCore(mine: .seeded(id("me")), theirs: sequence)
		#expect(throws: Never.self) {
			try auth.validateMember(.basic(identity: id("id-0")))
		}
	}

	@Test func validateMemberRejectsEvictedAndUnpinnedIdentity() throws {
		var sequence = PartySequence.seeded(id("id-0"))
		for i in 1...PartySequence.credentialHistoryWindow {
			try sequence.commit(id("id-\(i)"))
		}
		let auth = AuthCore(mine: .seeded(id("me")), theirs: sequence)
		#expect(throws: TwoMLSError.unknownIdentity) {
			try auth.validateMember(.basic(identity: id("id-0")))
		}
	}

	@Test func validateMemberRejectsUnsupportedCredentialType() throws {
		let auth = AuthCore(mine: .seeded(id("me")), theirs: .seeded(id("them")))
		#expect(throws: TwoMLSError.unsupportedCredential) {
			try auth.validateMember(
				.other(type: MLS.RFC9420.CredentialType(.x509), data: Data()))
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
	@Test func sameIdentifierIsAcceptedByDesignRegardlessOfKeyChange() throws {
		let sequence = PartySequence.seeded(id("stable-id"))
		#expect(sequence.validSuccessor(pred: id("stable-id"), succ: id("stable-id")))
	}

	// MARK: - API 1 (succeeding current) / forward gaps / backward rollback

	/// API 1 pins the predecessor to the head: an authorized successor of the
	/// current head is accepted; an older-than-head id is not (going back to it
	/// is not a succession); and there is nothing valid with no head.
	@Test func validSuccessorOfCurrentUsesTheHead() throws {
		var sequence = PartySequence.seeded(id("c0"))
		try sequence.commit(id("c1"))  // head = c1
		sequence.authorize(id("c2"))
		#expect(sequence.validSuccessorOfCurrent(id("c2")))
		#expect(!sequence.validSuccessorOfCurrent(id("c0")))  // older than head
		#expect(!PartySequence().validSuccessorOfCurrent(id("x")))  // no head
	}

	/// Forward gap: the app authorizes a far successor, skipping intermediates it
	/// never saw; both APIs accept it from the current head even though nothing
	/// between them entered `history`.
	@Test func forwardGapIsAcceptedWhenAuthorized() throws {
		var sequence = PartySequence.seeded(id("c0"))
		sequence.authorize(id("c3"))  // c1, c2 skipped
		#expect(sequence.validSuccessor(pred: id("c0"), succ: id("c3")))
		#expect(sequence.validSuccessorOfCurrent(id("c3")))
	}

	/// A backward move within the window is rejected — an older-in-history succ
	/// is not a successor of a newer pred.
	@Test func backwardMoveIsRejected() throws {
		var sequence = PartySequence.seeded(id("c0"))
		try sequence.commit(id("c1"))
		try sequence.commit(id("c2"))
		#expect(!sequence.validSuccessor(pred: id("c2"), succ: id("c0")))
	}

	// MARK: - validatePQLeafMove (§A.5 PQ leaf-move gate)

	/// `validatePQLeafMove`'s own cases, isolated from any PQ/session
	/// machinery: `c0 → c1 → c2` committed, `cand` merely authorized (not
	/// yet canonical), `ancient` pinned (evicted-but-held). Each pair below
	/// is chosen to fail if either half of "same-id, OR (canonical AND a
	/// valid successor)" is dropped.
	@Test func validatePQLeafMoveCases() throws {
		var sequence = PartySequence.seeded(id("c0"))
		try sequence.commit(id("c1"))
		try sequence.commit(id("c2"))
		sequence.authorize(id("cand"))
		sequence.pin(id("ancient"))

		// Same-id, even on a merely-PINNED (evicted) id — the early return
		// must admit this without ever consulting `history`. Mutation:
		// deleting the `oldID == newID` early return makes this throw
		// (`ancient` is absent from `history`).
		#expect(throws: Never.self) {
			try validatePQLeafMove(
				oldID: id("ancient"), newID: id("ancient"), in: sequence)
		}
		// An ordinary catch-up within `history`.
		#expect(throws: Never.self) {
			try validatePQLeafMove(oldID: id("c0"), newID: id("c2"), in: sequence)
		}
		// A catch-up from a pinned (evicted) predecessor.
		#expect(throws: Never.self) {
			try validatePQLeafMove(oldID: id("ancient"), newID: id("c1"), in: sequence)
		}

		// A rollback WITHIN history (`c2` → `c0`) and a move from an unknown
		// predecessor: `newID` is already canonical either way, so only the
		// `validSuccessor` conjunct catches them. Mutation: dropping
		// `validSuccessor` (keeping only `history.contains`) makes both
		// wrongly pass.
		#expect(throws: TwoMLSError.invalidSuccession) {
			try validatePQLeafMove(oldID: id("c2"), newID: id("c0"), in: sequence)
		}
		#expect(throws: TwoMLSError.invalidSuccession) {
			try validatePQLeafMove(oldID: id("unknown"), newID: id("c2"), in: sequence)
		}

		// A move to a merely-AUTHORIZED (not yet canonical) candidate is
		// exactly what `validSuccessor` alone would accept (its own
		// authorization shortcut), but a PQ leaf may only fast-forward to an
		// ALREADY-canonical id. Mutation: dropping the `history.contains`
		// conjunct (keeping only `validSuccessor`) makes this wrongly pass.
		#expect(throws: TwoMLSError.invalidSuccession) {
			try validatePQLeafMove(oldID: id("c0"), newID: id("cand"), in: sequence)
		}
		// An id neither committed nor authorized.
		#expect(throws: TwoMLSError.invalidSuccession) {
			try validatePQLeafMove(oldID: id("c0"), newID: id("nobody"), in: sequence)
		}
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
	@Test func adjudicateAcceptsAuthorizedRotationAndRejectsUnauthorizedOne() throws {
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
		let rawWelcome = creationSent.welcome
		let welcome = try #require(rawWelcome)
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
			Issue.record("expected a public proposal message")
			return
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
			}),
			case .credentialReplaced(let leaf, let old, let new) = credentialReplaced
		else {
			Issue.record("expected a credentialReplaced effect")
			return
		}
		#expect(leaf == bobLeaf)
		#expect(new.credential == newIdentity.credential)

		// `adjudicate`'s `.added` arm is real: the founding commit carries a
		// genuine `.added(bob)` `CredentialPresentation` (not a hand-built one).
		#expect(
			foundingEffects.events.contains {
				if case .added = $0 { return true }
				return false
			})

		// Accept: the rotated id was authorized in the AS beforehand. Also
		// exercises `adjudicate`'s `.added` arm (`validateMember(presentation:)`)
		// against the founding commit's real `CredentialPresentation`.
		// `myLeaf` = alice's own leaf index (`acceptingAuth`/etc.'s `mine`
		// is seeded from `alice.identity`): bob's leaf (the one that
		// actually moves, `bobLeaf`) is never it, so every `adjudicate`
		// call below correctly routes to `theirs`.
		let myLeaf = aliceGroup.myLeafIndex
		#expect(myLeaf != bobLeaf)

		var acceptingAuth = AuthCore(
			mine: .seeded(alice.identity), theirs: .seeded(bob.identity))
		acceptingAuth.theirs.authorize(rotated.identity)
		#expect(throws: Never.self) {
			try acceptingAuth.adjudicate(foundingEffects, myLeaf: myLeaf)
		}
		#expect(throws: Never.self) {
			try acceptingAuth.adjudicate(rotationEffects, myLeaf: myLeaf)
		}

		// Reject: a fresh AS that never authorized (or caught up to) the
		// rotated id — the profile already rejects a forged credential
		// before this AS ever sees it, so "unauthorized" here means an id
		// this AS's state never admits, not tampered bytes.
		let rejectingAuth = AuthCore(
			mine: .seeded(alice.identity), theirs: .seeded(bob.identity))
		#expect(throws: TwoMLSError.invalidSuccession) {
			try rejectingAuth.adjudicate(rotationEffects, myLeaf: myLeaf)
		}

		// Per-party adjudication: the moved leaf is BOB's (`theirs`), which
		// never authorized the rotated id — even though `mine` (alice, who
		// never even presents a leaf in this effect) DOES. Mutation:
		// restoring the old cross-party-OR check (`mine.validSuccessor(...)
		// || theirs.validSuccessor(...)`) makes this wrongly accept, since
		// `mine`'s own authorization would leak into a check that should
		// only ever consult the party whose leaf actually moved.
		var crossAuth = AuthCore(
			mine: .seeded(alice.identity), theirs: .seeded(bob.identity))
		// `mine.validSuccessor` gates its authorized-`succ` branch behind
		// `pred` being known to THAT sequence first — pristine sequences
		// never overlap in practice (each starts from its own owner's
		// distinct id), so this also hand-seeds `mine.history` with bob's
		// OLD (pre-rotation) id, standing in for however such overlap
		// could arise, to prove the isolation holds even then.
		crossAuth.mine.history.append(bob.identity)
		crossAuth.mine.authorize(rotated.identity)
		#expect(throws: TwoMLSError.invalidSuccession) {
			try crossAuth.adjudicate(rotationEffects, myLeaf: myLeaf)
		}

		// Lease successor-half: `old` IS the head (bob), yet a rotation to an
		// unauthorized `new` is still rejected — the lease checks BOTH `old ==
		// head` AND that `new` is a valid successor of it. Mutation: dropping the
		// `validSuccessorOfCurrent` half of the lease makes this pass wrongly.
		#expect(throws: TwoMLSError.invalidSuccession) {
			try rejectingAuth.validateSuccessionAgainstCurrent(old: old, new: new)
		}

		// Reject via the `.added` arm: an AS whose `theirs` never knew Bob's id
		// rejects the founding commit's `.added(bob)` — pins that `adjudicate`
		// validates added members, not only credential replacements. Mutation:
		// turning the `.added` case into `break` makes ONLY this assertion fail.
		let strangerAuth = AuthCore(
			mine: .seeded(alice.identity), theirs: .seeded(Data("not-bob".utf8)))
		#expect(throws: TwoMLSError.unknownIdentity) {
			try strangerAuth.adjudicate(foundingEffects, myLeaf: myLeaf)
		}

		// API 1 (lease) vs API 2 (explicit pred), on the SAME real effect. With
		// the peer's head still at `bob`, the lease accepts the rotation. Advance
		// the peer's head past `bob` and the lease (API 1) rejects a rotation
		// still built on `bob`, while API 2 accepts it as a gap-spanning handoff
		// from a known-but-not-current predecessor.
		#expect(throws: Never.self) {
			try acceptingAuth.validateSuccessionAgainstCurrent(old: old, new: new)
		}
		var movedOn = AuthCore(
			mine: .seeded(alice.identity), theirs: .seeded(bob.identity))
		try movedOn.theirs.commit(Data("bob-moved".utf8))
		movedOn.theirs.authorize(rotated.identity)
		#expect(throws: TwoMLSError.invalidSuccession) {
			try movedOn.validateSuccessionAgainstCurrent(old: old, new: new)
		}
		#expect(throws: Never.self) {
			try movedOn.validateSuccession(old: old, new: new, party: movedOn.theirs)
		}
	}

	// MARK: - pins(forPresented:) normal form (book group-rules.md rule 4)

	/// A presented id already in `history` is included in the pin set —
	/// behavior-neutral (`commit`/`validSuccessor` both special-case an
	/// in-history id ahead of ever consulting `pinned`), but the normal form
	/// includes it regardless, rather than special-casing it out. Mutation:
	/// subtracting `history` from `presented` (instead of only the candidate
	/// set) makes this fail.
	@Test func pinsForPresentedIncludesAnInHistoryID() throws {
		var sequence = PartySequence.seeded(id("a"))
		try sequence.commit(id("b"))
		#expect(sequence.pins(forPresented: [id("a")]) == [id("a")])
	}

	/// A presented id that is an authorized-but-not-yet-canonical candidate
	/// is EXCLUDED — pinning it would make `commit` reject its own
	/// canonicalization as a rollback. Mutation: dropping the
	/// `.subtracting(candidates)` step makes this fail.
	@Test func pinsForPresentedExcludesAnAuthorizedCandidate() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.authorize(id("candidate"))
		#expect(sequence.pins(forPresented: [id("candidate")]) == [])
	}

	/// An id nobody presents is never in the pin set, even if it was pinned
	/// before — the normal form is a pure function of `presented`, not an
	/// incremental update. Mutation: unioning with the sequence's own prior
	/// `pinned` (instead of deriving purely from `presented`) makes this
	/// fail.
	@Test func pinsForPresentedDropsAnIDNoLongerPresented() throws {
		var sequence = PartySequence.seeded(id("a"))
		sequence.pin(id("stale"))
		#expect(sequence.pins(forPresented: []) == [])
	}

	/// Sorted (lexicographic bytes) and deduplicated — the exact shape
	/// `SessionMigrationTests`'s minted-vs-native comparison relies on.
	/// Mutation: returning `Array(presented)` unsorted makes this fail
	/// (order-dependent on `Set`'s unspecified iteration).
	@Test func pinsForPresentedIsSortedAndDeduplicated() throws {
		let sequence = PartySequence.seeded(id("z"))
		let result = sequence.pins(forPresented: [id("z"), id("m"), id("a")])
		#expect(result == [id("a"), id("m"), id("z")])
	}
}
