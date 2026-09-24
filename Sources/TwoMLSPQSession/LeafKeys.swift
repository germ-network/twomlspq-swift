import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420

// MARK: - Stored signing keys, by role
//
// Each of a session's four groups (send-classical, recv-classical, send-PQ,
// recv-PQ) owns a stored key set: `current` is the key its own leaf
// presents right now, `pending[target]` is a key minted for a credential id
// that leaf does not present YET. This is the ONLY source of a group's
// signing secrets — signing reads the slot directly, never identity, a
// rotation candidate, or the retained recv-leaf custody, which stay for
// persistence/migration/the test oracle only (see TwoMLSSession.swift).

/// One leaf's own signing keypair.
struct LeafKey: Sendable {
	let signingKey: MLS.SignatureSecretKey
	let signatureKey: MLS.SignaturePublicKey
}

/// One group's own stored key set.
struct GroupKeySet: Sendable {
	var current: LeafKey? = nil
	var pending: [Data: LeafKey] = [:]

	/// Stage `key` for `target`, idempotently: re-staging the SAME key
	/// (compared by signature key — the two secrets of a real pair always
	/// agree with it) for a target that already holds one is a no-op. A
	/// DIFFERENT key for an already-held target throws `.rotationInFlight` —
	/// a key a proposal already on the wire may still name is never
	/// silently overwritten.
	mutating func stage(_ key: LeafKey, for target: Data) throws {
		if let existing = pending[target] {
			guard existing.signatureKey == key.signatureKey else {
				throw TwoMLSError.rotationInFlight
			}
			return
		}
		pending[target] = key
	}

	/// The leaf now presents `signatureKey`, under credential id `id`. If
	/// that's already `current`, nothing changes (idempotent — a peer-only
	/// fold that never touched this leaf's own presentation lands here
	/// harmlessly). If it's `pending[id]`, that entry is promoted to
	/// `current` and removed from `pending`. Any other presentation is
	/// `.credentialUnknown` — this set holds no key for it, which must never
	/// happen for a leaf this session's own signing sites actually control.
	mutating func promoted(presenting signatureKey: MLS.SignaturePublicKey, id: Data) throws {
		if let current, current.signatureKey == signatureKey { return }
		guard let staged = pending[id], staged.signatureKey == signatureKey else {
			throw TwoMLSError.credentialUnknown
		}
		current = staged
		pending[id] = nil
	}
}

/// The four groups' own stored key sets — `TwoMLSSession.leafKeys`'s value
/// type. Seeded at `initiate`/`receive`/the §A.3 bootstrap; every signing
/// site reads a slot here directly (`TwoMLSSession.swift`'s
/// `send`/`recv` `Classical`/`PQ` `SigningKey()` accessors).
struct LeafKeys: Sendable {
	var sendClassical: GroupKeySet
	var recvClassical: GroupKeySet
	var sendPQ: GroupKeySet
	var recvPQ: GroupKeySet
}

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// The live choke-point check (`StateUpdate.swift`'s `stateUpdate(kind:)`
	/// choke point): every EXISTING group's own leaf must currently present
	/// its stored key set's `current` — fail-closed, `.credentialUnknown`,
	/// UNLESS its role is in `noCustody` (step 3), in which case a nil
	/// `current` is tolerated. Step 3: first runs the monotone `noCustody`
	/// drain — any role whose set now genuinely has a `current` (a
	/// promotion since the flag was set, at any of the several promotion
	/// call sites, none of which touch `noCustody` themselves) is dropped
	/// here, at the one choke point every state-advancing call already
	/// passes through — this is how the flag "clears on promotion" without
	/// hunting down every promotion site individually. Checks only existing
	/// groups (a reservation names no leaf yet, so there is nothing to
	/// compare it against); costs at most four own-leaf `LeafNode` decodes
	/// and byte compares, no crypto, and never decodes a proposal.
	mutating func assertLeafKeysPresented() throws {
		if leafKeys.sendClassical.current != nil { noCustody.remove(.sendClassical) }
		if leafKeys.recvClassical.current != nil { noCustody.remove(.recvClassical) }
		if leafKeys.sendPQ.current != nil { noCustody.remove(.sendPQ) }
		if leafKeys.recvPQ.current != nil { noCustody.remove(.recvPQ) }

		if let send = sendGroup {
			try Self.assertPresented(
				leafKeys.sendClassical, in: send.classical,
				noCustody: noCustody.contains(.sendClassical))
			if let sendPQGroup = send.pq {
				try Self.assertPresented(
					leafKeys.sendPQ, in: sendPQGroup,
					noCustody: noCustody.contains(.sendPQ))
			}
		}
		if let recv = recvGroup {
			try Self.assertPresented(
				leafKeys.recvClassical, in: recv.classical,
				noCustody: noCustody.contains(.recvClassical))
			if let recvPQGroup = recv.pq {
				try Self.assertPresented(
					leafKeys.recvPQ, in: recvPQGroup,
					noCustody: noCustody.contains(.recvPQ))
			}
		}
	}

	private static func assertPresented(
		_ set: GroupKeySet, in group: MLS.RFC9420.Group, noCustody: Bool
	) throws {
		guard let current = set.current else {
			guard noCustody else { throw TwoMLSError.credentialUnknown }
			return
		}
		guard try ownLeaf(of: group).signatureKey == current.signatureKey else {
			throw TwoMLSError.credentialUnknown
		}
	}
}

/// Which caller context is validating `leafKeys` — step 3 widens
/// `validateLeafKeys` (previously restore-only) to also run at mint, where
/// two further modes apply. `.restore` is the default so every pre-step-3
/// call site (and every existing test) keeps its exact prior behavior.
enum LeafKeysValidationMode: Equatable {
	/// `TwoMLSSession.restore`.
	case restore
	/// `SessionMigration.mintArchive` on the temporary owner-keyed
	/// `convertDeployedKeys` fallback (`parts.leafKeys == nil`).
	case mintConverted
	/// `SessionMigration.mintArchive`/`mintOwnOfferWindow` on a caller-
	/// supplied `MigratedLeafKeys` (`parts.leafKeys != nil`).
	case mintSupplied
}

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// What restore and the migration mint validate about `leafKeys`
	/// against everything else the restored/minted state describes. Every
	/// failure is `.archiveInvalid`. Callers supply already-restored native
	/// values (not archive types) — `LeafKeysArchive.restore()` (called
	/// before this) already ran the archive-level checks (every key
	/// derives; every pending target non-empty/unique); this covers the
	/// semantic ones. Staged proposals are decoded only here, matching
	/// `rebuildStagedProposalStore`'s own skip-on-any-failure treatment:
	/// skip, never reject, a foreign-group/undecodable/non-`PublicMessage`/
	/// non-`.update` entry — a verification failure also transparently
	/// skips a stale-epoch entry, since `verifying` itself is epoch-checked.
	///
	/// Step 3 additions: `mode`/`noCustody` widen check 3 (an existing
	/// group's `current` may legitimately be `nil` when its role is in
	/// `noCustody`) and generalize check 7 (any lagging own leaf, not only a
	/// rotation candidate or the retained born-dedicated custody, needs
	/// `pending[mine.current]` — see `isRotationCandidateOutstanding`'s
	/// sibling doc, `TwoMLSSession+ClassicalCommit.swift`'s
	/// `ownLeafCatchUpTarget`). All three default to the pre-step-3 shape
	/// (`.restore`, empty `noCustody`) so no other call site changes.
	static func validateLeafKeys(
		_ leafKeys: LeafKeys,
		sendGroup: APQGroup?, recvGroup: APQGroup?,
		identity: TwoMLSIdentity,
		bootstrapKPSecret:
			(
				leafSecretKey: MLS.HpkeSecretKey, initSecretKey: MLS.HpkeSecretKey,
				keyPackage: MLS.RFC9420.KeyPackage
			)?,
		stagedUpdates: [(digest: Data, message: Data)],
		pendingProposal: (proposing: Data, message: Data, hash: Data)?,
		pqInflight: PQInflight?,
		rotationCandidate: RotationCandidate?,
		recvLeafPrincipal: RecvLeafPrincipal?,
		auth: AuthCore,
		mode: LeafKeysValidationMode = .restore,
		noCustody: Set<MigratedGroupRole> = [],
		windowTargets: [(id: Data, signatureKey: MLS.SignaturePublicKey)] = [],
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws {
		// Check 3: every EXISTING group presents its own `current`, UNLESS
		// its role is in `noCustody` (step 3) — in which case `current` must
		// be `nil`. `noCustody` must name exactly the existing groups whose
		// `current` is nil: a role listed there whose `current` is actually
		// present is as inconsistent as an un-listed group with a nil one
		// (and, since only `.mintSupplied`/restore ever populate a nil
		// `current` in the first place, a non-empty `noCustody` under
		// `.mintConverted` always fails here — conversion never produces
		// one).
		var actualNoCustody: Set<MigratedGroupRole> = []
		if let send = sendGroup {
			try requirePresented(
				leafKeys.sendClassical, in: send.classical, role: .sendClassical,
				noCustody: noCustody, actual: &actualNoCustody)
			if let sendPQGroup = send.pq {
				try requirePresented(
					leafKeys.sendPQ, in: sendPQGroup, role: .sendPQ,
					noCustody: noCustody, actual: &actualNoCustody)
			}
		}
		if let recv = recvGroup {
			try requirePresented(
				leafKeys.recvClassical, in: recv.classical, role: .recvClassical,
				noCustody: noCustody, actual: &actualNoCustody)
			if let recvPQGroup = recv.pq {
				try requirePresented(
					leafKeys.recvPQ, in: recvPQGroup, role: .recvPQ,
					noCustody: noCustody, actual: &actualNoCustody)
			}
		}
		guard actualNoCustody == noCustody else { throw TwoMLSError.archiveInvalid }

		// Check 4: reservations for every group that does NOT exist yet.
		if recvGroup == nil {
			guard leafKeys.recvClassical.pending.isEmpty,
				leafKeys.recvClassical.current?.signatureKey
					== identity.keyPackage.classical.leafNode.signatureKey
			else { throw TwoMLSError.archiveInvalid }
		}
		if recvGroup?.pq == nil {
			guard leafKeys.recvPQ.pending.isEmpty else {
				throw TwoMLSError.archiveInvalid
			}
			// The torn state (Bootstrap.swift: `bootstrapKPSecret` cleared
			// before the throwing export) accepts any key here — there is
			// no longer a KP′ to compare against.
			if let bootstrapKPSecret {
				guard
					leafKeys.recvPQ.current?.signatureKey
						== bootstrapKPSecret.keyPackage.leafNode
						.signatureKey
				else { throw TwoMLSError.archiveInvalid }
			}
		}
		if sendGroup?.pq == nil, sendGroup != nil {
			guard leafKeys.sendPQ.pending.isEmpty,
				leafKeys.sendPQ.current?.signatureKey
					== identity.keyPackage.pq.leafNode.signatureKey
			else { throw TwoMLSError.archiveInvalid }
		}

		// Check 6: every current-epoch OWN Update names `current` or
		// `pending[its leaf id]` — `stagedUpdates`/`pendingProposal` (and,
		// at mint, the window's own targets — an O(1) dictionary lookup)
		// against recv-classical, a parked Upd′ against recv-PQ. A
		// no-custody group has no `current` to match, so this already forces
		// such a target into `pending` with no special-casing.
		if let recv = recvGroup {
			var ownClassicalProposals = stagedUpdates.map { $0.message }
			if let pendingProposal {
				ownClassicalProposals.append(pendingProposal.message)
			}
			for message in ownClassicalProposals {
				guard
					let (targetID, signatureKey) = try? decodedUpdateTarget(
						message, against: recv.classical,
						provider: classicalProvider)
				else { continue }
				guard
					leafKeys.recvClassical.current?.signatureKey == signatureKey
						|| leafKeys.recvClassical.pending[targetID]?
							.signatureKey
							== signatureKey
				else { throw TwoMLSError.archiveInvalid }
			}
			for (targetID, signatureKey) in windowTargets {
				guard
					leafKeys.recvClassical.current?.signatureKey == signatureKey
						|| leafKeys.recvClassical.pending[targetID]?
							.signatureKey == signatureKey
				else { throw TwoMLSError.archiveInvalid }
			}
			if let recvPQGroup = recv.pq {
				// Step 3 (generalized rule 7, PQ arm): a lagging recv-PQ own
				// leaf's `pending[mine.current]` is allowed independent of
				// `pqInflight` — the retained catch-up entry
				// (`TwoMLSSession+Rekey.swift`'s post-apply retention)
				// survives across restore with no round outstanding. The
				// parked `.rekeyInitiated` Upd′'s own target is allowed too,
				// WHATEVER id it names — a parked Upd′ staged before a later
				// classical rotation may still target a now-historical id
				// (a classical canonicalization never clears recv-PQ
				// pending, and an in-flight Upd′ is never re-minted), so
				// this is never restricted to `{mine.current} ∪
				// authorizedNext` (that restriction is classical-only,
				// check 8).
				let ownPQID = try basicIdentifier(
					Self.ownLeaf(of: recvPQGroup).credential)
				var allowed: [Data: MLS.SignaturePublicKey] = [:]
				if let mineCurrent = auth.mine.current, ownPQID != mineCurrent,
					let key = leafKeys.recvPQ.pending[mineCurrent]
				{
					allowed[mineCurrent] = key.signatureKey
				}
				if case .rekeyInitiated(let updMessage) = pqInflight,
					let (targetID, signatureKey) = try? decodedUpdateTarget(
						updMessage, against: recvPQGroup,
						provider: pqProvider)
				{
					allowed[targetID] = signatureKey
				}
				for (target, key) in leafKeys.recvPQ.pending {
					guard allowed[target] == key.signatureKey else {
						throw TwoMLSError.archiveInvalid
					}
				}
			}
		}
		// send-PQ's own pending is never meaningful except the same
		// generalized rule-7 catch-up entry (step 3) — PQ has no
		// rotation-candidate arm of its own, so any OTHER entry is a
		// leftover or a smuggled, unresolvable key.
		if let send = sendGroup, let sendPQGroup = send.pq {
			let ownSendPQID = try basicIdentifier(
				Self.ownLeaf(of: sendPQGroup).credential)
			var allowed: [Data: MLS.SignaturePublicKey] = [:]
			if let mineCurrent = auth.mine.current, ownSendPQID != mineCurrent,
				let key = leafKeys.sendPQ.pending[mineCurrent]
			{
				allowed[mineCurrent] = key.signatureKey
			}
			for (target, key) in leafKeys.sendPQ.pending {
				guard allowed[target] == key.signatureKey else {
					throw TwoMLSError.archiveInvalid
				}
			}
		}

		// Check 8: whenever a candidate is outstanding, the send leaf not
		// yet presenting it needs
		// `sendClassical.pending[C]` REGARDLESS of whether the candidate has
		// canonicalized; an UNCANONICAL candidate additionally needs
		// `recvClassical.pending[C]` (the offer awaiting the peer's fold).
		if let candidate = rotationCandidate {
			let sendPresentsCandidate =
				try sendGroup.map {
					try basicIdentifier(
						Self.ownLeaf(of: $0.classical).credential)
						== candidate.clientID
				} ?? false
			if !sendPresentsCandidate {
				guard leafKeys.sendClassical.pending[candidate.clientID] != nil
				else {
					throw TwoMLSError.archiveInvalid
				}
			}
			if isRotationCandidateOutstanding(
				candidate.clientID, mineHistory: auth.mine.history)
			{
				guard leafKeys.recvClassical.pending[candidate.clientID] != nil
				else {
					throw TwoMLSError.archiveInvalid
				}
			}
		}
		// S-3 (step 3, `.mintSupplied` only — CLASSICAL only, never PQ: a
		// recv-PQ pending target may legitimately be a historical id the
		// classical AS no longer tracks, per check 6 above): every classical
		// pending target is plausible (`{mine.current} ∪ authorizedNext`),
		// and every candidate target (a pending target ≠ `mine.current`)
		// carries the SAME key in both classical sets, matching
		// `rotationCandidate`'s own key when it names that target. Does NOT
		// require every `authorizedNext` id to have a live pending entry —
		// `authorizedNext` may outlive its candidate (see the type's own
		// doc, `CredentialAuthentication.swift`).
		if mode == .mintSupplied {
			try requireMintSuppliedRotationShape(
				leafKeys, auth: auth, rotationCandidate: rotationCandidate)
		}

		// Check 7: any existing own leaf whose credential lags
		// `auth.mine.current` needs `pending[mine.current]` in that group —
		// classical, in every mode; PQ, only in `.mintSupplied` (native
		// sessions mint no PQ catch-up key until a later step's per-move
		// keys land, and a migrated session converted through the temporary
		// owner-keyed fallback can't always supply one either).
		if let recv = recvGroup {
			try requireCatchUpTargetIfLagging(
				leafKeys.recvClassical, in: recv.classical,
				mineCurrent: auth.mine.current,
				required: true)
			if let recvPQGroup = recv.pq {
				try requireCatchUpTargetIfLagging(
					leafKeys.recvPQ, in: recvPQGroup,
					mineCurrent: auth.mine.current,
					required: mode == .mintSupplied)
			}
		}
		if let send = sendGroup {
			try requireCatchUpTargetIfLagging(
				leafKeys.sendClassical, in: send.classical,
				mineCurrent: auth.mine.current,
				required: true)
			if let sendPQGroup = send.pq {
				try requireCatchUpTargetIfLagging(
					leafKeys.sendPQ, in: sendPQGroup,
					mineCurrent: auth.mine.current,
					required: mode == .mintSupplied)
			}
		}
	}

	private static func requirePresented(
		_ set: GroupKeySet, in group: MLS.RFC9420.Group, role: MigratedGroupRole,
		noCustody: Set<MigratedGroupRole>, actual: inout Set<MigratedGroupRole>
	) throws {
		guard let current = set.current else {
			actual.insert(role)
			guard noCustody.contains(role) else { throw TwoMLSError.archiveInvalid }
			return
		}
		guard try Self.ownLeaf(of: group).signatureKey == current.signatureKey else {
			throw TwoMLSError.archiveInvalid
		}
	}

	/// Check 7 (generalized catch-up): does `set`'s own leaf (read off
	/// `group`'s tree) lag `mineCurrent`? If so and `required`, it must hold
	/// `pending[mineCurrent]`; if so and NOT `required`, nothing is enforced
	/// (a native or `.mintConverted`/`.restore` PQ session may simply have
	/// no catch-up key yet — step 5's self-drive is what would consume one
	/// if supplied). A leaf that does not lag needs nothing here regardless.
	private static func requireCatchUpTargetIfLagging(
		_ set: GroupKeySet, in group: MLS.RFC9420.Group, mineCurrent: Data?, required: Bool
	) throws {
		guard required, let mineCurrent else { return }
		let ownID = try basicIdentifier(Self.ownLeaf(of: group).credential)
		guard ownID != mineCurrent else { return }
		guard set.pending[mineCurrent] != nil else { throw TwoMLSError.archiveInvalid }
	}

	/// S-3's `.mintSupplied`-only companion to check 8 — see that check's
	/// call site for the exact rule. CLASSICAL sets only.
	private static func requireMintSuppliedRotationShape(
		_ leafKeys: LeafKeys, auth: AuthCore, rotationCandidate: RotationCandidate?
	) throws {
		guard let mineCurrent = auth.mine.current else { throw TwoMLSError.archiveInvalid }
		let allowedTargets = Set(auth.mine.authorizedNext).union([mineCurrent])
		for target in leafKeys.sendClassical.pending.keys {
			guard allowedTargets.contains(target) else {
				throw TwoMLSError.archiveInvalid
			}
		}
		for target in leafKeys.recvClassical.pending.keys {
			guard allowedTargets.contains(target) else {
				throw TwoMLSError.archiveInvalid
			}
		}
		let sendCandidates = leafKeys.sendClassical.pending.filter { $0.key != mineCurrent }
		let recvCandidates = leafKeys.recvClassical.pending.filter { $0.key != mineCurrent }
		let candidateTargets = Set(sendCandidates.keys).union(recvCandidates.keys)
		for target in candidateTargets {
			guard let sendKey = sendCandidates[target]?.signatureKey,
				let recvKey = recvCandidates[target]?.signatureKey,
				sendKey == recvKey
			else { throw TwoMLSError.archiveInvalid }
			if let rotationCandidate, rotationCandidate.clientID == target {
				guard rotationCandidate.signatureKey == sendKey else {
					throw TwoMLSError.archiveInvalid
				}
			}
		}
	}

	/// Decode `message` as a `PublicMessage` `.update` proposal that verifies
	/// against `group` (mirrors `rebuildStagedProposalStore`'s decode
	/// shape), and return the id/key it names. Any failure — wrong shape,
	/// wrong epoch, a bad signature, a foreign group — throws, so every
	/// caller here treats it as "skip this entry" via `try?`.
	static func decodedUpdateTarget(
		_ message: Data, against group: MLS.RFC9420.Group,
		provider: any MLS.CipherSuiteProvider
	) throws -> (id: Data, signatureKey: MLS.SignaturePublicKey) {
		try withDeployedWireConventions {
			guard
				case .publicMessage(let updatePub) = try MLS.RFC9420.Message(
					mlsEncoded: message)
			else {
				throw TwoMLSError.archiveInvalid
			}
			let verified = try group.verifying(provider, proposal: updatePub)
			guard case .update(let leafNode) = verified.proposal else {
				throw TwoMLSError.archiveInvalid
			}
			let id = try basicIdentifier(leafNode.credential)
			return (id, leafNode.signatureKey)
		}
	}
}

/// The ONE predicate for "is a rotation candidate still outstanding" —
/// canonical-ness is defined entirely by `mine.history` (native `AuthCore`
/// or migrated `MigratedAuth` alike — both expose the same `[Data]`
/// shape), never by what a tree happens to present right now (which is a
/// derived, possibly lagging, consequence of that same commit). Used
/// consistently by check 6 above, `updateRecvClassicalKeys`'s post-apply
/// retention (ClassicalCommit.swift), and the migration converter's own
/// recv-side gate (SessionMigration.swift).
func isRotationCandidateOutstanding(_ candidateID: Data, mineHistory: [Data]) -> Bool {
	!mineHistory.contains(candidateID)
}

extension GroupKeySet {
	/// recv-classical's post-apply retention rule, run once per epoch
	/// advance (`applyFoldCommit`/`applyBind`'s own success point, AFTER
	/// this set's own presentation has already been promoted for that same
	/// apply): a `pending[t]` entry survives only while `t` is still LIVE —
	/// the outstanding rotation candidate (not yet canonicalized), or the
	/// rule-4 catch-up target — never merely because some now-stale own
	/// proposal named it. A target the leaf itself now presents is never
	/// examined here at all: promotion already removed it from `pending`
	/// before this runs, so retention only ever prunes a target the leaf
	/// still lacks.
	mutating func retainRecvClassical(
		candidateID: Data?, candidateCanonicalized: Bool, ruleFourTarget: Data?
	) {
		pending = pending.filter { target, _ in
			if let candidateID, target == candidateID, !candidateCanonicalized {
				return true
			}
			if let ruleFourTarget, target == ruleFourTarget {
				return true
			}
			return false
		}
	}
}
