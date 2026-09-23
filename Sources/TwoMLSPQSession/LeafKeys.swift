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
	/// its stored key set's `current` — fail-closed, `.credentialUnknown`.
	/// Checks only existing groups (a reservation names no leaf yet, so
	/// there is nothing to compare it against); costs at most four own-leaf
	/// `LeafNode` decodes and byte compares, no crypto, and never decodes a
	/// proposal.
	func assertLeafKeysPresented() throws {
		if let send = sendGroup {
			try Self.assertPresented(leafKeys.sendClassical, in: send.classical)
			if let sendPQGroup = send.pq {
				try Self.assertPresented(leafKeys.sendPQ, in: sendPQGroup)
			}
		}
		if let recv = recvGroup {
			try Self.assertPresented(leafKeys.recvClassical, in: recv.classical)
			if let recvPQGroup = recv.pq {
				try Self.assertPresented(leafKeys.recvPQ, in: recvPQGroup)
			}
		}
	}

	private static func assertPresented(_ set: GroupKeySet, in group: MLS.RFC9420.Group) throws
	{
		guard let current = set.current else { throw TwoMLSError.credentialUnknown }
		guard try ownLeaf(of: group).signatureKey == current.signatureKey else {
			throw TwoMLSError.credentialUnknown
		}
	}
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
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider
	) throws {
		// Check 2: every EXISTING group presents its own `current`.
		if let send = sendGroup {
			try requirePresented(leafKeys.sendClassical, in: send.classical)
			if let sendPQGroup = send.pq {
				try requirePresented(leafKeys.sendPQ, in: sendPQGroup)
				// Nothing in this version ever stages a send-PQ pending
				// entry (PQ has no rotation-candidate arm) — a non-empty
				// one could only be a leftover or a smuggled, unresolvable
				// entry, never a meaningful in-flight offer.
				guard leafKeys.sendPQ.pending.isEmpty else {
					throw TwoMLSError.archiveInvalid
				}
			}
		}
		if let recv = recvGroup {
			try requirePresented(leafKeys.recvClassical, in: recv.classical)
			if let recvPQGroup = recv.pq {
				try requirePresented(leafKeys.recvPQ, in: recvPQGroup)
			}
		}

		// Check 3: reservations for every group that does NOT exist yet.
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

		// Check 5: every current-epoch OWN Update names `current` or
		// `pending[its leaf id]` — `stagedUpdates`/`pendingProposal` against
		// recv-classical, a parked Upd′ against recv-PQ.
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
			if let recvPQGroup = recv.pq {
				if case .rekeyInitiated(let updMessage) = pqInflight {
					if let (targetID, signatureKey) = try? decodedUpdateTarget(
						updMessage, against: recvPQGroup,
						provider: pqProvider)
					{
						guard
							leafKeys.recvPQ.current?.signatureKey
								== signatureKey
								|| leafKeys.recvPQ.pending[
									targetID]?
									.signatureKey
									== signatureKey
						else { throw TwoMLSError.archiveInvalid }
					}
				} else {
					// No Upd′ parked to justify a recv-PQ pending entry — the
					// only thing that ever stages one is a parked §A.5 Upd′
					// (`.rekeyInitiated`); a non-empty `pending` under any
					// other `pqInflight` is a leftover or smuggled entry, not
					// a meaningful in-flight offer.
					guard leafKeys.recvPQ.pending.isEmpty else {
						throw TwoMLSError.archiveInvalid
					}
				}
			}
		}

		// Check 6: whenever a candidate is outstanding, the send leaf not
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

		// Check 7: a lagging born-dedicated recv leaf has
		// `pending[identity.clientID]`.
		if let recvLeafPrincipal, let recv = recvGroup {
			let recvID = try basicIdentifier(
				Self.ownLeaf(of: recv.classical).credential)
			if recvID == recvLeafPrincipal.clientID, recvID != auth.mine.current {
				guard leafKeys.recvClassical.pending[identity.clientID] != nil
				else {
					throw TwoMLSError.archiveInvalid
				}
			}
		}
	}

	private static func requirePresented(_ set: GroupKeySet, in group: MLS.RFC9420.Group) throws
	{
		guard let current = set.current else { throw TwoMLSError.archiveInvalid }
		guard try Self.ownLeaf(of: group).signatureKey == current.signatureKey else {
			throw TwoMLSError.archiveInvalid
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
