import Foundation
import MLSCodec
import MLSProfileRFC9420

// MARK: - AppBinding (0xF0A2, group-rules.md rule 8)
//
// The optional app-supplied binding that welds a session to the app's
// IMMUTABLE relationship identity — distinct from `APQInfo` (which the
// combiner writes into both halves naming the pair itself), but carried the
// same way: a GroupContext extension, written once at creation into the
// classical halves only, riding the Welcome, and never rewritten (rule 1's
// GroupContextExtensions ban is what makes it immutable). The crate never
// interprets the bytes — the app owns the digest and its derivation (book
// carried-encodings.md, "The app binding is a derived equality").

/// `struct { opaque data<V>; } AppBinding` — a one-field byte-vec struct
/// matching the Rust reference's `AppBinding { data: Vec<u8> }` byte-for-byte
/// (`writeOpaque`/`readOpaque` and `mls_rs_codec::byte_vec` are the same
/// varint-length-prefixed `opaque<V>`), mirroring `MLS.Combiner.APQInfo`'s
/// own encode/read shape one level up.
struct AppBinding: Sendable, Equatable, MLSCodable {
	var data: Data

	init(data: Data) {
		self.data = data
	}

	func encode(to writer: inout MLS.Writer) throws {
		try writer.writeOpaque(data)
	}

	init(from reader: inout MLS.Reader) throws {
		data = Data(try reader.readOpaque())
	}
}

extension AppBinding {
	/// The `AppBinding` GroupContext extension type (RFC 9420 §17.3
	/// private-use range), the code point after `APQInfo`'s `0xF0A1` (book
	/// group-rules.md rule 8). Port-local: `MLS.Combiner.Codepoints` has no
	/// such field — every extension this module's groups carry rides the
	/// combiner's own opaque-carrying GroupContext extensions list, with no
	/// registration needed.
	static let extensionType = MLS.RFC9420.ExtensionType(rawValue: 0xF0A2)

	/// Wrap as an `MLS.RFC9420.Extension` — the GroupContext extension a
	/// bound classical half is created with (mirrors
	/// `MLS.Combiner.APQInfo.asExtension`).
	func asExtension() throws -> MLS.RFC9420.Extension {
		MLS.RFC9420.Extension(type: Self.extensionType, data: try mlsEncoded())
	}

	/// Read the `AppBinding` out of a GroupContext's extensions: `nil` when
	/// absent (an unbound group is valid — the extension is optional).
	/// Throws `.appBindingMismatch` — NEVER `nil` — when present but
	/// undecodable (truncation or trailing bytes) or when more than one
	/// `0xF0A2` extension is present: a corrupt or duplicated binding must
	/// never read back as "unbound" (mirrors `APQInfo.read`'s same rule for
	/// the truncation/trailing-bytes case).
	static func read(fromExtensionsOf context: MLS.RFC9420.GroupContext) throws -> Data? {
		let matches = context.extensions.filter { $0.type == extensionType }
		guard let ext = matches.first else { return nil }
		guard matches.count == 1 else { throw TwoMLSError.appBindingMismatch }
		do {
			var reader = MLS.Reader(ext.data)
			let binding = try AppBinding(from: &reader)
			try reader.finish()
			return binding.data
		} catch {
			throw TwoMLSError.appBindingMismatch
		}
	}
}

/// Verify a group's `AppBinding` against the binding the caller expects — an
/// exact, symmetric match: `Some(bytes)` must be carried equal, `None`
/// requires the group to carry none. Anything else (a stripped, unequal, or
/// present-but-unexpected binding) is `.appBindingMismatch` (mirrors Rust
/// `component.rs`'s `verify_app_binding`).
func verifyAppBinding(_ group: MLS.RFC9420.Group, expected: Data?) throws {
	guard try AppBinding.read(fromExtensionsOf: group.context) == expected else {
		throw TwoMLSError.appBindingMismatch
	}
}

/// Assert a PQ half carries NO `AppBinding` and no session profile record:
/// the binding lives on the classical (message) halves only — a PQ half
/// inherits coverage through the `APQInfo` half-binding, and this module
/// never reads a binding off one; the session profile is likewise a
/// classical-half-only signal (book group-rules.md rule 9: "PQ halves carry
/// none"). `nil` (a deferred, not-yet-founded PQ half) is vacuously fine —
/// there is nothing to check yet. Folds both checks into one function
/// (mirrors Rust `verify_pq_half_unbound`, which checks only the binding —
/// Rust never records a profile) since every call site already needs both.
func verifyPQHalfUnbound(_ pq: MLS.RFC9420.Group?) throws {
	guard let pq else { return }
	guard try AppBinding.read(fromExtensionsOf: pq.context) == nil else {
		throw TwoMLSError.appBindingMismatch
	}
	guard try SessionProfile.recorded(in: pq.context) == .deployedCompatible else {
		throw TwoMLSError.sessionProfileMismatch
	}
}

/// Port-side leaf-advert enforcement (swift-mls does NOT enforce mls-rs's
/// per-client GroupContext-extension leaf-capability requirement — every
/// occupied leaf this module creates already advertises `0xF0A2`
/// unconditionally via `TwoMLSIdentity.leafCapabilities`, but a PEER's key
/// package might not): when a group is about to be created carrying an
/// `AppBinding`, both the founder's own leaf and the added peer's leaf must
/// advertise the extension type — an old-capability key package cannot be
/// added to a binding-carrying group (mirrors Rust's
/// `test_binding_group_rejects_uncapable_key_package`).
func ensureAppBindingLeafAdvert(
	founder: MLS.RFC9420.LeafNode, peer: MLS.RFC9420.LeafNode
) throws {
	guard founder.capabilities.extensions.contains(AppBinding.extensionType),
		peer.capabilities.extensions.contains(AppBinding.extensionType)
	else {
		throw TwoMLSError.appBindingLeafUnadvertised
	}
}

/// The join-side counterpart: the CREATOR leaf actually occupying a joined,
/// binding-carrying group's tree — read as cryptographic fact, never a
/// caller-supplied claim (this module's usual AS-binding pattern) — must
/// advertise the extension type too, in case the peer's own establishment-
/// side check was skipped or predates this cut.
func ensureAppBindingCreatorLeafAdvert(_ creator: MLS.RFC9420.LeafNode) throws {
	guard creator.capabilities.extensions.contains(AppBinding.extensionType) else {
		throw TwoMLSError.appBindingLeafUnadvertised
	}
}
