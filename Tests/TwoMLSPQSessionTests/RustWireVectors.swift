// Differential wire-compat vectors against the deployed Rust reference: the §7 Germ
// message-frame/proposal-section framing, and the deployed uint32 (big-endian)
// ComponentID width the AppDataUpdate attestation proposal's body carries.
//
// Golden hex captured from `two-mls-pq@c501f9d`, which pins `mls-rs-germ@b43703f` (the
// deployed pin) via `Cargo.toml` git `rev` — provider=awslc. All three quantities here
// are framing/structural, not cryptographic, so they are provider-independent.
//
// Regeneration recipe — two temporary, uncommitted Rust tests:
//
// 1. §7 framing: a `#[cfg(test)] mod wire_vector_emitter` added to two-mls-pq's
//    `src/session/frames.rs` (the encoders are `pub(crate)`, so this must be an in-crate
//    test), containing:
//
//        #[test]
//        fn emit_wire_vectors() {
//            let frame = encode_message_frame(&[0xAA; 3], vec![0xBB; 5], vec![0xCC; 7]);
//            println!("encode_message_frame: {}", to_hex(&frame));
//
//            let section = encode_proposal_section(&[0x11; 4], &[0x22; 6]);
//            println!("encode_proposal_section: {}", to_hex(&section));
//
//            let mut out = Vec::new();
//            push_section(&mut out, &[0x33; 9]);
//            println!("push_section: {}", to_hex(&out));
//        }
//
//    (`to_hex` is a one-line `bytes.iter().map(|b| format!("{b:02x}")).collect()` helper
//    in the same module.) Run with:
//        cargo test -p two-mls-pq --features awslc emit_wire_vectors -- --nocapture
//
// 2. AppDataUpdate body + uint32 width: an `apq/tests/wire_vector_emitter.rs`
//    integration test (`ApqInfoUpdate::to_custom_proposal` is `pub`):
//
//        #[test]
//        fn emit_app_data_update_vectors() {
//            let update = ApqInfoUpdate { t_epoch: 2, pq_epoch: 1 };
//            let custom = update.to_custom_proposal().unwrap();
//            println!("proposal_type: {:#06x}", custom.proposal_type().raw_value());
//            println!("body (custom.data()): {}", to_hex(custom.data()));
//            let full = Proposal::Custom(custom).mls_encode_to_vec().unwrap();
//            println!("full wrapped proposal: {}", to_hex(&full));
//        }
//
//    Run with: cargo test -p apq --test wire_vector_emitter -- --nocapture
//    (the `apq` crate's tests need no provider feature on macOS — awslc is an
//    unconditional dev-dependency and cryptokit is auto-added there; these bytes
//    are provider-independent regardless.)
//
// Both tests are scratch-only regeneration recipes, never committed to the Rust repo —
// this comment is their durable record, mirroring `RustOracleVectors.swift`.
//
// This file is pure data; it is exempt from swift-format so the long hex literal
// (the full wrapped-proposal golden) does not trip the line-length rule.

// swift-format-ignore-file

enum RustWireVectors {
	// MARK: - (b) §7 framing — `encode_message_frame(&[0xAA;3], vec![0xBB;5], vec![0xCC;7])`

	static let messageFrame = "0303000000aaaaaa05000000bbbbbbbbbb07000000cccccccccccccc"

	// (b) §7 framing — `encode_proposal_section(&[0x11;4], &[0x22;6])`
	static let proposalSection = "0400000011111111222222222222"

	// (b) §7 framing — a bare `push_section(&mut out, &[0x33;9])`
	static let pushSection = "09000000333333333333333333"

	// MARK: - (c)+(a) AppDataUpdate — `ApqInfoUpdate { t_epoch: 2, pq_epoch: 1 }`,
	// component id `APQ_COMPONENT_ID = 0xFF01`

	/// The mls-rs `CustomProposal`'s `.data()` — the BODY only, no outer wrapper:
	/// `component_id(uint32 BE) ‖ op(0x01) ‖ opaque update<V>`.
	static let appDataUpdateBody = "0000ff01011000000000000000020000000000000001"

	/// `Proposal::Custom(custom).mls_encode_to_vec()` — the FULL deployed-Rust wire
	/// bytes: `0x0008 ‖ VarInt(body.len) ‖ body`. Diverges from swift's spec-correct
	/// bare `0x0008 ‖ body` by exactly the VarInt length prefix — one byte here only
	/// because this body is 22 bytes (< 64, so the MLS VarInt is a single byte); a
	/// regenerated vector with a ≥64-byte body would carry a multi-byte prefix (see
	/// `testAppDataUpdateWrapperDivergesFromDeployedRustPendingUpstreamSeam`).
	static let appDataUpdateFullWrapped =
		"0008160000ff01011000000000000000020000000000000001"
}
