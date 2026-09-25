// Differential wire-compat vectors against the deployed Rust reference: the Germ
// message-frame/proposal-section framing, the deployed uint32 (big-endian) ComponentID
// width the AppDataUpdate attestation proposal's body carries, and (d) a real fold-only
// commit staple.
//
// Golden hex captured from `two-mls-pq@c501f9d`, which pins `mls-rs-germ@b43703f` (the
// deployed pin) via `Cargo.toml` git `rev` — provider=cryptokit for (d), awslc for the
// rest. (a)-(c) are framing/structural, not cryptographic, so they are provider-
// independent; (d) is a captured artifact, see its own note below.
//
// Regeneration recipe — two temporary, uncommitted Rust tests:
//
// 1. Framing: a `#[cfg(test)] mod wire_vector_emitter` added to two-mls-pq's
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
// 3. (d) The fold-only commit staple: a temporary `#[test] fn` added to two-mls-pq's
//    `src/session/tests.rs` (in-crate, for access to the `pub(crate)` test harness and the
//    session's private `inner` field), containing:
//
//        #[test]
//        fn emit_fold_only_staple_vector() {
//            let (alice_session, bob_session) = establish_sessions();
//
//            assert_ok!(alice_session.prepare_to_encrypt(None));
//            let enc = assert_ok!(alice_session.encrypt(b"propose".to_vec()));
//            let result = assert_some!(assert_ok!(bob_session.process_incoming(enc.cipher_text)));
//
//            assert_ok!(bob_session.queue_proposal(assert_some!(result.proposal).digest));
//            assert_ok!(bob_session.prepare_to_encrypt(None));
//            let enc = assert_ok!(bob_session.encrypt(b"full".to_vec()));
//            assert_ok!(alice_session.process_incoming(enc.cipher_text));
//
//            let inner = bob_session.inner.lock().unwrap_or_else(|e| e.into_inner());
//            println!("fold_only_staple: {}", to_hex(&inner.current_staple));
//        }
//
//    Run with: cargo test -p two-mls-pq --features cryptokit emit_fold_only_staple_vector \
//        -- --nocapture
//
//    Unlike (a)-(c), this vector is a fold commit's actual wire bytes — signatures and HPKE
//    path secrets are freshly randomized every run, so it is captured once and pinned as a
//    fixed artifact, not re-derivable byte-for-byte from a Swift-side encode. The Swift test
//    only pins ACCEPTANCE: `decodeMlsMessageStaple` takes it whole and `stapleKind` dispatches
//    it as `.mlsMessage` — see `testFoldOnlyStapleAcceptsRealRustCommit` in
//    `RustWireVectorsTests.swift`.
//
// All four tests above are scratch-only regeneration recipes, never committed to the Rust
// repo — this comment is their durable record, mirroring `RustOracleVectors.swift`.
//
// This file is pure data; it is exempt from swift-format so the long hex literal
// (the full wrapped-proposal golden) does not trip the line-length rule.

// swift-format-ignore-file

enum RustWireVectors {
	// MARK: - (b) framing — `encode_message_frame(&[0xAA;3], vec![0xBB;5], vec![0xCC;7])`

	static let messageFrame = "0303000000aaaaaa05000000bbbbbbbbbb07000000cccccccccccccc"

	// (b) framing — `encode_proposal_section(&[0x11;4], &[0x22;6])`
	static let proposalSection = "0400000011111111222222222222"

	// (b) framing — a bare `push_section(&mut out, &[0x33;9])`
	static let pushSection = "09000000333333333333333333"

	// MARK: - (c)+(a) AppDataUpdate — `ApqInfoUpdate { t_epoch: 2, pq_epoch: 1 }`,
	// component id `APQ_COMPONENT_ID = 0xFF01`

	/// The mls-rs `CustomProposal`'s `.data()` — the BODY only, no outer wrapper:
	/// `component_id(uint32 BE) ‖ op(0x01) ‖ opaque update<V>`.
	static let appDataUpdateBody = "0000ff01011000000000000000020000000000000001"

	/// `Proposal::Custom(custom).mls_encode_to_vec()` — the FULL deployed-Rust wire
	/// bytes the port now reproduces byte-for-byte via `Proposal.custom(type:body:)`:
	/// `0x0008 ‖ VarInt(body.len) ‖ body`. One byte of length prefix here only because
	/// this body is 22 bytes (< 64, so the MLS VarInt is a single byte); a regenerated
	/// vector with a ≥64-byte body would carry a multi-byte prefix (see
	/// `testAppDataUpdateWrapperByteMatchesDeployedRust`).
	static let appDataUpdateFullWrapped =
		"0008160000ff01011000000000000000020000000000000001"

	// MARK: - (d) A real fold-only commit staple (Bob folding Alice's approved Update)

	/// `bob_session`'s `current_staple` immediately after folding Alice's approved
	/// Update into a commit — the bare `MLSMessage` bytes `two-mls-pq` staples with no
	/// wrapper tag (`session/messaging.rs`'s `current_staple = cl_commit`). Starts
	/// `00 01 00 01` (`mls10` ‖ `public_message`), 599 bytes. A captured artifact, not a
	/// re-derivable structural encode — see the regeneration recipe above.
	static let foldOnlyStaple =
		"0001000120d60491ff4cf3c876e6e2c555d88989c3acfc482ef9446275e3296a9ec9d6e387000000000000000101000000000003220220864892ddec930c2c8055eec8579cec1635934a5ecb494be54069291db5c7f50a0120cb0b22e2e3af2d9443aee1306a05d2efe871f8de86877abf5df375e13cf98d63205d97793777e9b31f66de11f8bf24817b848cfdc5faeed671041d41e065bd87ec0001404026e39f8de3585b0198d4a56f030067402e9a0e831b755146fb00cf01326ed89d69bb5a384ea7920555cce0c4bed26640f76b65a3ff1675502fb6cd490919871f0200010a0002000700050001000304f0a1f0a20200080200010320e2b5b6eecb73bb644f41adbee1c6f0f2b0b297025f3eb14c20b15999617f51e40040405df417e9eb03b086e5779bf622afac3e2708ded71458dbce0e60200659a4ed43470a00bee005051707a52612a2628fa9ffabd67bcba6c6f376b60c854b41410f40752033143f529830508d4ea973ba26f253b9026ef4034b0364edf6eba8ec1ab46f0840522037ee2df3f1b3ac14a9816652e3e7140b2e896dc89e8395c8a7eed3d24eb5af56308ff02d348344e33e1bca4c862f6328c3c361b7fa1f1df5e5ba97b1daa4035111fd7fdab2ae32d0de5ecc787af73d0ae94040e19114786dfdec71b23c6d47ad4b679996b7819650f541919386ba4e8996f5b35d452514edad1dbdfcaec574e89617c688527c9215c5e01cd4e2b5892c4c970020a81bfec8f8a8e491aeeb49ff0bd1e6cc161a16120380d10519dec3ff947c57a62054abcdb08a5e8a5078a717fb30a922ea004d78ab10ee23261c26cda3cb098188"
}
