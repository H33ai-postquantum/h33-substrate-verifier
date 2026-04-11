//! End-to-end integration tests.
//!
//! These live in `tests/` rather than `src/` so they exercise the
//! crate's public API exactly as a downstream consumer would — if a
//! test here breaks because a type went private, that's a signal
//! that the change was a breaking API change even if the internal
//! tests still pass.

// Test code legitimately unwraps/panics on assertion failure. Relax
// the strictest library lints that would otherwise flag every assert!.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::items_after_statements
)]

use h33_substrate_verifier::{
    error::VerifierError,
    receipt::{ALG_ALL_THREE, ALG_DILITHIUM, ALG_FALCON, ALG_SPHINCS, RECEIPT_SIZE, RECEIPT_VERSION},
    AlgorithmFlags, CompactReceipt, Headers, PublicKeysResponse, Verifier,
};
use sha3::{Digest, Sha3_256};

fn sha3_of(body: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(body);
    h.finalize().into()
}

fn fabricate_receipt_hex(verified_at_ms: u64, flags: u8) -> String {
    let mut bytes = [0u8; RECEIPT_SIZE];
    bytes[0] = RECEIPT_VERSION;
    for b in &mut bytes[1..33] {
        *b = 0xEE;
    }
    bytes[33..41].copy_from_slice(&verified_at_ms.to_be_bytes());
    bytes[41] = flags;
    hex::encode(bytes)
}

#[test]
fn verifier_end_to_end_happy_path() {
    let body = b"{\"tenant_id\":\"t_abc\",\"plan\":\"premium\"}";
    let hash = sha3_of(body);
    let ts = 1_733_942_731_234_u64;
    let receipt_hex = fabricate_receipt_hex(ts, ALG_ALL_THREE);

    let substrate_hex = hex::encode(hash);
    let headers = Headers::from_strs(
        &substrate_hex,
        &receipt_hex,
        "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
        ts,
    );

    let verifier = Verifier::new();
    let result = verifier.verify(body, &headers).unwrap();

    assert!(result.is_valid());
    assert!(result.body_hash_matches);
    assert!(result.receipt_well_formed);
    assert!(result.algorithms_match_flags);
    assert!(result.timestamps_agree);
    assert_eq!(result.flags_from_receipt.unwrap().count(), 3);
    assert_eq!(result.summary(), "verified");
}

#[test]
fn verifier_exposes_typed_algorithm_flags() {
    let body = b"small";
    let hash = sha3_of(body);
    let ts = 1;
    let receipt_hex = fabricate_receipt_hex(ts, ALG_DILITHIUM | ALG_FALCON);

    let substrate_hex = hex::encode(hash);
    let headers = Headers::from_strs(
        &substrate_hex,
        &receipt_hex,
        "ML-DSA-65,FALCON-512",
        ts,
    );

    let verifier = Verifier::new();
    let result = verifier.verify(body, &headers).unwrap();
    assert!(result.is_valid());
    let flags = result.flags_from_receipt.unwrap();
    assert!(flags.has_dilithium());
    assert!(flags.has_falcon());
    assert!(!flags.has_sphincs());
}

#[test]
fn verifier_surfaces_each_failure_mode_distinctly() {
    let body = b"body";
    let hash = sha3_of(body);
    let ts = 9_000;
    let receipt_hex = fabricate_receipt_hex(ts, ALG_ALL_THREE);
    let substrate_hex = hex::encode(hash);
    let verifier = Verifier::new();

    // (1) Body tampering
    {
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
            ts,
        );
        let result = verifier.verify(b"tampered", &headers).unwrap();
        assert!(!result.body_hash_matches);
        assert!(result.summary().starts_with("body hash mismatch"));
    }

    // (2) Algorithm downgrade
    {
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65",
            ts,
        );
        let result = verifier.verify(body, &headers).unwrap();
        assert!(!result.algorithms_match_flags);
        assert!(result.summary().starts_with("algorithm disagreement"));
    }

    // (3) Timestamp stripping
    {
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
            ts + 1,
        );
        let result = verifier.verify(body, &headers).unwrap();
        assert!(!result.timestamps_agree);
        assert!(result.summary().starts_with("timestamp disagreement"));
    }
}

#[test]
fn unknown_algorithm_bubbles_as_err() {
    let body = b"body";
    let hash = sha3_of(body);
    let ts = 10_000;
    let receipt_hex = fabricate_receipt_hex(ts, ALG_SPHINCS);

    let substrate_hex = hex::encode(hash);
    let headers = Headers::from_strs(
        &substrate_hex,
        &receipt_hex,
        "QUANTUM-CRYSTAL-WIZARD-42",
        ts,
    );

    let verifier = Verifier::new();
    let err = verifier.verify(body, &headers).unwrap_err();
    assert!(matches!(err, VerifierError::UnknownAlgorithm(_)));
}

#[test]
fn public_keys_response_can_be_parsed() {
    let json = r#"{
        "epoch": "h33-substrate-abcdef1234567890",
        "is_current": true,
        "rotation_history": ["h33-substrate-abcdef1234567890"],
        "keys": {
            "dilithium": { "algorithm": "ML-DSA-65",          "format": "raw", "key_b64": "aGVsbG8gd29ybGQ=" },
            "falcon":    { "algorithm": "FALCON-512",         "format": "raw", "key_b64": "Zm9vYmFy" },
            "sphincs":   { "algorithm": "SPHINCS+-SHA2-128f", "format": "raw", "key_b64": "YmF6" }
        }
    }"#;
    let parsed = PublicKeysResponse::from_json(json).unwrap();
    assert_eq!(parsed.epoch, "h33-substrate-abcdef1234567890");
    assert!(parsed.is_current);
    let (dil, fal, sph) = parsed.decode_all().unwrap();
    assert_eq!(dil, b"hello world");
    assert_eq!(fal, b"foobar");
    assert_eq!(sph, b"baz");
}

#[test]
fn compact_receipt_exports_through_crate_root() {
    // This test exists purely to pin the public API surface. If any
    // of these types become private, this test fails to compile and
    // we catch it before a release.
    let bytes = [
        RECEIPT_VERSION,
        // 32 bytes of verification_hash
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB,
        // 8 bytes of verified_at_ms = 0x12345678
        0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
        // flags
        ALG_ALL_THREE,
    ];
    let receipt = CompactReceipt::from_bytes(&bytes).unwrap();
    assert_eq!(receipt.verified_at_ms(), 0x1234_5678);
    let flags: AlgorithmFlags = receipt.flags();
    assert!(flags.has_dilithium());
    assert!(flags.has_falcon());
    assert!(flags.has_sphincs());
}
