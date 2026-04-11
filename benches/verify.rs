//! Criterion benchmarks for the structural verifier.
//!
//! The structural path is the hot path every customer will exercise.
//! These benches pin its performance so a regression shows up as a
//! red diff in CI.
//!
//! Run with:
//!
//! ```bash
//! cargo bench --bench verify
//! ```

// Benches are not library code — relax the library lints that would
// otherwise flag every setup-helper unwrap.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use h33_substrate_verifier::{verify::verify_structural, Headers};
use sha3::{Digest, Sha3_256};

/// Helpers shared across every bench. Duplicated from the module-level
/// test helpers because benches are a separate crate from tests.
const RECEIPT_SIZE: usize = 42;
const RECEIPT_VERSION: u8 = 0x01;
const ALG_ALL_THREE: u8 = 0b0000_0111;

fn sha3_of(body: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(body);
    h.finalize().into()
}

fn fabricate_receipt_hex(verified_at_ms: u64, flags: u8) -> String {
    let mut bytes = [0u8; RECEIPT_SIZE];
    bytes[0] = RECEIPT_VERSION;
    for b in &mut bytes[1..33] {
        *b = 0xCC;
    }
    bytes[33..41].copy_from_slice(&verified_at_ms.to_be_bytes());
    bytes[41] = flags;
    hex::encode(bytes)
}

fn build_happy_path_inputs(body_size: usize) -> (Vec<u8>, String, String, u64) {
    let body = vec![b'x'; body_size];
    let hash = sha3_of(&body);
    let substrate_hex = hex::encode(hash);
    let ts = 1_733_942_731_234_u64;
    let receipt_hex = fabricate_receipt_hex(ts, ALG_ALL_THREE);
    (body, substrate_hex, receipt_hex, ts)
}

fn bench_verify_body_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_structural_by_body_size");

    for size in [100usize, 1024, 10_240, 102_400, 1_048_576] {
        let (body, substrate_hex, receipt_hex, ts) = build_happy_path_inputs(size);
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
            ts,
        );

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let result = verify_structural(std::hint::black_box(&body), &headers).unwrap();
                std::hint::black_box(result);
            });
        });
    }

    group.finish();
}

fn bench_tampered_body(c: &mut Criterion) {
    // Same happy-path setup as the 1KiB bench but verify against a
    // tampered body. The verifier should still run in O(body_len) —
    // the failing check comes after the SHA3 digest, so this bench
    // measures the same hot path as the good-body case.
    let (mut body, substrate_hex, receipt_hex, ts) = build_happy_path_inputs(1024);
    body[0] ^= 0xFF;
    let headers = Headers::from_strs(
        &substrate_hex,
        &receipt_hex,
        "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
        ts,
    );

    c.bench_function("verify_structural_tampered_1kb", |b| {
        b.iter(|| {
            let result = verify_structural(std::hint::black_box(&body), &headers).unwrap();
            std::hint::black_box(result);
        });
    });
}

criterion_group!(benches, bench_verify_body_sizes, bench_tampered_body);
criterion_main!(benches);
