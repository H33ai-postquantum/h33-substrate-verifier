# h33-substrate-verifier

[![Crates.io](https://img.shields.io/crates/v/h33-substrate-verifier.svg)](https://crates.io/crates/h33-substrate-verifier)
[![Docs](https://docs.rs/h33-substrate-verifier/badge.svg)](https://docs.rs/h33-substrate-verifier)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![no_std](https://img.shields.io/badge/no__std-compatible-blue.svg)](./README.md)
[![forbid(unsafe_code)](https://img.shields.io/badge/unsafe-forbidden-brightgreen.svg)](./README.md)
[![Patent pending](https://img.shields.io/badge/patent-pending-yellow.svg)](./README.md#license)

**Reference implementation of the H33 substrate response attestation verifier.**

## Constant-time verification — no side-channel on tampered bodies

The verifier's body-hash comparison runs in **identical wall-clock time** whether the response body is good or tampered. This is a deliberate security property: short-circuiting `==` on a SHA3-256 digest would leak the length of the longest common prefix between the computed hash and the claimed hash, which is exploitable over the network against a verifier running millions of requests per second.

Measured on M4 Max with 1000 Criterion iterations:

| Scenario | Verification time | Observation |
|---|---|---|
| Good body, 1 KiB | **1.53 µs** | baseline |
| **Tampered body, 1 KiB** | **1.53 µs** | **identical — zero timing leak** |

Most HTTP response verifiers do not bother with this because they are either not hashing at all or are using short-circuiting equality from the standard library. H33's verifier performs the body-hash comparison through a branchless XOR-accumulator over all 32 bytes of the SHA3-256 digest, so every execution path takes the same number of cycles. No `memcmp`, no `==`, no early return.

The constant-time check is implemented without a third-party crate (the tiny `subtle` wrapper would double the WASM binary size for a single 32-byte comparison) and is tested with a dedicated `constant_time_eq_rejects_last_byte_difference` unit case that flips every byte position.



Every HTTP response from a H33 API carries four attestation headers:

```
X-H33-Substrate:     <64 hex chars — SHA3-256 of the response body>
X-H33-Receipt:       <84 hex chars — 42-byte CompactReceipt>
X-H33-Algorithms:    ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f
X-H33-Substrate-Ts:  <milliseconds since Unix epoch>
```

This crate verifies those headers against the response body and returns
a structured verdict that calling code can inspect per-check.

```rust
use h33_substrate_verifier::{Headers, Verifier};

let body = b"{\"tenant_id\":\"t_abc\",\"plan\":\"premium\"}";

let headers = Headers::from_strs(
    "f3a8b2c1...",                                   // X-H33-Substrate
    "012e891fa4...",                                 // X-H33-Receipt
    "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",       // X-H33-Algorithms
    1_733_942_731_234,                               // X-H33-Substrate-Ts
);

let verifier = Verifier::new();
let result = verifier.verify(body, &headers)?;

if result.is_valid() {
    println!("✓ verified");
} else {
    println!("✗ {}", result.summary());
}
```

## What this verifier does

- **Body binding**: computes `SHA3-256(body)` locally and confirms it matches `X-H33-Substrate`. Proves the body was not tampered with in transit.
- **Receipt structure**: decodes the 42-byte `CompactReceipt`, verifies the version byte, size, and algorithm flags are valid.
- **Algorithm agreement**: confirms the algorithm names in `X-H33-Algorithms` exactly match the algorithm flags inside the receipt. Detects header stripping and algorithm downgrade.
- **Timestamp agreement**: confirms `X-H33-Substrate-Ts` matches the timestamp embedded in the receipt. Detects timestamp stripping.

All four checks are **local and fully offline** — no network, no async, no I/O.

## What this verifier does NOT do (yet)

Full raw-signature re-verification against each of the three post-quantum families requires the ephemeral Dilithium, FALCON, and SPHINCS+ signatures that the H33 pipeline destroys after one-shot verification on the signing host. When the scif-backend permanent signature storage ships (Tier 3.2) and exposes the substrate nonce, this crate will grow a second verification path that recomputes each of the three PQ signatures locally. Until then, structural verification is the security boundary.

## Install

```toml
[dependencies]
h33-substrate-verifier = "0.1"
```

Feature flags:

| Feature | Default | What it does |
|---|---|---|
| `std` | ✓ | Use `std::error::Error` and enable `reqwest-support` convenience helpers |
| `dilithium` | ✓ | Enable the Dilithium algorithm identifier mapping |
| `falcon` | ✓ | Enable the FALCON-512 algorithm identifier mapping |
| `sphincs` | ✓ | Enable the SPHINCS+-SHA2-128f algorithm identifier mapping |
| `reqwest-support` | | Extract headers from a `reqwest::Response` in one call |

## WASM

This crate is designed to compile to `wasm32-unknown-unknown` for browser-side verification. Disable the `std` feature flag and use `alloc` only:

```toml
[dependencies]
h33-substrate-verifier = { version = "0.1", default-features = false, features = ["dilithium", "falcon", "sphincs"] }
```

The four structural checks use only SHA3-256, hex decoding, and byte comparisons — all pure Rust with zero platform-specific dependencies. A customer's security team can open DevTools, call `H33.verify(response)`, and see a green checkmark.

## Security

- `#![forbid(unsafe_code)]` — the crate contains zero `unsafe` blocks
- `#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]` — library code never panics on malformed input
- Property-based tests with `proptest` exercise random header inputs and confirm the verifier never panics
- Constant-time byte comparison for the body hash check (no timing leaks)
- Criterion benchmarks validate sub-millisecond verification on commodity hardware

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for details.

The verifier is open source because verification is a pure function of public data, and because the trustlessness of verification is a defining property of the substrate primitive. Any party may verify any substrate locally, using only public keys and local cryptography, without acquiring a commercial license.

Patent pending — H33 substrate Claims 124-125.

## Resources

- Website: [h33.ai](https://h33.ai)
- Substrate spec: [h33.ai/substrate](https://h33.ai/substrate)
- Repository: [github.com/H33ai-postquantum/h33-substrate-verifier](https://github.com/H33ai-postquantum/h33-substrate-verifier)
- Support: support@h33.ai
