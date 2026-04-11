# h33-substrate-verifier

**Reference implementation of the H33 substrate response attestation verifier.**

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

Proprietary. Commercial use requires a license from H33.ai, Inc. Source is open for research, audit, and reference-implementation purposes.

Patent pending — H33 substrate Claims 124-125.

## Resources

- Website: [h33.ai](https://h33.ai)
- Substrate spec: [h33.ai/substrate](https://h33.ai/substrate)
- Repository: [github.com/H33ai-postquantum/h33-substrate-verifier](https://github.com/H33ai-postquantum/h33-substrate-verifier)
- Support: support@h33.ai
