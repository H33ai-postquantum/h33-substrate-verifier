//! # h33-substrate-verifier
//!
//! Reference implementation of the H33 substrate response attestation
//! verifier.
//!
//! Every HTTP response from a H33 API carries four attestation headers:
//!
//! ```text
//! X-H33-Substrate:     <64 hex chars>  SHA3-256 of the response body
//! X-H33-Receipt:       <84 hex chars>  42-byte CompactReceipt
//! X-H33-Algorithms:    ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f
//! X-H33-Substrate-Ts:  <ms since epoch> Substrate mint timestamp
//! ```
//!
//! This crate verifies those headers against the response body and
//! returns a structured [`VerificationResult`] that the calling code
//! can inspect per family.
//!
//! ## Verification model
//!
//! The H33 substrate pipeline destroys the raw ephemeral Dilithium,
//! FALCON, and SPHINCS+ signatures after they are verified on the
//! signing host. What the customer receives is the 42-byte
//! [`CompactReceipt`](receipt::CompactReceipt) — a cryptographic
//! *verification certificate* — plus the 32-byte body hash.
//!
//! The verifier performs four independent integrity checks:
//!
//! 1. **Body binding.** Compute `SHA3-256(body_bytes)` locally and
//!    confirm it matches the `X-H33-Substrate` header. Proves the
//!    body has not been tampered with in transit.
//! 2. **Receipt structure.** Parse the 42-byte `CompactReceipt` and
//!    confirm the version byte, size, and algorithm flags are valid.
//! 3. **Algorithm agreement.** Confirm the algorithm names in the
//!    `X-H33-Algorithms` header match the algorithm flags inside the
//!    receipt. Detects header stripping or algorithm downgrade.
//! 4. **Timestamp agreement.** Confirm the millisecond timestamp in
//!    `X-H33-Substrate-Ts` matches the timestamp embedded in the
//!    receipt. Detects timestamp stripping.
//!
//! All four checks are **local and fully offline** — no network, no
//! async, no I/O.
//!
//! ### What this verifier does NOT do (yet)
//!
//! Full raw-signature re-verification requires the ephemeral Dilithium,
//! FALCON, and SPHINCS+ signatures, which the H33 pipeline destroys
//! after attestation. When scif-backend ships persistent signature
//! storage (Tier 3.2 — permanent receipt storage on Arweave) and
//! exposes the substrate nonce, this crate will grow a second
//! verification path that recomputes each of the three PQ signatures
//! locally. Until then, structural verification is the security
//! boundary.
//!
//! ## Minimum viable example
//!
//! ```no_run
//! use h33_substrate_verifier::{Verifier, Headers};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let body_bytes = b"{\"tenant_id\":\"t_abc\",\"plan\":\"premium\"}";
//!
//! // Parse the four X-H33-* headers the server sent back.
//! let headers = Headers::from_strs(
//!     "f3a8b2c1deadbeef...64chars...",
//!     "012e891fa4cafebabedeadbeef...84chars...",
//!     "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
//!     1_733_942_731_234,
//! );
//!
//! // Verify.
//! let verifier = Verifier::new();
//! let result = verifier.verify(body_bytes, &headers)?;
//!
//! assert!(result.is_valid());
//! assert!(result.body_hash_matches);
//! assert!(result.receipt_well_formed);
//! assert!(result.algorithms_match_flags);
//! assert!(result.timestamps_agree);
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature flags
//!
//! | Feature | Default | What it does |
//! |---|---|---|
//! | `std` | yes | Use `std::error::Error` on the error type and enable the `reqwest-support` convenience helpers |
//! | `dilithium` | yes | Enable the Dilithium signature algorithm identifier mapping (no raw verification until Tier 3) |
//! | `falcon` | yes | Enable the FALCON-512 algorithm identifier mapping |
//! | `sphincs` | yes | Enable the SPHINCS+-SHA2-128f algorithm identifier mapping |
//! | `reqwest-support` | no | Pull in reqwest and expose `Headers::from_reqwest` for one-line extraction from an HTTP response |
//!
//! A WASM build can disable every family feature flag and still run the
//! four structural checks — SHA3-256, hex decoding, and byte comparisons
//! are all pure Rust and compile to `wasm32-unknown-unknown` without any
//! platform-specific dependency.
//!
//! ## Security
//!
//! - `#![forbid(unsafe_code)]` — the crate contains zero `unsafe` blocks.
//! - `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`
//!   — library code never panics on malformed input; every fallible
//!   operation returns a [`VerifierError`].
//! - Property-based tests with `proptest` exercise random header inputs
//!   and confirm the verifier never panics.
//! - Criterion benchmarks validate the verification path runs in
//!   sub-millisecond time on commodity hardware.
//!
//! ## License
//!
//! Proprietary. Commercial use requires a license from H33.ai, Inc.
//! Source is open for research, audit, and reference-implementation
//! purposes. Patent pending — H33 substrate Claims 124-125.

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    rust_2018_idioms,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp
)]
#![warn(
    unreachable_pub,
    clippy::pedantic,
    clippy::nursery,
    clippy::integer_division
)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]
#![cfg_attr(not(feature = "std"), no_std)]
// Tests legitimately unwrap/expect/panic — a test panic IS the failure mode.
// Relax the strictest lints inside test code so every assert! doesn't have to
// be rewritten as an if-let-ok-else-return-Err dance.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::too_many_lines
    )
)]

extern crate alloc;

pub mod error;
pub mod headers;
pub mod public_keys;
pub mod receipt;
pub mod substrate_layout;
pub mod verify;

pub use error::VerifierError;
pub use headers::Headers;
pub use public_keys::{PublicKeyBundle, PublicKeyEntry, PublicKeysResponse};
pub use receipt::{CompactReceipt, AlgorithmFlags, RECEIPT_SIZE, RECEIPT_VERSION};
pub use substrate_layout::{
    ComputationType, SUBSTRATE_SIZE, SUBSTRATE_VERSION,
};
pub use verify::{verify_structural, VerificationResult};

/// The canonical `Verifier`. A thin wrapper around [`verify_structural`]
/// kept as a struct so future Tier 3 work can attach a cached
/// [`PublicKeysResponse`] without changing the public API shape.
///
/// # Examples
///
/// ```
/// use h33_substrate_verifier::Verifier;
///
/// let verifier = Verifier::new();
/// // Subsequent calls to verifier.verify(...) use the structural path.
/// ```
#[derive(Debug, Default, Clone)]
pub struct Verifier {
    _private: (),
}

impl Verifier {
    /// Construct a new `Verifier`.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Verify an attested response.
    ///
    /// Returns `Ok(VerificationResult)` with per-check verdicts whenever
    /// the inputs are structurally parseable — even if the verdicts
    /// report failure. Returns `Err(VerifierError)` only when the inputs
    /// themselves are malformed (bad hex, wrong length, etc.).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use h33_substrate_verifier::{Headers, Verifier};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let body = b"{\"ok\":true}";
    /// let headers = Headers::from_strs(
    ///     "f3a8b2c1deadbeef...",
    ///     "012e891fa4cafebabedeadbeef...",
    ///     "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
    ///     1_733_942_731_234,
    /// );
    /// let verifier = Verifier::new();
    /// let result = verifier.verify(body, &headers)?;
    /// if result.is_valid() {
    ///     println!("Response was legitimately signed by H33");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify(
        &self,
        body: &[u8],
        headers: &Headers<'_>,
    ) -> Result<VerificationResult, VerifierError> {
        verify_structural(body, headers)
    }
}
