//! Error type for the verifier.
//!
//! All fallible operations in this crate return [`VerifierError`]. The
//! error variants are stable and semantic — calling code can match on
//! them to drive UI, metrics, or retry logic.

use alloc::string::String;
use thiserror::Error;

/// Every way verification can fail to *run*.
///
/// A successful [`verify_structural`](crate::verify::verify_structural)
/// call still returns a [`VerificationResult`](crate::verify::VerificationResult)
/// which itself may report failed checks — those are NOT
/// [`VerifierError`]s. This type is reserved for inputs that are
/// malformed to the point where no verdict can be produced.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifierError {
    /// The `X-H33-Substrate` header was not 64 hex characters.
    #[error("X-H33-Substrate header must be 64 hex characters (32 bytes), got {actual}")]
    InvalidSubstrateHeaderLength {
        /// Number of characters actually present in the header value.
        actual: usize,
    },

    /// The `X-H33-Substrate` header contained invalid hex.
    #[error("X-H33-Substrate header is not valid hex: {0}")]
    InvalidSubstrateHeaderHex(String),

    /// The `X-H33-Receipt` header was not 84 hex characters.
    #[error("X-H33-Receipt header must be 84 hex characters (42 bytes), got {actual}")]
    InvalidReceiptHeaderLength {
        /// Number of characters actually present in the header value.
        actual: usize,
    },

    /// The `X-H33-Receipt` header contained invalid hex.
    #[error("X-H33-Receipt header is not valid hex: {0}")]
    InvalidReceiptHeaderHex(String),

    /// The decoded receipt bytes had an unexpected version byte.
    ///
    /// The expected version for this verifier build is
    /// [`RECEIPT_VERSION`](crate::receipt::RECEIPT_VERSION).
    #[error("CompactReceipt version byte is 0x{actual:02X}, expected 0x{expected:02X}")]
    UnsupportedReceiptVersion {
        /// The version byte the receipt actually carried.
        actual: u8,
        /// The version byte this verifier build understands.
        expected: u8,
    },

    /// The decoded receipt bytes were not exactly 42 bytes.
    #[error("CompactReceipt must decode to exactly {expected} bytes, got {actual}")]
    InvalidReceiptSize {
        /// Byte length the parser read.
        actual: usize,
        /// Byte length the spec requires.
        expected: usize,
    },

    /// The receipt's algorithm flags byte had bits set that the verifier
    /// does not recognize. This can happen when a newer server adds a
    /// fourth signature family before the verifier crate catches up.
    /// Not fatal — the recognized families still verify — but the
    /// caller should know that the full algorithm set was not inspected.
    #[error(
        "CompactReceipt algorithm flags 0x{flags:02X} contain unrecognized bits; \
         verifier only knows Dilithium (0x01), FALCON (0x02), SPHINCS+ (0x04)"
    )]
    UnknownAlgorithmBits {
        /// The raw algorithm flags byte.
        flags: u8,
    },

    /// The public-keys JSON document could not be parsed.
    #[error("public keys JSON parse failed: {0}")]
    PublicKeysParse(String),

    /// A base64 value in the public-keys JSON could not be decoded.
    #[error("public keys contained invalid base64 for field `{field}`: {detail}")]
    PublicKeysBase64 {
        /// The JSON field the bad base64 was in.
        field: &'static str,
        /// Human-readable decoder detail.
        detail: String,
    },

    /// An unknown algorithm string appeared in `X-H33-Algorithms`. The
    /// verifier recognizes exactly these identifiers:
    ///
    /// - `ML-DSA-65` (Dilithium, NIST FIPS 204)
    /// - `FALCON-512`
    /// - `SPHINCS+-SHA2-128f` (SLH-DSA, NIST FIPS 205)
    #[error("unknown algorithm identifier in X-H33-Algorithms: `{0}`")]
    UnknownAlgorithm(String),
}

#[cfg(feature = "std")]
impl From<VerifierError> for std::io::Error {
    fn from(e: VerifierError) -> Self {
        Self::new(std::io::ErrorKind::InvalidData, e.to_string())
    }
}
