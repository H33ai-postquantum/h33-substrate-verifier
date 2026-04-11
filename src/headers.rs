//! Parse the four `X-H33-*` HTTP response headers.
//!
//! Every attested H33 API response carries:
//!
//! ```text
//! X-H33-Substrate:     <64 hex chars — SHA3-256 of the response body>
//! X-H33-Receipt:       <84 hex chars — 42-byte CompactReceipt>
//! X-H33-Algorithms:    ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f
//! X-H33-Substrate-Ts:  <ms timestamp>
//! ```
//!
//! This module is the thin, pure-Rust parser for those four strings.
//! It does NOT do any verification — see [`crate::verify`] for that.
//!
//! The `Headers` type borrows its input strings (`&'a str`), so it is
//! zero-allocation on the happy path when the caller already has the
//! raw header bytes in a buffer.

use crate::error::VerifierError;
use alloc::string::ToString;

/// The canonical lowercase name of the `X-H33-Substrate` header.
pub const HEADER_SUBSTRATE: &str = "x-h33-substrate";
/// The canonical lowercase name of the `X-H33-Receipt` header.
pub const HEADER_RECEIPT: &str = "x-h33-receipt";
/// The canonical lowercase name of the `X-H33-Algorithms` header.
pub const HEADER_ALGORITHMS: &str = "x-h33-algorithms";
/// The canonical lowercase name of the `X-H33-Substrate-Ts` header.
pub const HEADER_SUBSTRATE_TS: &str = "x-h33-substrate-ts";
/// The canonical lowercase name of the per-request opt-out REQUEST header.
pub const HEADER_ATTEST_OPT_OUT: &str = "x-h33-attest";

/// Exact expected length of the `X-H33-Substrate` header value in hex
/// characters (64 chars = 32 bytes).
pub const SUBSTRATE_HEADER_HEX_LEN: usize = 64;

/// Zero-allocation view of the four substrate headers.
///
/// Construct with [`Self::from_strs`] when you have already extracted
/// the raw string values, or enable the `reqwest-support` feature to
/// use [`Self::from_reqwest`] for one-line extraction from a
/// `reqwest::Response`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headers<'a> {
    /// Value of `X-H33-Substrate` — 64 lowercase hex chars.
    pub substrate: &'a str,
    /// Value of `X-H33-Receipt` — 84 lowercase hex chars.
    pub receipt: &'a str,
    /// Value of `X-H33-Algorithms` — comma-separated algorithm identifiers.
    pub algorithms: &'a str,
    /// Value of `X-H33-Substrate-Ts` — already parsed from string to u64.
    pub timestamp_ms: u64,
}

impl<'a> Headers<'a> {
    /// Construct from already-extracted string slices. This is the
    /// `no_std`-friendly constructor that every other constructor
    /// ultimately calls into.
    ///
    /// # Examples
    ///
    /// ```
    /// use h33_substrate_verifier::Headers;
    ///
    /// let headers = Headers::from_strs(
    ///     "f3a8b2c1deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ///     "012e891fa4cafebabedeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\
    ///      0000000012345678\
    ///      07",
    ///     "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
    ///     1_733_942_731_234,
    /// );
    /// assert_eq!(headers.substrate.len(), 64);
    /// ```
    #[must_use]
    pub const fn from_strs(
        substrate: &'a str,
        receipt: &'a str,
        algorithms: &'a str,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            substrate,
            receipt,
            algorithms,
            timestamp_ms,
        }
    }

    /// Parse the hex-encoded `X-H33-Substrate` value into the raw 32-byte
    /// SHA3-256 digest it represents. Runs length and hex-character
    /// validation before decoding.
    pub fn decode_substrate(&self) -> Result<[u8; 32], VerifierError> {
        if self.substrate.len() != SUBSTRATE_HEADER_HEX_LEN {
            return Err(VerifierError::InvalidSubstrateHeaderLength {
                actual: self.substrate.len(),
            });
        }
        let bytes = hex::decode(self.substrate)
            .map_err(|e| VerifierError::InvalidSubstrateHeaderHex(e.to_string()))?;
        let mut out = [0u8; 32];
        if bytes.len() != 32 {
            return Err(VerifierError::InvalidSubstrateHeaderLength {
                actual: self.substrate.len(),
            });
        }
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Split `X-H33-Algorithms` into its comma-separated parts, trimming
    /// whitespace. Returns an iterator that is lazy and zero-copy.
    pub fn algorithm_identifiers(&self) -> impl Iterator<Item = &'a str> {
        self.algorithms.split(',').map(str::trim).filter(|s| !s.is_empty())
    }
}

/// Reqwest adapter — extracts all four headers from a
/// [`reqwest::Response`] in one call. Returns `Err` if any of the
/// required headers is missing or not valid UTF-8.
#[cfg(feature = "reqwest-support")]
pub fn headers_from_reqwest(
    response: &reqwest::Response,
) -> Result<OwnedHeaders, VerifierError> {
    use alloc::string::String;

    fn get(
        response: &reqwest::Response,
        name: &str,
    ) -> Result<String, VerifierError> {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string)
            .ok_or_else(|| {
                VerifierError::PublicKeysParse(alloc::format!(
                    "missing required header: {name}"
                ))
            })
    }

    let substrate = get(response, HEADER_SUBSTRATE)?;
    let receipt = get(response, HEADER_RECEIPT)?;
    let algorithms = get(response, HEADER_ALGORITHMS)?;
    let ts_str = get(response, HEADER_SUBSTRATE_TS)?;
    let timestamp_ms = ts_str.parse::<u64>().map_err(|e| {
        VerifierError::PublicKeysParse(alloc::format!(
            "X-H33-Substrate-Ts is not a valid u64: {e}"
        ))
    })?;

    Ok(OwnedHeaders {
        substrate,
        receipt,
        algorithms,
        timestamp_ms,
    })
}

/// Owned variant of [`Headers`] used by the reqwest adapter when the
/// caller doesn't have its own string buffer to borrow from. Construct
/// via [`headers_from_reqwest`] and call [`OwnedHeaders::borrow`] to
/// get back a `Headers<'_>` view for the verifier.
#[cfg(feature = "reqwest-support")]
#[derive(Debug, Clone)]
pub struct OwnedHeaders {
    /// Owned value of `X-H33-Substrate`.
    pub substrate: alloc::string::String,
    /// Owned value of `X-H33-Receipt`.
    pub receipt: alloc::string::String,
    /// Owned value of `X-H33-Algorithms`.
    pub algorithms: alloc::string::String,
    /// Parsed value of `X-H33-Substrate-Ts`.
    pub timestamp_ms: u64,
}

#[cfg(feature = "reqwest-support")]
impl OwnedHeaders {
    /// Borrow this owned-headers value as a zero-allocation
    /// [`Headers`] view suitable for handing to the verifier.
    #[must_use]
    pub fn borrow(&self) -> Headers<'_> {
        Headers::from_strs(
            &self.substrate,
            &self.receipt,
            &self.algorithms,
            self.timestamp_ms,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_substrate_round_trips() {
        let hex_str = "f3a8b2c1deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let h = Headers::from_strs(hex_str, "00", "ML-DSA-65", 0);
        let decoded = h.decode_substrate().unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded[0], 0xF3);
        assert_eq!(decoded[1], 0xA8);
    }

    #[test]
    fn decode_substrate_rejects_wrong_length() {
        let h = Headers::from_strs("f3a8", "00", "ML-DSA-65", 0);
        assert!(matches!(
            h.decode_substrate(),
            Err(VerifierError::InvalidSubstrateHeaderLength { actual: 4 })
        ));
    }

    #[test]
    fn decode_substrate_rejects_bad_hex() {
        let bad = "z".repeat(SUBSTRATE_HEADER_HEX_LEN);
        let h = Headers::from_strs(&bad, "00", "ML-DSA-65", 0);
        assert!(matches!(
            h.decode_substrate(),
            Err(VerifierError::InvalidSubstrateHeaderHex(_))
        ));
    }

    #[test]
    fn algorithm_identifiers_splits_and_trims() {
        let h = Headers::from_strs(
            "",
            "",
            "ML-DSA-65, FALCON-512 , SPHINCS+-SHA2-128f",
            0,
        );
        let ids: alloc::vec::Vec<&str> = h.algorithm_identifiers().collect();
        assert_eq!(ids, ["ML-DSA-65", "FALCON-512", "SPHINCS+-SHA2-128f"]);
    }

    #[test]
    fn algorithm_identifiers_drops_empty_segments() {
        let h = Headers::from_strs("", "", "ML-DSA-65,,FALCON-512,", 0);
        let ids: alloc::vec::Vec<&str> = h.algorithm_identifiers().collect();
        assert_eq!(ids, ["ML-DSA-65", "FALCON-512"]);
    }
}
