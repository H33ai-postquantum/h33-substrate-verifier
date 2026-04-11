//! Parser for the `GET /v1/substrate/public-keys` JSON response.
//!
//! The verifier does NOT currently use the public keys to verify raw
//! signatures — that's blocked on scif-backend Tier 3.2 (permanent
//! signature storage + nonce exposure). The parser exists today so
//! customer verification code can hard-code the JSON shape and the
//! base64 field contract, and the types are forward-compatible with
//! the day a raw-verification path lands.
//!
//! ## JSON shape
//!
//! ```json
//! {
//!   "epoch": "h33-substrate-abcdef1234567890",
//!   "is_current": true,
//!   "rotation_history": ["h33-substrate-abcdef1234567890"],
//!   "keys": {
//!     "dilithium": { "algorithm": "ML-DSA-65", "format": "raw", "key_b64": "..." },
//!     "falcon":    { "algorithm": "FALCON-512", "format": "raw", "key_b64": "..." },
//!     "sphincs":   { "algorithm": "SPHINCS+-SHA2-128f", "format": "raw", "key_b64": "..." }
//!   }
//! }
//! ```

use crate::error::VerifierError;
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// Type alias for the decoded three-family public key byte triple
/// returned by [`PublicKeysResponse::decode_all`].
pub type DecodedKeyTriple = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Parsed `GET /v1/substrate/public-keys` response.
///
/// This is an owned-string type because it represents data fetched
/// over the network that the caller will typically cache for 24 h
/// (the static-resource TTL in the server's response middleware).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeysResponse {
    /// Opaque identifier for this key generation epoch. Stable across
    /// restarts of the same keypair set.
    pub epoch: String,
    /// Whether this response represents the currently-active epoch.
    pub is_current: bool,
    /// Every epoch the server has records of. Today this is always a
    /// single entry; with Tier 3.5 key rotation this grows into a
    /// full timeline.
    pub rotation_history: Vec<String>,
    /// The three public keys themselves.
    pub keys: PublicKeyBundle,
}

/// The three public keys, one per signature family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    /// Dilithium ML-DSA-65 public key.
    pub dilithium: PublicKeyEntry,
    /// FALCON-512 public key.
    pub falcon: PublicKeyEntry,
    /// SPHINCS+-SHA2-128f public key.
    pub sphincs: PublicKeyEntry,
}

/// A single public-key entry. Owned-string form so the parser can
/// deserialize from any input without lifetime entanglement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyEntry {
    /// SPDX-style algorithm identifier (e.g. `ML-DSA-65`).
    pub algorithm: String,
    /// Encoding of `key_b64`. Currently always `raw`.
    pub format: String,
    /// The public key itself, base64-encoded with the standard alphabet.
    pub key_b64: String,
}

impl PublicKeyEntry {
    /// Decode the base64-encoded key bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use h33_substrate_verifier::PublicKeyEntry;
    ///
    /// let entry = PublicKeyEntry {
    ///     algorithm: "ML-DSA-65".into(),
    ///     format: "raw".into(),
    ///     key_b64: "aGVsbG8gd29ybGQ=".into(),
    /// };
    /// let bytes = entry.decode_bytes("dilithium").unwrap();
    /// assert_eq!(bytes, b"hello world");
    /// ```
    pub fn decode_bytes(
        &self,
        field_name: &'static str,
    ) -> Result<Vec<u8>, VerifierError> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(self.key_b64.as_bytes())
            .map_err(|e| VerifierError::PublicKeysBase64 {
                field: field_name,
                detail: alloc::format!("{e}"),
            })
    }
}

impl PublicKeysResponse {
    /// Parse a JSON document into a `PublicKeysResponse`.
    pub fn from_json(json: &str) -> Result<Self, VerifierError> {
        serde_json::from_str(json).map_err(|e| {
            VerifierError::PublicKeysParse(alloc::format!("{e}"))
        })
    }

    /// Decode all three public keys at once, returning a
    /// [`DecodedKeyTriple`] of `(dilithium, falcon, sphincs)` as owned
    /// byte vectors. Returns the first base64 error encountered.
    pub fn decode_all(&self) -> Result<DecodedKeyTriple, VerifierError> {
        Ok((
            self.keys.dilithium.decode_bytes("dilithium")?,
            self.keys.falcon.decode_bytes("falcon")?,
            self.keys.sphincs.decode_bytes("sphincs")?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_JSON: &str = r#"{
        "epoch": "h33-substrate-abcdef1234567890",
        "is_current": true,
        "rotation_history": ["h33-substrate-abcdef1234567890"],
        "keys": {
            "dilithium": {
                "algorithm": "ML-DSA-65",
                "format": "raw",
                "key_b64": "aGVsbG8gd29ybGQ="
            },
            "falcon": {
                "algorithm": "FALCON-512",
                "format": "raw",
                "key_b64": "Zm9vYmFy"
            },
            "sphincs": {
                "algorithm": "SPHINCS+-SHA2-128f",
                "format": "raw",
                "key_b64": "YmF6"
            }
        }
    }"#;

    #[test]
    fn parses_fixture_json() {
        let parsed = PublicKeysResponse::from_json(FIXTURE_JSON).unwrap();
        assert_eq!(parsed.epoch, "h33-substrate-abcdef1234567890");
        assert!(parsed.is_current);
        assert_eq!(parsed.rotation_history.len(), 1);
        assert_eq!(parsed.keys.dilithium.algorithm, "ML-DSA-65");
        assert_eq!(parsed.keys.falcon.algorithm, "FALCON-512");
        assert_eq!(parsed.keys.sphincs.algorithm, "SPHINCS+-SHA2-128f");
    }

    #[test]
    fn decodes_base64_bytes() {
        let parsed = PublicKeysResponse::from_json(FIXTURE_JSON).unwrap();
        let (dil, fal, sph) = parsed.decode_all().unwrap();
        assert_eq!(dil, b"hello world");
        assert_eq!(fal, b"foobar");
        assert_eq!(sph, b"baz");
    }

    #[test]
    fn rejects_malformed_json() {
        let bad = "{not valid json";
        assert!(matches!(
            PublicKeysResponse::from_json(bad),
            Err(VerifierError::PublicKeysParse(_))
        ));
    }

    #[test]
    fn rejects_bad_base64_in_key() {
        let bad_json = r#"{
            "epoch": "e",
            "is_current": true,
            "rotation_history": ["e"],
            "keys": {
                "dilithium": { "algorithm": "ML-DSA-65",          "format": "raw", "key_b64": "@@@@" },
                "falcon":    { "algorithm": "FALCON-512",         "format": "raw", "key_b64": "Zm9v" },
                "sphincs":   { "algorithm": "SPHINCS+-SHA2-128f", "format": "raw", "key_b64": "YmF6" }
            }
        }"#;
        let parsed = PublicKeysResponse::from_json(bad_json).unwrap();
        let err = parsed.decode_all().unwrap_err();
        assert!(matches!(
            err,
            VerifierError::PublicKeysBase64 {
                field: "dilithium",
                ..
            }
        ));
    }
}
