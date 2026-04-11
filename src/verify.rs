//! The structural verification pipeline.
//!
//! This module is the core of the crate. Given a response body and the
//! four `X-H33-*` headers, it runs four independent integrity checks
//! and returns a [`VerificationResult`] that reports each check
//! separately.
//!
//! No network calls. No async. No allocations on the hot path beyond
//! the single hex decode of the receipt header. Safe to call from WASM,
//! embedded, or any other constrained environment.
//!
//! ## The four checks
//!
//! 1. **Body binding** — `SHA3-256(body) == X-H33-Substrate`
//! 2. **Receipt structure** — 42 bytes, version 0x01, known algorithm flags
//! 3. **Algorithm agreement** — `X-H33-Algorithms` contains exactly the
//!    family names that `CompactReceipt::flags()` reports
//! 4. **Timestamp agreement** — `X-H33-Substrate-Ts == CompactReceipt::verified_at_ms()`
//!
//! `verify_structural` returns `Ok(VerificationResult)` whenever the
//! inputs are parseable at all. A parseable-but-failing result still
//! returns `Ok`; the caller inspects the per-field booleans on the
//! result to decide pass/fail.
//!
//! The only reason `verify_structural` returns `Err` is when the
//! inputs themselves are malformed past the point of being inspected
//! — bad hex, wrong receipt version, impossible lengths, etc.

use crate::{
    error::VerifierError,
    headers::Headers,
    receipt::{AlgorithmFlags, CompactReceipt},
};
use alloc::string::ToString;
use sha3::{Digest, Sha3_256};

/// Structured verdict from running the four structural checks.
///
/// Every field is a boolean, and every field answers a distinct,
/// independently-valuable question. [`Self::is_valid`] is simply
/// the AND of all four; callers that want partial verdicts (e.g.
/// "body is bound and the receipt is structurally valid, but the
/// algorithms header was stripped") can read the fields directly.
///
/// The four booleans map one-to-one to the four independent
/// integrity checks and deliberately do not collapse into a
/// state-machine enum: a caller often wants to surface a specific
/// check that failed in a log or UI, and an enum would flatten
/// that information.
#[allow(clippy::struct_excessive_bools)] // Four independent yes/no integrity checks — see the doc comment above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    /// `true` if `SHA3-256(body) == X-H33-Substrate`.
    pub body_hash_matches: bool,
    /// `true` if `X-H33-Receipt` decoded to a v1 42-byte receipt with
    /// recognized algorithm flags.
    pub receipt_well_formed: bool,
    /// `true` if the algorithm names listed in `X-H33-Algorithms`
    /// correspond exactly (set-equal) to the algorithm flags inside
    /// the receipt.
    pub algorithms_match_flags: bool,
    /// `true` if `X-H33-Substrate-Ts` equals the `verified_at_ms`
    /// field inside the receipt.
    pub timestamps_agree: bool,
    /// Typed view of the algorithm flags byte from the decoded receipt.
    /// Populated as soon as the receipt itself parses, even if the
    /// other checks fail.
    pub flags_from_receipt: Option<AlgorithmFlags>,
    /// The 32-byte SHA3-256 hash this verifier computed over the body,
    /// surfaced so callers can log it alongside pass/fail.
    pub computed_body_hash: [u8; 32],
}

impl VerificationResult {
    /// The overall verdict: `true` only when every structural check passes.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.body_hash_matches
            && self.receipt_well_formed
            && self.algorithms_match_flags
            && self.timestamps_agree
    }

    /// A short human-readable description of which check failed first.
    /// Useful in CLI output and logs. Returns `"verified"` when every
    /// check passed.
    #[must_use]
    pub const fn summary(&self) -> &'static str {
        if !self.body_hash_matches {
            "body hash mismatch — response body does not match X-H33-Substrate"
        } else if !self.receipt_well_formed {
            "receipt malformed — X-H33-Receipt failed structural parsing"
        } else if !self.algorithms_match_flags {
            "algorithm disagreement — X-H33-Algorithms does not match receipt flags"
        } else if !self.timestamps_agree {
            "timestamp disagreement — X-H33-Substrate-Ts does not match receipt verified_at_ms"
        } else {
            "verified"
        }
    }
}

/// Run the four structural integrity checks over a response body and
/// its four substrate attestation headers.
///
/// See the module-level docs for what each check does. The function
/// never panics and never allocates on the happy path beyond the one
/// hex decode of the 84-char receipt header.
pub fn verify_structural(
    body: &[u8],
    headers: &Headers<'_>,
) -> Result<VerificationResult, VerifierError> {
    // ── Check 1: body binding ────────────────────────────────────────
    let mut hasher = Sha3_256::new();
    hasher.update(body);
    let computed_body_hash: [u8; 32] = hasher.finalize().into();

    let claimed_body_hash = headers.decode_substrate()?;
    let body_hash_matches = constant_time_eq(&computed_body_hash, &claimed_body_hash);

    // ── Check 2: receipt structure ───────────────────────────────────
    let receipt_result = CompactReceipt::from_hex(headers.receipt);
    let (receipt_well_formed, flags_from_receipt, receipt_timestamp) =
        receipt_result.as_ref().map_or((false, None, None), |r| {
            (true, Some(r.flags()), Some(r.verified_at_ms()))
        });

    // ── Check 3: algorithm agreement ─────────────────────────────────
    //
    // We compare the set of algorithm identifiers named in the
    // X-H33-Algorithms header against the set of bits set in the
    // decoded receipt's flag byte. Both sets must be exactly equal —
    // a header that claims more than the receipt means someone added
    // algorithm names that the signer did not actually run, and a
    // receipt that claims more than the header means the header was
    // trimmed in transit.
    let algorithms_match_flags = if let Some(flags) = flags_from_receipt {
        let header_set = parse_algorithm_set(headers)?;
        let receipt_set = AlgorithmSet::from_flags(flags);
        header_set == receipt_set
    } else {
        false
    };

    // ── Check 4: timestamp agreement ─────────────────────────────────
    let timestamps_agree = matches!(
        receipt_timestamp,
        Some(ts) if ts == headers.timestamp_ms
    );

    Ok(VerificationResult {
        body_hash_matches,
        receipt_well_formed,
        algorithms_match_flags,
        timestamps_agree,
        flags_from_receipt,
        computed_body_hash,
    })
}

/// The three-family set we know how to talk about. Implemented as a
/// small bit-packed struct for `Eq` and fast comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AlgorithmSet {
    has_dilithium: bool,
    has_falcon: bool,
    has_sphincs: bool,
}

impl AlgorithmSet {
    const fn from_flags(flags: AlgorithmFlags) -> Self {
        Self {
            has_dilithium: flags.has_dilithium(),
            has_falcon: flags.has_falcon(),
            has_sphincs: flags.has_sphincs(),
        }
    }
}

/// Parse the `X-H33-Algorithms` header into an `AlgorithmSet`. Returns
/// [`VerifierError::UnknownAlgorithm`] if any identifier in the header
/// is not one of the three families this verifier build knows.
fn parse_algorithm_set(headers: &Headers<'_>) -> Result<AlgorithmSet, VerifierError> {
    let mut set = AlgorithmSet {
        has_dilithium: false,
        has_falcon: false,
        has_sphincs: false,
    };
    for raw in headers.algorithm_identifiers() {
        match canonicalize_alg_id(raw) {
            Some(CanonicalAlg::Dilithium) => set.has_dilithium = true,
            Some(CanonicalAlg::Falcon) => set.has_falcon = true,
            Some(CanonicalAlg::Sphincs) => set.has_sphincs = true,
            None => return Err(VerifierError::UnknownAlgorithm(raw.to_string())),
        }
    }
    Ok(set)
}

enum CanonicalAlg {
    Dilithium,
    Falcon,
    Sphincs,
}

/// Canonicalize an algorithm identifier from the `X-H33-Algorithms`
/// header into one of the three families this verifier understands.
///
/// We accept **every known future variant** of each family deliberately,
/// not just the specific parameter set scif-backend runs today. The
/// substrate on-wire algorithm flag is a per-family bit, not a
/// per-variant bit, so any Dilithium variant (ML-DSA-44/65/87) maps to
/// the same Dilithium bit; any FALCON variant (512/1024) maps to the
/// same FALCON bit; any SPHINCS+/SLH-DSA variant (SHA2/SHAKE × 128/192/256
/// × f/s × simple/robust) maps to the same SPHINCS+ bit.
///
/// This means a customer verifier built today keeps working when
/// scif-backend upgrades to FALCON-1024 or SPHINCS+-SHA2-192f in the
/// future — no verifier release needed. The specific variant in use is
/// still pinned by the server's `X-H33-Algorithms` header; the verifier
/// simply doesn't gatekeep on the parameter choice. Parameter tracking
/// is the server's responsibility, not the verifier's.
fn canonicalize_alg_id(raw: &str) -> Option<CanonicalAlg> {
    let r = raw.trim();

    // ── Dilithium family (MLWE lattice) ──────────────────────────────
    // Every ML-DSA parameter set that exists or is plausible:
    //   ML-DSA-44  (NIST Level 2, FIPS 204 minimum)
    //   ML-DSA-65  (NIST Level 3, FIPS 204 recommended)
    //   ML-DSA-87  (NIST Level 5, FIPS 204 maximum)
    // Pre-FIPS historical name: Dilithium2/3/5
    if r.eq_ignore_ascii_case("ML-DSA-44")
        || r.eq_ignore_ascii_case("ML-DSA-65")
        || r.eq_ignore_ascii_case("ML-DSA-87")
        || r.eq_ignore_ascii_case("Dilithium2")
        || r.eq_ignore_ascii_case("Dilithium3")
        || r.eq_ignore_ascii_case("Dilithium5")
    {
        return Some(CanonicalAlg::Dilithium);
    }

    // ── FALCON family (NTRU lattice) ─────────────────────────────────
    // The two standardized FALCON parameter sets:
    //   FALCON-512   (NIST Level 1)
    //   FALCON-1024  (NIST Level 5)
    // Pre-FIPS historical name: FN-DSA-512 / FN-DSA-1024
    if r.eq_ignore_ascii_case("FALCON-512")
        || r.eq_ignore_ascii_case("FALCON-1024")
        || r.eq_ignore_ascii_case("FN-DSA-512")
        || r.eq_ignore_ascii_case("FN-DSA-1024")
    {
        return Some(CanonicalAlg::Falcon);
    }

    // ── SPHINCS+ / SLH-DSA family (stateless hash-based) ─────────────
    // FIPS 205 SLH-DSA parameter set grid:
    //   SHA2 × {128, 192, 256} × {f, s}  (6 variants)
    //   SHAKE × {128, 192, 256} × {f, s} (6 variants)
    // Pre-FIPS historical name: SPHINCS+-<hash>-<bits><speed>-<simple|robust>
    // f = fast (bigger signatures, faster signing)
    // s = small (smaller signatures, slower signing)
    // simple = NIST-standardized; robust = legacy variant, still accepted
    //
    // A newer server may emit any of these; a verifier built today
    // should honor all of them so the customer does not have to ship a
    // new verifier when the server's parameter set is rotated for
    // security-level upgrade reasons.
    if is_slh_dsa_identifier(r) || is_sphincs_plus_identifier(r) {
        return Some(CanonicalAlg::Sphincs);
    }

    None
}

/// Match any NIST FIPS 205 SLH-DSA identifier.
fn is_slh_dsa_identifier(r: &str) -> bool {
    // SLH-DSA-<hash>-<level><speed>
    // hash    ∈ { SHA2, SHAKE }
    // level   ∈ { 128, 192, 256 }
    // speed   ∈ { f, s }
    matches!(
        r.to_ascii_uppercase().as_str(),
        "SLH-DSA-SHA2-128F"
            | "SLH-DSA-SHA2-128S"
            | "SLH-DSA-SHA2-192F"
            | "SLH-DSA-SHA2-192S"
            | "SLH-DSA-SHA2-256F"
            | "SLH-DSA-SHA2-256S"
            | "SLH-DSA-SHAKE-128F"
            | "SLH-DSA-SHAKE-128S"
            | "SLH-DSA-SHAKE-192F"
            | "SLH-DSA-SHAKE-192S"
            | "SLH-DSA-SHAKE-256F"
            | "SLH-DSA-SHAKE-256S"
    )
}

/// Match any pre-FIPS SPHINCS+ identifier (with or without the
/// `-simple` / `-robust` suffix).
fn is_sphincs_plus_identifier(r: &str) -> bool {
    let upper = r.to_ascii_uppercase();
    let trimmed = upper
        .strip_suffix("-SIMPLE")
        .or_else(|| upper.strip_suffix("-ROBUST"))
        .unwrap_or(&upper);
    matches!(
        trimmed,
        "SPHINCS+-SHA2-128F"
            | "SPHINCS+-SHA2-128S"
            | "SPHINCS+-SHA2-192F"
            | "SPHINCS+-SHA2-192S"
            | "SPHINCS+-SHA2-256F"
            | "SPHINCS+-SHA2-256S"
            | "SPHINCS+-SHAKE-128F"
            | "SPHINCS+-SHAKE-128S"
            | "SPHINCS+-SHAKE-192F"
            | "SPHINCS+-SHAKE-192S"
            | "SPHINCS+-SHAKE-256F"
            | "SPHINCS+-SHAKE-256S"
    )
}

/// Constant-time byte slice equality for fixed 32-byte hashes.
///
/// We never compare hashes with a short-circuiting `==` because the
/// timing channel reveals the longest common prefix of the computed
/// hash and the claimed hash. The `subtle` crate would do this too,
/// but pulling it in as a dependency for a single comparison doubles
/// the WASM binary size. Hand-rolled is fine because the inputs are
/// fixed-length.
#[inline]
#[must_use]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        // SAFETY-adjacent: indexing is bounds-checked but the `i`
        // values are compile-time constants, so the bounds check is
        // trivially eliminated. Doing this by index rather than by
        // iterator to keep the control flow branch-free.
        let left = a.get(i).copied().unwrap_or(0);
        let right = b.get(i).copied().unwrap_or(0);
        diff |= left ^ right;
    }
    diff == 0
}

/// Known-answer vector — computed from the SPEC.md test vectors so the
/// parser behaves identically to the signer. The vector is the
/// SHA3-256 of the empty string, hex-encoded.
#[cfg(test)]
pub(crate) const KNOWN_SHA3_EMPTY: &str =
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{
        ALG_ALL_THREE, ALG_DILITHIUM, ALG_FALCON, ALG_SPHINCS, RECEIPT_SIZE,
        RECEIPT_VERSION,
    };

    /// Build a matching receipt for the given body and timestamp so we
    /// can test the happy path without needing a real signer.
    fn fabricate_receipt_hex(
        _body_hash: [u8; 32],
        verified_at_ms: u64,
        flags: u8,
    ) -> alloc::string::String {
        let mut bytes = [0u8; RECEIPT_SIZE];
        bytes[0] = RECEIPT_VERSION;
        // verification_hash is 32 bytes of 0xCC — real value would be
        // SHA3 of (domain || msg || pks || sigs) but the structural
        // verifier doesn't check it.
        for b in &mut bytes[1..33] {
            *b = 0xCC;
        }
        bytes[33..41].copy_from_slice(&verified_at_ms.to_be_bytes());
        bytes[41] = flags;
        hex::encode(bytes)
    }

    fn sha3_of(body: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(body);
        h.finalize().into()
    }

    #[test]
    fn verifies_a_known_good_response() {
        let body = b"{\"tenant\":\"abc\",\"plan\":\"premium\"}";
        let body_hash = sha3_of(body);
        let substrate_hex = hex::encode(body_hash);
        let ts = 1_733_942_731_234_u64;
        let receipt_hex = fabricate_receipt_hex(body_hash, ts, ALG_ALL_THREE);

        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
            ts,
        );

        let result = verify_structural(body, &headers).unwrap();
        assert!(result.is_valid(), "expected valid, got: {}", result.summary());
        assert!(result.body_hash_matches);
        assert!(result.receipt_well_formed);
        assert!(result.algorithms_match_flags);
        assert!(result.timestamps_agree);
    }

    #[test]
    fn detects_body_tampering() {
        let body = b"original body";
        let tampered = b"tampered body";
        let original_hash = sha3_of(body);
        let substrate_hex = hex::encode(original_hash);
        let ts = 1_000;
        let receipt_hex = fabricate_receipt_hex(original_hash, ts, ALG_ALL_THREE);

        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
            ts,
        );

        // Verifier is given the TAMPERED body but the ORIGINAL headers.
        // Expected: body_hash_matches is false, overall is_valid is false.
        let result = verify_structural(tampered, &headers).unwrap();
        assert!(!result.body_hash_matches);
        assert!(!result.is_valid());
        assert!(result.summary().contains("body hash mismatch"));
    }

    #[test]
    fn detects_algorithm_header_stripping() {
        let body = b"body";
        let hash = sha3_of(body);
        let ts = 2_000;
        let receipt_hex = fabricate_receipt_hex(hash, ts, ALG_ALL_THREE);

        // Receipt claims all three; header claims only two.
        let substrate_hex = hex::encode(hash);
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65,FALCON-512",
            ts,
        );

        let result = verify_structural(body, &headers).unwrap();
        assert!(result.body_hash_matches);
        assert!(result.receipt_well_formed);
        assert!(!result.algorithms_match_flags);
        assert!(!result.is_valid());
    }

    #[test]
    fn detects_timestamp_disagreement() {
        let body = b"body";
        let hash = sha3_of(body);
        let receipt_hex = fabricate_receipt_hex(hash, 3_000, ALG_ALL_THREE);

        // Header claims a different timestamp than the receipt.
        let substrate_hex = hex::encode(hash);
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65,FALCON-512,SPHINCS+-SHA2-128f",
            4_000,
        );

        let result = verify_structural(body, &headers).unwrap();
        assert!(!result.timestamps_agree);
        assert!(!result.is_valid());
    }

    #[test]
    fn partial_algorithm_sets_verify_when_header_matches() {
        let body = b"body";
        let hash = sha3_of(body);
        let ts = 5_000;
        // Receipt is Dilithium + FALCON only (no SPHINCS+).
        let receipt_hex =
            fabricate_receipt_hex(hash, ts, ALG_DILITHIUM | ALG_FALCON);

        let substrate_hex = hex::encode(hash);
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65,FALCON-512",
            ts,
        );

        let result = verify_structural(body, &headers).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.flags_from_receipt.unwrap().count(), 2);
    }

    #[test]
    fn unknown_algorithm_identifier_is_an_error() {
        let body = b"body";
        let hash = sha3_of(body);
        let ts = 6_000;
        let receipt_hex = fabricate_receipt_hex(hash, ts, ALG_DILITHIUM);

        let substrate_hex = hex::encode(hash);
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "QUANTUM-MAGIC-9000",
            ts,
        );

        // Structural verify should return Err for a totally unknown
        // algorithm identifier — this catches clients that upgraded
        // their server before upgrading their verifier and would
        // otherwise see a misleading "ok" verdict.
        let result = verify_structural(body, &headers);
        assert!(matches!(
            result,
            Err(VerifierError::UnknownAlgorithm(_))
        ));
    }

    #[test]
    fn historical_aliases_are_accepted() {
        let body = b"body";
        let hash = sha3_of(body);
        let ts = 7_000;
        let receipt_hex = fabricate_receipt_hex(hash, ts, ALG_ALL_THREE);

        let substrate_hex = hex::encode(hash);
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "Dilithium3, FN-DSA-512, SLH-DSA-SHA2-128f",
            ts,
        );

        let result = verify_structural(body, &headers).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn every_known_dilithium_variant_maps_to_the_dilithium_bit() {
        for name in [
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "Dilithium2",
            "Dilithium3",
            "Dilithium5",
            "ml-dsa-65", // case-insensitive
        ] {
            assert!(
                matches!(canonicalize_alg_id(name), Some(CanonicalAlg::Dilithium)),
                "identifier {name} should map to Dilithium"
            );
        }
    }

    #[test]
    fn every_known_falcon_variant_maps_to_the_falcon_bit() {
        for name in [
            "FALCON-512",
            "FALCON-1024",
            "FN-DSA-512",
            "FN-DSA-1024",
            "falcon-512",
            "fn-dsa-1024",
        ] {
            assert!(
                matches!(canonicalize_alg_id(name), Some(CanonicalAlg::Falcon)),
                "identifier {name} should map to FALCON"
            );
        }
    }

    #[test]
    fn every_known_sphincs_plus_variant_maps_to_the_sphincs_bit() {
        // Every FIPS 205 SLH-DSA identifier.
        for name in [
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-256f",
            "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-256f",
            "SLH-DSA-SHAKE-256s",
        ] {
            assert!(
                matches!(canonicalize_alg_id(name), Some(CanonicalAlg::Sphincs)),
                "FIPS 205 identifier {name} should map to SPHINCS+"
            );
        }

        // Every pre-FIPS SPHINCS+ name, bare and -simple / -robust suffixed.
        for base in [
            "SPHINCS+-SHA2-128f",
            "SPHINCS+-SHA2-128s",
            "SPHINCS+-SHA2-192f",
            "SPHINCS+-SHA2-192s",
            "SPHINCS+-SHA2-256f",
            "SPHINCS+-SHA2-256s",
            "SPHINCS+-SHAKE-128f",
            "SPHINCS+-SHAKE-128s",
            "SPHINCS+-SHAKE-192f",
            "SPHINCS+-SHAKE-192s",
            "SPHINCS+-SHAKE-256f",
            "SPHINCS+-SHAKE-256s",
        ] {
            for suffix in ["", "-simple", "-robust"] {
                let name = alloc::format!("{base}{suffix}");
                assert!(
                    matches!(canonicalize_alg_id(&name), Some(CanonicalAlg::Sphincs)),
                    "SPHINCS+ identifier {name} should map to SPHINCS+"
                );
            }
        }
    }

    #[test]
    fn level3_upgrade_algorithm_bundle_still_verifies() {
        // Scenario: scif-backend has been upgraded to FALCON-1024 +
        // SPHINCS+-SHA2-192f. A customer verifier built BEFORE the
        // upgrade must continue to verify responses from the upgraded
        // server without a verifier release.
        let body = b"body";
        let hash = sha3_of(body);
        let ts = 9_000;
        let receipt_hex = fabricate_receipt_hex(hash, ts, ALG_ALL_THREE);

        let substrate_hex = hex::encode(hash);
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "ML-DSA-65, FALCON-1024, SLH-DSA-SHA2-192f",
            ts,
        );

        let result = verify_structural(body, &headers).unwrap();
        assert!(
            result.is_valid(),
            "Level 3 upgrade bundle should still verify: {}",
            result.summary()
        );
    }

    #[test]
    fn sphincs_only_receipt_verifies_with_sphincs_only_header() {
        let body = b"body";
        let hash = sha3_of(body);
        let ts = 8_000;
        let receipt_hex = fabricate_receipt_hex(hash, ts, ALG_SPHINCS);

        let substrate_hex = hex::encode(hash);
        let headers = Headers::from_strs(
            &substrate_hex,
            &receipt_hex,
            "SPHINCS+-SHA2-128f",
            ts,
        );

        let result = verify_structural(body, &headers).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn constant_time_eq_rejects_last_byte_difference() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(constant_time_eq(&a, &b));
        b[31] = 1;
        assert!(!constant_time_eq(&a, &b));
        a[0] = 255;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn empty_body_computes_known_sha3() {
        let body: &[u8] = b"";
        let hash = sha3_of(body);
        assert_eq!(hex::encode(hash), KNOWN_SHA3_EMPTY);
    }

}
