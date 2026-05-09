//! H33-74 Verification — Three-Family Post-Quantum Signature Verification
//!
//! Verifies substrates signed under ML-DSA-65, FALCON-512, and SLH-DSA-SHA2-128f.
//! All verification uses detached signature APIs.

use crate::types::{SigningSubstrate, SubstrateError, SUBSTRATE_SIZE};
use crate::signer::{SignedSubstrate, SignatureAlgorithm};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_falcon::falcon512;
use pqcrypto_sphincsplus::sphincssha2128fsimple;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
use sha3::{Sha3_256, Digest};

/// Result of full-chain verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// Substrate deserialized and valid
    pub substrate_valid: bool,
    /// Signing message matches substrate bytes
    pub commitment_valid: bool,
    /// Signature(s) verified
    pub signature_valid: bool,
    /// Which algorithm was verified
    pub algorithm: SignatureAlgorithm,
    /// For 3-Key: individual results
    pub three_key_results: Option<ThreeKeyVerification>,
    /// Total verification time in microseconds
    pub verification_us: u64,
}

#[derive(Debug)]
pub struct ThreeKeyVerification {
    pub dilithium_valid: bool,
    pub falcon_valid: bool,
    pub sphincs_valid: bool,
}

pub struct SubstrateVerifier;

impl SubstrateVerifier {
    /// Verify a signed substrate — full chain.
    ///
    /// 1. Deserialize the 58-byte substrate
    /// 2. Recompute signing message and verify commitment
    /// 3. Verify signature(s) using detached verification
    pub fn verify(
        signed: &SignedSubstrate,
        dilithium_pk: Option<&[u8]>,
        falcon_pk: Option<&[u8]>,
        sphincs_pk: Option<&[u8]>,
    ) -> VerificationResult {
        let start = std::time::Instant::now();

        // Step 1: Deserialize substrate
        let substrate = match SigningSubstrate::from_bytes(&signed.substrate_bytes) {
            Ok(s) => s,
            Err(_) => return VerificationResult {
                substrate_valid: false,
                commitment_valid: false,
                signature_valid: false,
                algorithm: signed.algorithm,
                three_key_results: None,
                verification_us: start.elapsed().as_micros() as u64,
            },
        };

        // Step 2: Recompute signing message and verify commitment
        let recomputed = substrate.signing_message();
        let commitment_valid = recomputed == signed.signing_message;

        // Step 3: Verify signature(s)
        let (signature_valid, three_key_results) = match signed.algorithm {
            SignatureAlgorithm::Dilithium => {
                let pk_bytes = dilithium_pk.expect("Dilithium PK required");
                let valid = Self::verify_dilithium(&signed.signature, &signed.signing_message, pk_bytes);
                (valid, None)
            }
            SignatureAlgorithm::Falcon => {
                let pk_bytes = falcon_pk.expect("FALCON PK required");
                let valid = Self::verify_falcon(&signed.signature, &signed.signing_message, pk_bytes);
                (valid, None)
            }
            SignatureAlgorithm::Sphincs => {
                let pk_bytes = sphincs_pk.expect("SPHINCS+ PK required");
                let valid = Self::verify_sphincs(&signed.signature, &signed.signing_message, pk_bytes);
                (valid, None)
            }
            SignatureAlgorithm::ThreeKey => {
                let nested = signed.nested_signatures.as_ref().expect("3-Key signatures required");
                let dil_valid = dilithium_pk
                    .map(|pk| Self::verify_dilithium(&nested.dilithium, &signed.signing_message, pk))
                    .unwrap_or(false);
                let fal_valid = falcon_pk
                    .map(|pk| Self::verify_falcon(&nested.falcon, &signed.signing_message, pk))
                    .unwrap_or(false);
                let sph_valid = sphincs_pk
                    .map(|pk| Self::verify_sphincs(&nested.sphincs, &signed.signing_message, pk))
                    .unwrap_or(false);

                let all_valid = dil_valid && fal_valid && sph_valid;
                (all_valid, Some(ThreeKeyVerification {
                    dilithium_valid: dil_valid,
                    falcon_valid: fal_valid,
                    sphincs_valid: sph_valid,
                }))
            }
        };

        VerificationResult {
            substrate_valid: true,
            commitment_valid,
            signature_valid,
            algorithm: signed.algorithm,
            three_key_results,
            verification_us: start.elapsed().as_micros() as u64,
        }
    }

    /// Verify a standalone substrate commitment against known FHE output.
    pub fn verify_fhe_binding(substrate: &SigningSubstrate, fhe_output: &[u8]) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(fhe_output);
        let expected: [u8; 32] = hasher.finalize().into();
        constant_time_eq::constant_time_eq_n::<32>(&expected, substrate.fhe_commitment())
    }

    // ── Detached verification helpers ────────────────────────────────

    fn verify_dilithium(sig: &[u8], msg: &[u8; 32], pk_bytes: &[u8]) -> bool {
        let pk = match mldsa65::PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let det_sig = match mldsa65::DetachedSignature::from_bytes(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        mldsa65::verify_detached_signature(&det_sig, msg, &pk).is_ok()
    }

    fn verify_falcon(sig: &[u8], msg: &[u8; 32], pk_bytes: &[u8]) -> bool {
        let pk = match falcon512::PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let det_sig = match falcon512::DetachedSignature::from_bytes(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        falcon512::verify_detached_signature(&det_sig, msg, &pk).is_ok()
    }

    fn verify_sphincs(sig: &[u8], msg: &[u8; 32], pk_bytes: &[u8]) -> bool {
        let pk = match sphincssha2128fsimple::PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let det_sig = match sphincssha2128fsimple::DetachedSignature::from_bytes(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        sphincssha2128fsimple::verify_detached_signature(&det_sig, msg, &pk).is_ok()
    }
}
