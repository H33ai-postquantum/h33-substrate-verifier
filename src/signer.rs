//! H33-74 Signing — Three-Family Post-Quantum Signature Bundle
//!
//! Three independent NIST-standardized PQ signature families:
//!   - ML-DSA-65 (FIPS 204, MLWE lattice, Level 3)
//!   - FALCON-512 (Draft FIPS 206, NTRU lattice, Level 1)
//!   - SLH-DSA-SHA2-128f (FIPS 205, hash-based, Level 1)
//!
//! All signatures use detached sign/verify APIs for correct interop.

use crate::types::{SigningSubstrate, SUBSTRATE_SIZE};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_falcon::falcon512;
use pqcrypto_sphincsplus::sphincssha2128fsimple;
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};
use sha3::{Sha3_256, Digest};

/// Which algorithm signed the substrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    /// ML-DSA-65 (Dilithium) — NIST FIPS 204, Level 3
    Dilithium = 0x01,
    /// FALCON-512 — NTRU lattice, NIST alternate
    Falcon = 0x02,
    /// SLH-DSA-SHA2-128f (SPHINCS+) — NIST FIPS 205, Level 1
    Sphincs = 0x03,
    /// H33-3-Key: ML-DSA-65 + FALCON-512 + SLH-DSA-SHA2-128f
    ThreeKey = 0x04,
}

/// A substrate with its signature attached.
#[derive(Debug)]
pub struct SignedSubstrate {
    /// The raw 58-byte substrate
    pub substrate_bytes: [u8; SUBSTRATE_SIZE],
    /// The 32-byte signing message (SHA3-256 of substrate)
    pub signing_message: [u8; 32],
    /// Which algorithm was used
    pub algorithm: SignatureAlgorithm,
    /// The detached signature bytes (primary)
    pub signature: Vec<u8>,
    /// For 3-Key: all three signatures
    pub nested_signatures: Option<ThreeKeySignatures>,
    /// Signing timestamp (from substrate)
    pub timestamp_ms: u64,
}

/// Three independent detached signatures over the same signing message.
#[derive(Debug)]
pub struct ThreeKeySignatures {
    /// ML-DSA-65 detached signature (~3,309 bytes)
    pub dilithium: Vec<u8>,
    /// FALCON-512 detached signature (~666 bytes)
    pub falcon: Vec<u8>,
    /// SLH-DSA-SHA2-128f detached signature (17,088 bytes)
    pub sphincs: Vec<u8>,
}

/// Signs substrates with one or more PQ algorithms.
pub struct SubstrateSigner {
    /// ML-DSA-65 keypair
    dilithium_sk: Vec<u8>,
    dilithium_pk: Vec<u8>,
    /// FALCON-512 keypair
    falcon_sk: Vec<u8>,
    falcon_pk: Vec<u8>,
    /// SLH-DSA-SHA2-128f keypair
    sphincs_sk: Vec<u8>,
    sphincs_pk: Vec<u8>,
}

impl SubstrateSigner {
    /// Generate fresh keys for all three PQ families.
    pub fn generate() -> Self {
        // ML-DSA-65 keygen (MLWE lattice, Level 3)
        let (dil_pk, dil_sk) = mldsa65::keypair();
        let dil_pk_bytes = pqcrypto_traits::sign::PublicKey::as_bytes(&dil_pk).to_vec();
        let dil_sk_bytes = pqcrypto_traits::sign::SecretKey::as_bytes(&dil_sk).to_vec();

        // FALCON-512 keygen (NTRU lattice, Level 1)
        let (fal_pk, fal_sk) = falcon512::keypair();
        let fal_pk_bytes = pqcrypto_traits::sign::PublicKey::as_bytes(&fal_pk).to_vec();
        let fal_sk_bytes = pqcrypto_traits::sign::SecretKey::as_bytes(&fal_sk).to_vec();

        // SLH-DSA-SHA2-128f keygen (hash-based, Level 1)
        let (sph_pk, sph_sk) = sphincssha2128fsimple::keypair();
        let sph_pk_bytes = pqcrypto_traits::sign::PublicKey::as_bytes(&sph_pk).to_vec();
        let sph_sk_bytes = pqcrypto_traits::sign::SecretKey::as_bytes(&sph_sk).to_vec();

        Self {
            dilithium_sk: dil_sk_bytes,
            dilithium_pk: dil_pk_bytes,
            falcon_sk: fal_sk_bytes,
            falcon_pk: fal_pk_bytes,
            sphincs_sk: sph_sk_bytes,
            sphincs_pk: sph_pk_bytes,
        }
    }

    /// Sign with all three PQ families — detached signatures.
    ///
    /// Three independent mathematical hardness assumptions:
    ///   ML-DSA-65:          MLWE (module lattice)
    ///   FALCON-512:         NTRU-SIS (NTRU lattice)
    ///   SLH-DSA-SHA2-128f:  SHA2-256 pre-image resistance (hash-based)
    ///
    /// Forgery requires breaking all three simultaneously.
    pub fn sign_three_key(&self, substrate: &SigningSubstrate) -> SignedSubstrate {
        let msg = substrate.signing_message();

        // ML-DSA-65 — detached signature
        let dil_sk = mldsa65::SecretKey::from_bytes(&self.dilithium_sk)
            .expect("Invalid ML-DSA-65 SK");
        let dil_det = mldsa65::detached_sign(&msg, &dil_sk);
        let dil_sig = pqcrypto_traits::sign::DetachedSignature::as_bytes(&dil_det).to_vec();

        // FALCON-512 — detached signature
        let fal_sk = falcon512::SecretKey::from_bytes(&self.falcon_sk)
            .expect("Invalid FALCON-512 SK");
        let fal_det = falcon512::detached_sign(&msg, &fal_sk);
        let fal_sig = pqcrypto_traits::sign::DetachedSignature::as_bytes(&fal_det).to_vec();

        // SLH-DSA-SHA2-128f — detached signature
        let sph_sk = sphincssha2128fsimple::SecretKey::from_bytes(&self.sphincs_sk)
            .expect("Invalid SLH-DSA SK");
        let sph_det = sphincssha2128fsimple::detached_sign(&msg, &sph_sk);
        let sph_sig = pqcrypto_traits::sign::DetachedSignature::as_bytes(&sph_det).to_vec();

        SignedSubstrate {
            substrate_bytes: substrate.to_bytes(),
            signing_message: msg,
            algorithm: SignatureAlgorithm::ThreeKey,
            signature: dil_sig.clone(), // primary = ML-DSA-65
            nested_signatures: Some(ThreeKeySignatures {
                dilithium: dil_sig,
                falcon: fal_sig,
                sphincs: sph_sig,
            }),
            timestamp_ms: substrate.timestamp_ms(),
        }
    }

    /// Sign with ML-DSA-65 only (detached).
    pub fn sign_dilithium(&self, substrate: &SigningSubstrate) -> SignedSubstrate {
        let msg = substrate.signing_message();
        let sk = mldsa65::SecretKey::from_bytes(&self.dilithium_sk)
            .expect("Invalid ML-DSA-65 SK");
        let det = mldsa65::detached_sign(&msg, &sk);
        let sig = pqcrypto_traits::sign::DetachedSignature::as_bytes(&det).to_vec();

        SignedSubstrate {
            substrate_bytes: substrate.to_bytes(),
            signing_message: msg,
            algorithm: SignatureAlgorithm::Dilithium,
            signature: sig,
            nested_signatures: None,
            timestamp_ms: substrate.timestamp_ms(),
        }
    }

    /// Sign with FALCON-512 only (detached).
    pub fn sign_falcon(&self, substrate: &SigningSubstrate) -> SignedSubstrate {
        let msg = substrate.signing_message();
        let sk = falcon512::SecretKey::from_bytes(&self.falcon_sk)
            .expect("Invalid FALCON-512 SK");
        let det = falcon512::detached_sign(&msg, &sk);
        let sig = pqcrypto_traits::sign::DetachedSignature::as_bytes(&det).to_vec();

        SignedSubstrate {
            substrate_bytes: substrate.to_bytes(),
            signing_message: msg,
            algorithm: SignatureAlgorithm::Falcon,
            signature: sig,
            nested_signatures: None,
            timestamp_ms: substrate.timestamp_ms(),
        }
    }

    /// Sign with SLH-DSA-SHA2-128f only (detached).
    pub fn sign_sphincs(&self, substrate: &SigningSubstrate) -> SignedSubstrate {
        let msg = substrate.signing_message();
        let sk = sphincssha2128fsimple::SecretKey::from_bytes(&self.sphincs_sk)
            .expect("Invalid SLH-DSA SK");
        let det = sphincssha2128fsimple::detached_sign(&msg, &sk);
        let sig = pqcrypto_traits::sign::DetachedSignature::as_bytes(&det).to_vec();

        SignedSubstrate {
            substrate_bytes: substrate.to_bytes(),
            signing_message: msg,
            algorithm: SignatureAlgorithm::Sphincs,
            signature: sig,
            nested_signatures: None,
            timestamp_ms: substrate.timestamp_ms(),
        }
    }

    // Public key accessors
    pub fn dilithium_pk(&self) -> &[u8] { &self.dilithium_pk }
    pub fn falcon_pk(&self) -> &[u8] { &self.falcon_pk }
    pub fn sphincs_pk(&self) -> &[u8] { &self.sphincs_pk }

    /// Backward-compatible accessor (old code references ed25519_pk for the third family)
    pub fn ed25519_pk(&self) -> &[u8] { &self.sphincs_pk }
}
