//! The 58-byte H33 signing substrate layout.
//!
//! This module is a pure, dependency-free reimplementation of the
//! substrate wire format from the public specification (see
//! `gitlab.com/drata5764111/h33/h33-substrate/SPEC.md`). It is NOT a
//! reference to any internal H33 crate — a verifier that depended on
//! the signer's private code would defeat the purpose of an open
//! reference implementation.
//!
//! ## Byte layout (v1)
//!
//! ```text
//! Offset  Size  Field              Description
//! ──────  ────  ─────              ───────────
//! 0       1     version            Schema version. Always 0x01 for v1.
//! 1       1     computation_type   Domain separator (see ComputationType).
//! 2       32    fhe_commitment     SHA3-256(canonical source bytes).
//! 34      8     timestamp_ms       Millisecond Unix timestamp, big-endian.
//! 42      16    nonce              16 random bytes, unique per signing event.
//! ──────  ────
//! Total:  58 bytes
//! ```
//!
//! The signing message passed to the post-quantum signature algorithms
//! is always `SHA3-256(substrate_bytes)` — exactly 32 bytes regardless
//! of what the substrate committed to.

/// Total size of a v1 substrate in bytes.
pub const SUBSTRATE_SIZE: usize = 58;

/// Schema version byte for v1 substrates.
pub const SUBSTRATE_VERSION: u8 = 0x01;

/// Size of the `fhe_commitment` field in bytes (SHA3-256 digest).
pub const COMMITMENT_SIZE: usize = 32;

/// Size of the `timestamp_ms` field in bytes (`u64` big-endian).
pub const TIMESTAMP_SIZE: usize = 8;

/// Size of the `nonce` field in bytes.
pub const NONCE_SIZE: usize = 16;

/// Offset at which the `fhe_commitment` starts.
pub const COMMITMENT_OFFSET: usize = 2;

/// Offset at which the `timestamp_ms` starts.
pub const TIMESTAMP_OFFSET: usize = COMMITMENT_OFFSET + COMMITMENT_SIZE;

/// Offset at which the `nonce` starts.
pub const NONCE_OFFSET: usize = TIMESTAMP_OFFSET + TIMESTAMP_SIZE;

/// Domain separator values defined by the substrate specification.
///
/// A substrate minted for one computation type can NEVER be confused
/// with a substrate minted for another, because the type byte is
/// covered by the SHA3-256 signing message.
///
/// Values are an append-only enum — once assigned, a value cannot be
/// reused or removed without breaking every historical signature that
/// used the old meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum ComputationType {
    /// FHE biometric authentication match.
    BiometricAuth = 0x01,
    /// FHE fraud scoring result.
    FraudScore = 0x02,
    /// `FedNow` payment attestation.
    FedNowPayment = 0x03,
    /// Solana transaction attestation.
    SolanaAttestation = 0x04,
    /// HATS governance proof.
    HatsGovernance = 0x05,
    /// Bitcoin UTXO quantum-insurance attestation.
    BitcoinUtxo = 0x06,
    /// ZK-KYC identity verification.
    KycVerification = 0x07,
    /// H33-Share cross-institution computation.
    ShareComputation = 0x08,
    /// `ArchiveSign` document attestation.
    ArchiveSign = 0x09,
    /// `MedVault` PHI operation.
    MedVaultPhi = 0x0A,
    /// `VaultKey` secret operation.
    VaultKeyOp = 0x0B,
    /// HTTP API response attestation (Tier 1 substrate response middleware).
    ApiResponse = 0x0C,
    /// Generic FHE computation — catch-all for unrelated uses.
    GenericFhe = 0xFF,
}

impl ComputationType {
    /// Convert from a raw byte. Returns `None` for values the verifier
    /// does not recognize.
    ///
    /// # Examples
    ///
    /// ```
    /// use h33_substrate_verifier::ComputationType;
    ///
    /// assert_eq!(ComputationType::from_byte(0x01), Some(ComputationType::BiometricAuth));
    /// assert_eq!(ComputationType::from_byte(0x0C), Some(ComputationType::ApiResponse));
    /// assert_eq!(ComputationType::from_byte(0x42), None);
    /// ```
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::BiometricAuth),
            0x02 => Some(Self::FraudScore),
            0x03 => Some(Self::FedNowPayment),
            0x04 => Some(Self::SolanaAttestation),
            0x05 => Some(Self::HatsGovernance),
            0x06 => Some(Self::BitcoinUtxo),
            0x07 => Some(Self::KycVerification),
            0x08 => Some(Self::ShareComputation),
            0x09 => Some(Self::ArchiveSign),
            0x0A => Some(Self::MedVaultPhi),
            0x0B => Some(Self::VaultKeyOp),
            0x0C => Some(Self::ApiResponse),
            0xFF => Some(Self::GenericFhe),
            _ => None,
        }
    }

    /// Convert to the raw byte value.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_constants_add_up() {
        // Every offset + size combination must cleanly tile the 58-byte
        // substrate with zero overlap and zero gaps.
        assert_eq!(SUBSTRATE_SIZE, 58);
        assert_eq!(COMMITMENT_OFFSET, 2);
        assert_eq!(TIMESTAMP_OFFSET, 34);
        assert_eq!(NONCE_OFFSET, 42);
        assert_eq!(NONCE_OFFSET + NONCE_SIZE, SUBSTRATE_SIZE);
    }

    #[test]
    fn computation_type_round_trip() {
        let all = [
            ComputationType::BiometricAuth,
            ComputationType::FraudScore,
            ComputationType::FedNowPayment,
            ComputationType::SolanaAttestation,
            ComputationType::HatsGovernance,
            ComputationType::BitcoinUtxo,
            ComputationType::KycVerification,
            ComputationType::ShareComputation,
            ComputationType::ArchiveSign,
            ComputationType::MedVaultPhi,
            ComputationType::VaultKeyOp,
            ComputationType::ApiResponse,
            ComputationType::GenericFhe,
        ];
        for ct in all {
            assert_eq!(ComputationType::from_byte(ct.to_byte()), Some(ct));
        }
    }

    #[test]
    fn unrecognized_computation_type_bytes_are_none() {
        assert_eq!(ComputationType::from_byte(0x00), None);
        assert_eq!(ComputationType::from_byte(0x0D), None);
        assert_eq!(ComputationType::from_byte(0x42), None);
        assert_eq!(ComputationType::from_byte(0xFE), None);
    }
}
