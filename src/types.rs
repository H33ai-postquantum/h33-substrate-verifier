//! Core substrate types — the 58-byte signing payload.

use sha3::{Sha3_256, Digest};
use zeroize::Zeroize;

/// Substrate is always exactly 58 bytes. No exceptions.
pub const SUBSTRATE_SIZE: usize = 58;

/// Current substrate schema version.
pub const SUBSTRATE_VERSION: u8 = 0x01;

/// Domain separator — what type of computation produced this output.
/// Prevents cross-domain attestation replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ComputationType {
    /// Biometric authentication
    BiometricAuth = 0x01,
    /// Fraud scoring
    FraudScore = 0x02,
    /// Payment attestation
    PaymentAttestation = 0x03,
    /// Blockchain transaction attestation
    BlockchainAttestation = 0x04,
    /// Governance proof
    Governance = 0x05,
    /// Healthcare / PHI operation
    HealthcarePhi = 0x06,
    /// Generic FHE computation
    GenericFhe = 0xFF,
}

impl ComputationType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::BiometricAuth),
            0x02 => Some(Self::FraudScore),
            0x03 => Some(Self::PaymentAttestation),
            0x04 => Some(Self::BlockchainAttestation),
            0x05 => Some(Self::Governance),
            0x06 => Some(Self::HealthcarePhi),
            0xFF => Some(Self::GenericFhe),
            // Domain bytes 0x07-0xFE are reserved for registered computation types.
            // Contact H33 for domain registration.
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum SubstrateError {
    EmptyFheOutput,
    InvalidComputationType(u8),
    InvalidSize(usize),
    InvalidVersion(u8),
}

impl std::fmt::Display for SubstrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyFheOutput => write!(f, "FHE output is empty"),
            Self::InvalidComputationType(v) => write!(f, "Invalid computation type: 0x{:02X}", v),
            Self::InvalidSize(s) => write!(f, "Invalid substrate size: {} (expected {})", s, SUBSTRATE_SIZE),
            Self::InvalidVersion(v) => write!(f, "Invalid substrate version: 0x{:02X}", v),
        }
    }
}

impl std::error::Error for SubstrateError {}

/// The 58-byte signing substrate.
///
/// Layout (all big-endian, fixed width, no padding):
/// ```text
/// [0]       version            (1 byte)
/// [1]       computation_type   (1 byte)
/// [2..34]   fhe_commitment     (32 bytes — SHA3-256 of canonical FHE output)
/// [34..42]  timestamp_ms       (8 bytes — millisecond Unix timestamp, big-endian)
/// [42..58]  nonce              (16 bytes — random, anti-replay)
/// ```
#[derive(Clone)]
pub struct SigningSubstrate {
    version: u8,
    computation_type: ComputationType,
    fhe_commitment: [u8; 32],
    timestamp_ms: u64,
    nonce: [u8; 16],
}

impl SigningSubstrate {
    pub fn new(
        computation_type: ComputationType,
        fhe_output: &[u8],
        timestamp_ms: u64,
    ) -> Result<Self, SubstrateError> {
        if fhe_output.is_empty() {
            return Err(SubstrateError::EmptyFheOutput);
        }
        let mut hasher = Sha3_256::new();
        hasher.update(fhe_output);
        let commitment: [u8; 32] = hasher.finalize().into();
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).expect("getrandom failed");
        Ok(Self { version: SUBSTRATE_VERSION, computation_type, fhe_commitment: commitment, timestamp_ms, nonce })
    }

    pub fn from_commitment(
        computation_type: ComputationType,
        commitment: [u8; 32],
        timestamp_ms: u64,
    ) -> Self {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).expect("getrandom failed");
        Self { version: SUBSTRATE_VERSION, computation_type, fhe_commitment: commitment, timestamp_ms, nonce }
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; SUBSTRATE_SIZE] {
        let mut buf = [0u8; SUBSTRATE_SIZE];
        buf[0] = self.version;
        buf[1] = self.computation_type as u8;
        buf[2..34].copy_from_slice(&self.fhe_commitment);
        buf[34..42].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        buf[42..58].copy_from_slice(&self.nonce);
        buf
    }

    #[inline]
    pub fn signing_message(&self) -> [u8; 32] {
        let substrate_bytes = self.to_bytes();
        let mut hasher = Sha3_256::new();
        hasher.update(&substrate_bytes);
        hasher.finalize().into()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SubstrateError> {
        if bytes.len() != SUBSTRATE_SIZE {
            return Err(SubstrateError::InvalidSize(bytes.len()));
        }
        let version = bytes[0];
        if version != SUBSTRATE_VERSION {
            return Err(SubstrateError::InvalidVersion(version));
        }
        let comp_type = ComputationType::from_u8(bytes[1])
            .ok_or(SubstrateError::InvalidComputationType(bytes[1]))?;
        let mut fhe_commitment = [0u8; 32];
        fhe_commitment.copy_from_slice(&bytes[2..34]);
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&bytes[34..42]);
        let timestamp_ms = u64::from_be_bytes(ts_bytes);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[42..58]);
        Ok(Self { version, computation_type: comp_type, fhe_commitment, timestamp_ms, nonce })
    }

    pub fn version(&self) -> u8 { self.version }
    pub fn computation_type(&self) -> ComputationType { self.computation_type }
    pub fn fhe_commitment(&self) -> &[u8; 32] { &self.fhe_commitment }
    pub fn timestamp_ms(&self) -> u64 { self.timestamp_ms }
    pub fn nonce(&self) -> &[u8; 16] { &self.nonce }
}

impl Drop for SigningSubstrate {
    fn drop(&mut self) {
        self.fhe_commitment.zeroize();
        self.nonce.zeroize();
    }
}
