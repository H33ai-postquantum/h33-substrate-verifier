//! The 42-byte `CompactReceipt` wire format.
//!
//! Layout (v1):
//!
//! ```text
//! Offset  Size  Field                Description
//! ──────  ────  ─────                ───────────
//! 0       1     version              Always 0x01 for v1.
//! 1       32    verification_hash    SHA3-256("h33:pq3:v1:" ||
//!                                              signing_message ||
//!                                              dil_pk || fal_pk || sph_pk ||
//!                                              dil_sig || fal_sig || sph_sig)
//! 33      8     verified_at_ms       Milliseconds since Unix epoch, big-endian.
//! 41      1     algorithm_flags      Bit flags: 0x01=Dilithium 0x02=FALCON 0x04=SPHINCS+
//! ──────  ────
//! Total:  42 bytes
//! ```

use crate::error::VerifierError;

/// Total size of a v1 `CompactReceipt` in bytes.
pub const RECEIPT_SIZE: usize = 42;

/// Schema version byte for v1 receipts.
pub const RECEIPT_VERSION: u8 = 0x01;

/// Offset of the `verification_hash` field.
pub const VERIFICATION_HASH_OFFSET: usize = 1;

/// Size of the `verification_hash` field.
pub const VERIFICATION_HASH_SIZE: usize = 32;

/// Offset of the `verified_at_ms` field.
pub const VERIFIED_AT_OFFSET: usize = 33;

/// Size of the `verified_at_ms` field.
pub const VERIFIED_AT_SIZE: usize = 8;

/// Offset of the `algorithm_flags` byte.
pub const ALGORITHM_FLAGS_OFFSET: usize = 41;

/// Bit flag indicating Dilithium (ML-DSA-65) was verified.
pub const ALG_DILITHIUM: u8 = 0b0000_0001;

/// Bit flag indicating FALCON-512 was verified.
pub const ALG_FALCON: u8 = 0b0000_0010;

/// Bit flag indicating SPHINCS+-SHA2-128f was verified.
pub const ALG_SPHINCS: u8 = 0b0000_0100;

/// Bitmask of every algorithm flag the current verifier build
/// understands. Any bits set outside this mask will trigger
/// [`VerifierError::UnknownAlgorithmBits`].
pub const ALG_KNOWN_MASK: u8 = ALG_DILITHIUM | ALG_FALCON | ALG_SPHINCS;

/// Bit flag for the "all three" case, returned by
/// [`AlgorithmFlags::all_three`].
pub const ALG_ALL_THREE: u8 = ALG_DILITHIUM | ALG_FALCON | ALG_SPHINCS;

/// Typed view of the algorithm flags byte from a decoded
/// [`CompactReceipt`].
///
/// # Examples
///
/// ```
/// use h33_substrate_verifier::AlgorithmFlags;
///
/// let flags = AlgorithmFlags::from_byte(0b0000_0111);
/// assert!(flags.has_dilithium());
/// assert!(flags.has_falcon());
/// assert!(flags.has_sphincs());
/// assert_eq!(flags.count(), 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmFlags(u8);

impl AlgorithmFlags {
    /// The "all three families present" bit set.
    #[must_use]
    pub const fn all_three() -> Self {
        Self(ALG_ALL_THREE)
    }

    /// Construct from a raw byte. Does not validate that the bits are
    /// recognized — use
    /// [`validated_from_byte`](Self::validated_from_byte) for that.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        Self(byte)
    }

    /// Construct from a raw byte, returning an error if unknown bits
    /// are set.
    pub const fn validated_from_byte(byte: u8) -> Result<Self, VerifierError> {
        if byte & !ALG_KNOWN_MASK != 0 {
            return Err(VerifierError::UnknownAlgorithmBits { flags: byte });
        }
        Ok(Self(byte))
    }

    /// Raw byte value.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Does the flag set include Dilithium?
    #[must_use]
    pub const fn has_dilithium(self) -> bool {
        self.0 & ALG_DILITHIUM != 0
    }

    /// Does the flag set include FALCON?
    #[must_use]
    pub const fn has_falcon(self) -> bool {
        self.0 & ALG_FALCON != 0
    }

    /// Does the flag set include SPHINCS+?
    #[must_use]
    pub const fn has_sphincs(self) -> bool {
        self.0 & ALG_SPHINCS != 0
    }

    /// Count how many families are present.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }
}

/// A decoded 42-byte `CompactReceipt`.
///
/// Construct one from the `X-H33-Receipt` header bytes with
/// [`Self::from_bytes`] or from the hex-encoded header value with
/// [`Self::from_hex`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactReceipt {
    verification_hash: [u8; VERIFICATION_HASH_SIZE],
    verified_at_ms: u64,
    flags: AlgorithmFlags,
}

impl CompactReceipt {
    /// Parse a receipt from exactly 42 bytes.
    ///
    /// Returns [`VerifierError::InvalidReceiptSize`] if the slice is the
    /// wrong length, and [`VerifierError::UnsupportedReceiptVersion`]
    /// if the first byte is not [`RECEIPT_VERSION`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifierError> {
        if bytes.len() != RECEIPT_SIZE {
            return Err(VerifierError::InvalidReceiptSize {
                actual: bytes.len(),
                expected: RECEIPT_SIZE,
            });
        }
        // Safe because we just checked the length.
        let version = bytes.first().copied().unwrap_or(0);
        if version != RECEIPT_VERSION {
            return Err(VerifierError::UnsupportedReceiptVersion {
                actual: version,
                expected: RECEIPT_VERSION,
            });
        }

        let mut verification_hash = [0u8; VERIFICATION_HASH_SIZE];
        let hash_end = VERIFICATION_HASH_OFFSET + VERIFICATION_HASH_SIZE;
        let hash_slice = bytes
            .get(VERIFICATION_HASH_OFFSET..hash_end)
            .ok_or(VerifierError::InvalidReceiptSize {
                actual: bytes.len(),
                expected: RECEIPT_SIZE,
            })?;
        verification_hash.copy_from_slice(hash_slice);

        let mut ts_bytes = [0u8; VERIFIED_AT_SIZE];
        let ts_end = VERIFIED_AT_OFFSET + VERIFIED_AT_SIZE;
        let ts_slice = bytes
            .get(VERIFIED_AT_OFFSET..ts_end)
            .ok_or(VerifierError::InvalidReceiptSize {
                actual: bytes.len(),
                expected: RECEIPT_SIZE,
            })?;
        ts_bytes.copy_from_slice(ts_slice);
        let verified_at_ms = u64::from_be_bytes(ts_bytes);

        let flags_byte = bytes
            .get(ALGORITHM_FLAGS_OFFSET)
            .copied()
            .ok_or(VerifierError::InvalidReceiptSize {
                actual: bytes.len(),
                expected: RECEIPT_SIZE,
            })?;
        let flags = AlgorithmFlags::validated_from_byte(flags_byte)?;

        Ok(Self {
            verification_hash,
            verified_at_ms,
            flags,
        })
    }

    /// Parse a receipt from the hex string used in the `X-H33-Receipt`
    /// HTTP header. The input must be exactly 84 hex characters
    /// (= 42 bytes).
    pub fn from_hex(hex_str: &str) -> Result<Self, VerifierError> {
        if hex_str.len() != RECEIPT_SIZE * 2 {
            return Err(VerifierError::InvalidReceiptHeaderLength {
                actual: hex_str.len(),
            });
        }
        let bytes = hex::decode(hex_str).map_err(|e| {
            VerifierError::InvalidReceiptHeaderHex(alloc::format!("{e}"))
        })?;
        Self::from_bytes(&bytes)
    }

    /// The 32-byte verification hash embedded in the receipt.
    #[must_use]
    pub const fn verification_hash(&self) -> &[u8; VERIFICATION_HASH_SIZE] {
        &self.verification_hash
    }

    /// Unix timestamp in milliseconds when the receipt was issued.
    #[must_use]
    pub const fn verified_at_ms(&self) -> u64 {
        self.verified_at_ms
    }

    /// Typed view of the algorithm flags byte.
    #[must_use]
    pub const fn flags(&self) -> AlgorithmFlags {
        self.flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a known-valid 42-byte receipt for tests.
    fn fixture_bytes() -> [u8; RECEIPT_SIZE] {
        let mut bytes = [0u8; RECEIPT_SIZE];
        bytes[0] = RECEIPT_VERSION;
        // verification_hash: 32 bytes of 0xAB
        for b in &mut bytes[VERIFICATION_HASH_OFFSET..VERIFIED_AT_OFFSET] {
            *b = 0xAB;
        }
        // verified_at_ms: 0x0000_0000_1234_5678 big-endian
        bytes[VERIFIED_AT_OFFSET..VERIFIED_AT_OFFSET + VERIFIED_AT_SIZE]
            .copy_from_slice(&0x1234_5678_u64.to_be_bytes());
        // flags: all three
        bytes[ALGORITHM_FLAGS_OFFSET] = ALG_ALL_THREE;
        bytes
    }

    #[test]
    fn parses_known_good_receipt() {
        let receipt = CompactReceipt::from_bytes(&fixture_bytes()).unwrap();
        assert_eq!(receipt.verified_at_ms(), 0x1234_5678);
        assert!(receipt.flags().has_dilithium());
        assert!(receipt.flags().has_falcon());
        assert!(receipt.flags().has_sphincs());
        assert_eq!(receipt.flags().count(), 3);
        assert_eq!(receipt.verification_hash()[0], 0xAB);
        assert_eq!(receipt.verification_hash()[31], 0xAB);
    }

    #[test]
    fn rejects_wrong_size() {
        let too_small = [0u8; RECEIPT_SIZE - 1];
        assert!(matches!(
            CompactReceipt::from_bytes(&too_small),
            Err(VerifierError::InvalidReceiptSize { actual: 41, .. })
        ));

        let too_big = [0u8; RECEIPT_SIZE + 1];
        assert!(matches!(
            CompactReceipt::from_bytes(&too_big),
            Err(VerifierError::InvalidReceiptSize { actual: 43, .. })
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = fixture_bytes();
        bytes[0] = 0x02;
        assert!(matches!(
            CompactReceipt::from_bytes(&bytes),
            Err(VerifierError::UnsupportedReceiptVersion {
                actual: 0x02,
                expected: 0x01
            })
        ));
    }

    #[test]
    fn rejects_unknown_algorithm_bits() {
        let mut bytes = fixture_bytes();
        bytes[ALGORITHM_FLAGS_OFFSET] = 0b0000_1111; // bit 3 is unknown
        assert!(matches!(
            CompactReceipt::from_bytes(&bytes),
            Err(VerifierError::UnknownAlgorithmBits { flags: 0b0000_1111 })
        ));
    }

    #[test]
    fn accepts_partial_algorithm_sets() {
        // Dilithium only
        let mut bytes = fixture_bytes();
        bytes[ALGORITHM_FLAGS_OFFSET] = ALG_DILITHIUM;
        let receipt = CompactReceipt::from_bytes(&bytes).unwrap();
        assert!(receipt.flags().has_dilithium());
        assert!(!receipt.flags().has_falcon());
        assert!(!receipt.flags().has_sphincs());
        assert_eq!(receipt.flags().count(), 1);

        // Dilithium + FALCON, no SPHINCS+
        bytes[ALGORITHM_FLAGS_OFFSET] = ALG_DILITHIUM | ALG_FALCON;
        let receipt = CompactReceipt::from_bytes(&bytes).unwrap();
        assert_eq!(receipt.flags().count(), 2);
    }

    #[test]
    fn parses_hex_from_header() {
        let bytes = fixture_bytes();
        let hex_str = hex::encode(bytes);
        let receipt = CompactReceipt::from_hex(&hex_str).unwrap();
        assert_eq!(receipt.verified_at_ms(), 0x1234_5678);
    }

    #[test]
    fn rejects_wrong_hex_length() {
        // 83 chars, not 84
        let short = "ab".repeat(41) + "a";
        assert!(matches!(
            CompactReceipt::from_hex(&short),
            Err(VerifierError::InvalidReceiptHeaderLength { actual: 83 })
        ));
    }

    #[test]
    fn rejects_invalid_hex_characters() {
        // Right length, wrong charset
        let bad = "z".repeat(RECEIPT_SIZE * 2);
        assert!(matches!(
            CompactReceipt::from_hex(&bad),
            Err(VerifierError::InvalidReceiptHeaderHex(_))
        ));
    }
}
