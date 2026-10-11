//! DTLS AEAD record formatting types and constants.
//!
//! This module contains types and constants specific to DTLS AEAD record formatting,
//! separate from the pluggable crypto provider abstraction.

use arrayvec::ArrayVec;

use crate::types::{ContentType, Sequence};

/// Fixed IV portion for DTLS AEAD.
///
/// Both DTLS versions use a 12-byte fixed IV and no explicit nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Iv {
    bytes: [u8; 12],
    len: u8,
}

impl Iv {
    pub(crate) fn new(iv: &[u8]) -> Self {
        assert!(
            iv.len() <= 12,
            "invalid IV length: expected <= 12, got {}",
            iv.len()
        );
        let mut bytes = [0u8; 12];
        bytes[..iv.len()].copy_from_slice(iv);
        Self {
            bytes,
            len: iv.len() as u8,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns the full 12-byte backing array.
    ///
    /// Only valid for 12-byte IVs (ChaCha20-Poly1305).
    pub(crate) fn as_12_bytes(&self) -> &[u8; 12] {
        assert_eq!(
            self.len(),
            12,
            "as_12_bytes called on {}-byte IV",
            self.len()
        );
        &self.bytes
    }
}

/// Full AEAD nonce derived from the fixed IV and sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    /// Create a nonce by XORing the IV with the padded sequence number.
    ///
    /// Used by both DTLS 1.2 (ChaCha20-Poly1305) and DTLS 1.3:
    /// nonce = iv XOR pad_left(sequence_number, 12)
    /// See RFC 8446 Section 5.3 / RFC 7905.
    pub(crate) fn xor(iv: &[u8; 12], seq: u64) -> Self {
        let mut nonce = *iv;
        let seq_bytes = seq.to_be_bytes(); // 8 bytes
        // XOR the last 8 bytes of the 12-byte IV with the sequence number
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        Self(nonce)
    }
}

/// Additional Authenticated Data for DTLS records.
///
/// Variable-length to support both DTLS 1.2 (13 bytes) and DTLS 1.3 (3-5 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aad(pub ArrayVec<u8, 13>);

impl Aad {
    /// Create Additional Authenticated Data for a DTLS 1.2 record.
    pub(crate) fn new_dtls12(content_type: ContentType, sequence: Sequence, length: u16) -> Self {
        let mut aad = ArrayVec::new();

        // First set the full 8-byte sequence number
        let seq_bytes = sequence.sequence_number.to_be_bytes();
        // unwrap: eight sequence bytes fit within the 13-byte AAD capacity
        aad.try_extend_from_slice(&seq_bytes).unwrap();

        // Overwrite the first 2 bytes with epoch
        let epoch_bytes = sequence.epoch.to_be_bytes();
        aad[0] = epoch_bytes[0];
        aad[1] = epoch_bytes[1];

        // Content type at index 8
        aad.push(content_type.as_u8());

        // Protocol version bytes (major:minor) at indexes 9-10
        aad.push(0xfe); // DTLS 1.2 major version
        aad.push(0xfd); // DTLS 1.2 minor version

        // Payload length (2 bytes) at indexes 11-12
        // unwrap: eleven bytes are present, leaving space for the two-byte length
        aad.try_extend_from_slice(&length.to_be_bytes()).unwrap();

        Aad(aad)
    }

    /// Create Additional Authenticated Data for a DTLS 1.3 record.
    ///
    /// The AAD is the raw unified header bytes (3-5 bytes).
    pub(crate) fn new_dtls13(header_bytes: &[u8]) -> Self {
        let mut aad = ArrayVec::new();
        // unwrap: header_bytes is at most 5 bytes, well within capacity 13
        aad.try_extend_from_slice(header_bytes).unwrap();
        Aad(aad)
    }
}
