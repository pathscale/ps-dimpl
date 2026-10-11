//! Cipher suite implementations using RustCrypto.
//!
//! DTLS 1.2 offers only TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (RFC 7905)
//! and DTLS 1.3 only TLS_CHACHA20_POLY1305_SHA256.
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::ChaCha20Poly1305 as ChaCha20Poly1305Aead;
use chacha20poly1305::aead::AeadInPlace;

use super::super::{Cipher, SupportedDtls12CipherSuite, SupportedDtls13CipherSuite};
use crate::buffer::{Buf, TmpBuf};
use crate::crypto::{Aad, Nonce};
use crate::dtls12::message::Dtls12CipherSuite;
use crate::error::bounded_error_len;
use crate::types::{Dtls13CipherSuite, HashAlgorithm};
use crate::{CryptoError, CryptoOperation};

/// ChaCha20-Poly1305 cipher implementation using RustCrypto.
struct ChaCha20Poly1305Cipher {
    cipher: Box<ChaCha20Poly1305Aead>,
}

impl std::fmt::Debug for ChaCha20Poly1305Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305Cipher")
            .finish_non_exhaustive()
    }
}

impl ChaCha20Poly1305Cipher {
    fn new(key: &[u8]) -> Result<Self, CryptoError> {
        use chacha20poly1305::KeyInit;
        if key.len() != 32 {
            return Err(CryptoError::InvalidChacha20Poly1305KeySize {
                actual: bounded_error_len(key.len()),
            });
        }
        let key = chacha20poly1305::Key::from_slice(key);
        Ok(ChaCha20Poly1305Cipher {
            cipher: Box::new(ChaCha20Poly1305Aead::new(key)),
        })
    }
}

impl Cipher for ChaCha20Poly1305Cipher {
    fn encrypt(&mut self, data: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), CryptoError> {
        let nonce_array: [u8; 12] = nonce[..12]
            .try_into()
            .map_err(|_| CryptoError::InvalidNonce)?;

        use generic_array::{GenericArray, typenum::U12};
        let chacha_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
        self.cipher
            .encrypt_in_place(&chacha_nonce, &aad, data)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Encrypt))?;

        Ok(())
    }

    fn decrypt(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::CiphertextTooShort {
                minimum: 16,
                actual: ciphertext.len() as u8,
            });
        }

        let nonce_array: [u8; 12] = nonce[..12]
            .try_into()
            .map_err(|_| CryptoError::InvalidNonce)?;

        use generic_array::{GenericArray, typenum::U12};
        let chacha_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
        self.cipher
            .decrypt_in_place(&chacha_nonce, &aad, ciphertext)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Decrypt))?;

        Ok(())
    }
}

/// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 cipher suite (RFC 7905).
#[derive(Debug)]
struct ChaCha20Poly1305Sha256;

impl SupportedDtls12CipherSuite for ChaCha20Poly1305Sha256 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 32, 12) // (mac_key_len, enc_key_len, fixed_iv_len)
    }

    fn explicit_nonce_len(&self) -> usize {
        0
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(ChaCha20Poly1305Cipher::new(key)?))
    }
}

/// Static instances of supported DTLS 1.2 cipher suites.
static CHACHA20_POLY1305_SHA256: ChaCha20Poly1305Sha256 = ChaCha20Poly1305Sha256;

/// All supported DTLS 1.2 cipher suites.
pub(super) static ALL_CIPHER_SUITES: &[&dyn SupportedDtls12CipherSuite] =
    &[&CHACHA20_POLY1305_SHA256];

// ============================================================================
// DTLS 1.3 Cipher Suites
// ============================================================================

/// TLS_CHACHA20_POLY1305_SHA256 cipher suite (TLS 1.3 / DTLS 1.3).
#[derive(Debug)]
struct Tls13ChaCha20Poly1305Sha256;

impl SupportedDtls13CipherSuite for Tls13ChaCha20Poly1305Sha256 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::CHACHA20_POLY1305_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_len(&self) -> usize {
        32 // ChaCha20 key
    }

    fn iv_len(&self) -> usize {
        12 // Poly1305 nonce
    }

    fn tag_len(&self) -> usize {
        16 // Poly1305 tag
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(ChaCha20Poly1305Cipher::new(key)?))
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        // RFC 9001 Section 5.4.4: ChaCha20 header protection
        // counter = sample[0..4] (LE u32), nonce = sample[4..16]
        // mask = first 5 bytes of ChaCha20 keystream at given counter
        // unwrap: the slices are exactly 4 and 12 bytes of a 16-byte array
        let counter = u32::from_le_bytes(sample[0..4].try_into().unwrap());
        let nonce: [u8; 12] = sample[4..16].try_into().unwrap();

        let key = chacha20::Key::from_slice(sn_key);
        let nonce = chacha20::Nonce::from_slice(&nonce);

        let mut cipher = chacha20::ChaCha20::new(key, nonce);
        // Seek to the correct block counter position (each block = 64 bytes)
        cipher.seek(counter as u64 * 64);

        let mut out = [0u8; 16];
        cipher.apply_keystream(&mut out);
        out
    }
}

/// Static instances of supported DTLS 1.3 cipher suites.
static TLS13_CHACHA20_POLY1305_SHA256: Tls13ChaCha20Poly1305Sha256 = Tls13ChaCha20Poly1305Sha256;

/// All supported DTLS 1.3 cipher suites.
pub(super) static ALL_DTLS13_CIPHER_SUITES: &[&dyn SupportedDtls13CipherSuite] =
    &[&TLS13_CHACHA20_POLY1305_SHA256];
