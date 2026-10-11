//! SRTP keying material types and profiles used by DTLS-SRTP.
use std::ops::Deref;

/// Keying material used as master key for SRTP.
pub struct KeyingMaterial(Vec<u8>);

impl KeyingMaterial {
    /// Create a new wrapper for DTLS-SRTP keying material bytes.
    pub fn new(m: &[u8]) -> Self {
        KeyingMaterial(m.to_vec())
    }
}

impl Deref for KeyingMaterial {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for KeyingMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyingMaterial")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
/// Supported SRTP protection profiles (RFC 5764 negotiation).
///
/// The only profile uses ChaCha20-Poly1305 with a 12-byte IV derived from SSRC,
/// packet index and salt, and a 16-byte authentication tag. Its wire identifier
/// is a placeholder until registered. Peers must agree on this profile.
/// The DTLS handshake that keys it uses RFC 7905 ChaCha20-Poly1305 suites.
pub enum SrtpProfile {
    /// AEAD_CHACHA20_POLY1305: 32-byte master key, 12-byte master salt.
    CHACHA20_POLY1305,
}

impl SrtpProfile {
    /// All supported profiles ordered by preference.
    pub const ALL: &'static [SrtpProfile] = &[SrtpProfile::CHACHA20_POLY1305];

    /// The length of keying material to extract from the DTLS session in bytes.
    pub fn keying_material_len(&self) -> usize {
        match self {
            // MASTER_KEY_LEN * 2 + MASTER_SALT_LEN * 2
            SrtpProfile::CHACHA20_POLY1305 => 32 * 2 + 12 * 2,
        }
    }
}

impl std::fmt::Display for SrtpProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SrtpProfile::CHACHA20_POLY1305 => write!(f, "SRTP_AEAD_CHACHA20_POLY1305"),
        }
    }
}
