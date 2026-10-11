//! Certificate generation and formatting utilities exposed via the public `certificate` module.
//!
//! This module provides helpers to generate self-signed certificates suitable for DTLS,
//! compute fingerprints, and format them for display.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use p256::ecdsa::{DerSignature, SigningKey};
use pkcs8::EncodePrivateKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::Encode;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

const CERTIFICATE_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Certificate utility error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    /// Invalid certificate format
    InvalidFormat,
    /// Fingerprint verification failed
    FingerprintMismatch,
    /// Certificate generation failed
    GenerationFailed,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertificateError::InvalidFormat => write!(f, "Invalid certificate format"),
            CertificateError::FingerprintMismatch => write!(f, "Fingerprint mismatch"),
            CertificateError::GenerationFailed => write!(f, "Certificate generation failed"),
        }
    }
}

impl std::error::Error for CertificateError {}

pub use crate::DtlsCertificate;

/// Generate a self-signed certificate for DTLS
pub fn generate_self_signed_certificate() -> Result<DtlsCertificate, CertificateError> {
    let mut rng = OsRng;
    let signing_key = SigningKey::random(&mut rng);
    let mut serial = [0u8; 16];
    rng.try_fill_bytes(&mut serial)
        .map_err(|_| CertificateError::GenerationFailed)?;
    // RFC 5280 requires a positive, nonzero serial number.
    serial[0] |= 1;

    let subject =
        Name::from_str("CN=DTLS Peer,O=DTLS").map_err(|_| CertificateError::GenerationFailed)?;
    let public_key = SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key())
        .map_err(|_| CertificateError::GenerationFailed)?;
    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::new(&serial).map_err(|_| CertificateError::GenerationFailed)?,
        Validity::from_now(CERTIFICATE_LIFETIME).map_err(|_| CertificateError::GenerationFailed)?,
        subject,
        public_key,
        &signing_key,
    )
    .map_err(|_| CertificateError::GenerationFailed)?;
    let certificate = builder
        .build::<DerSignature>()
        .map_err(|_| CertificateError::GenerationFailed)?
        .to_der()
        .map_err(|_| CertificateError::GenerationFailed)?;
    let private_key = signing_key
        .to_pkcs8_der()
        .map_err(|_| CertificateError::GenerationFailed)?
        .as_bytes()
        .to_vec();

    Ok(DtlsCertificate {
        certificate,
        private_key,
    })
}

/// Calculate a certificate fingerprint using SHA-256
pub fn calculate_fingerprint(cert_der: &[u8]) -> Vec<u8> {
    // Use SHA-256 to calculate the fingerprint
    Sha256::digest(cert_der).to_vec()
}

/// Format a fingerprint as a colon-separated hex string
/// Example: "AF:12:F6:..."
pub fn format_fingerprint(fingerprint: &[u8]) -> String {
    fingerprint
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<String>>()
        .join(":")
}

impl DtlsCertificate {
    /// Returns the certificate fingerprint as raw bytes.
    ///
    /// The fingerprint is computed by hashing the DER-encoded certificate
    /// with SHA-256 and is therefore 32 bytes long.
    pub fn fingerprint(&self) -> Vec<u8> {
        calculate_fingerprint(&self.certificate)
    }

    /// Returns the certificate fingerprint as a human-readable string.
    ///
    /// The string is the SHA-256 fingerprint formatted as uppercase
    /// hex byte pairs separated by colons, for example "AF:12:F6:...".
    pub fn fingerprint_str(&self) -> String {
        format_fingerprint(&self.fingerprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_signed_certificate() {
        // Generate a certificate
        let cert = generate_self_signed_certificate().unwrap();

        // Check certificate format
        assert!(!cert.certificate.is_empty());
        assert!(!cert.private_key.is_empty());

        // Fingerprint should be 32 bytes (SHA-256)
        assert_eq!(cert.fingerprint().len(), 32);
    }

    #[test]
    fn test_unique_serial_numbers() {
        // Generate two certificates
        let cert1 = generate_self_signed_certificate().unwrap();
        let cert2 = generate_self_signed_certificate().unwrap();

        // Fingerprints should be different (unique serial numbers + keys)
        assert_ne!(cert1.fingerprint(), cert2.fingerprint());

        // Parse the certificates to verify serial numbers are different
        use der::Decode;
        use x509_cert::Certificate as X509Certificate;
        // unwrap: both certificates were generated as valid DER above
        let parsed1 = X509Certificate::from_der(&cert1.certificate).unwrap();
        let parsed2 = X509Certificate::from_der(&cert2.certificate).unwrap();
        assert_ne!(
            parsed1.tbs_certificate.serial_number, parsed2.tbs_certificate.serial_number,
            "Serial numbers must be unique for Firefox compatibility"
        );
    }

    #[test]
    fn test_fingerprint_formatting() {
        let test_fingerprint = vec![0xAF, 0x12, 0xF6, 0x38, 0x2A];
        let formatted = format_fingerprint(&test_fingerprint);
        assert_eq!(formatted, "AF:12:F6:38:2A");

        // Test with an actual generated certificate
        let cert = generate_self_signed_certificate().unwrap();
        let formatted = format_fingerprint(&cert.fingerprint());

        // Verify the format
        assert_eq!(formatted.len(), 95); // 32 bytes * 3 - 1 = 95 (32 hex pairs with : between them)
        assert!(formatted.contains(':'));

        // Each segment should be 2 hex chars
        for segment in formatted.split(':') {
            assert_eq!(segment.len(), 2);
            // Verify it's valid hex
            assert!(u8::from_str_radix(segment, 16).is_ok());
        }
    }
}
