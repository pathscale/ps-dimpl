//! HMAC implementation using RustCrypto.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use zeroize::Zeroize;

use super::super::HmacProvider;
use crate::types::HashAlgorithm;
use crate::{CryptoError, CryptoOperation};

/// HMAC provider implementation.
#[derive(Debug)]
pub(crate) struct RustCryptoHmacProvider;

impl HmacProvider for RustCryptoHmacProvider {
    fn hmac(
        &self,
        hash: HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match hash {
            HashAlgorithm::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| CryptoError::OperationFailed(CryptoOperation::ComputeHmac))?;
                mac.update(data);
                let out = &mut out[..hash.output_len()];
                let mut result = mac.finalize().into_bytes();
                out.copy_from_slice(&result);
                result.as_mut_slice().zeroize();
                Ok(out.len())
            }
            HashAlgorithm::SHA384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| CryptoError::OperationFailed(CryptoOperation::ComputeHmac))?;
                mac.update(data);
                let out = &mut out[..hash.output_len()];
                let mut result = mac.finalize().into_bytes();
                out.copy_from_slice(&result);
                result.as_mut_slice().zeroize();
                Ok(out.len())
            }
            _ => Err(CryptoError::UnsupportedHmacHash(hash)),
        }
    }
}

/// Static instance of the HMAC provider.
pub(crate) static HMAC_PROVIDER: RustCryptoHmacProvider = RustCryptoHmacProvider;
