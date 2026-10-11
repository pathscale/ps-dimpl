//! PRF and HKDF key derivation built on top of [`HmacProvider`].
//!
//! Both TLS 1.2 PRF and TLS 1.3 HKDF are pure compositions of HMAC calls.
//! This module provides generic implementations so that crypto backends only
//! need to implement [`HmacProvider`]; no separate PRF or HKDF providers.

use crate::CryptoError;
use crate::buffer::Buf;
use crate::types::HashAlgorithm;

use super::HmacProvider;

/// Maximum HMAC output size we support (SHA-384 = 48 bytes).
const MAX_HASH_LEN: usize = 48;

// ============================================================================
// TLS 1.2 PRF (RFC 5246 Section 5)
// ============================================================================

/// TLS 1.2 PRF: `PRF(secret, label, seed)` writing `output_len` bytes to `out`.
///
/// Uses `scratch` for temporary concatenation of label+seed.
#[allow(clippy::too_many_arguments)]
pub fn prf_tls12(
    hmac: &dyn HmacProvider,
    secret: &[u8],
    label: &str,
    seed: &[u8],
    out: &mut Buf,
    output_len: usize,
    scratch: &mut Buf,
    hash: HashAlgorithm,
) -> Result<(), CryptoError> {
    let mut hmac_a = [0u8; MAX_HASH_LEN];

    // Build label + seed
    scratch.clear();
    scratch.extend_from_slice(label.as_bytes());
    scratch.extend_from_slice(seed);
    let label_seed = scratch.as_ref();

    // A(1) = HMAC(secret, label_seed)
    let hash_len = hmac.hmac(hash, secret, label_seed, &mut hmac_a)?;

    // Build payload = A(i) || label || seed
    scratch.clear();
    scratch.extend_from_slice(&hmac_a[..hash_len]);
    scratch.extend_from_slice(label.as_bytes());
    scratch.extend_from_slice(seed);
    let payload = scratch.as_mut();

    out.clear();
    while out.len() < output_len {
        // P(i) = HMAC(secret, A(i) || label || seed)
        let mut hmac_block = [0u8; MAX_HASH_LEN];
        let block_len = hmac.hmac(hash, secret, payload, &mut hmac_block)?;

        let remaining = output_len - out.len();
        let to_copy = remaining.min(block_len);
        out.extend_from_slice(&hmac_block[..to_copy]);

        if out.len() < output_len {
            // A(i+1) = HMAC(secret, A(i))
            hmac.hmac(hash, secret, &payload[..hash_len], &mut hmac_a)?;
            payload[..hash_len].copy_from_slice(&hmac_a[..hash_len]);
        }
    }

    Ok(())
}

// ============================================================================
// HKDF (RFC 5869)
// ============================================================================

/// HKDF-Extract: `PRK = HMAC-Hash(salt, IKM)`.
pub fn hkdf_extract(
    hmac: &dyn HmacProvider,
    hash: HashAlgorithm,
    salt: &[u8],
    ikm: &[u8],
    out: &mut Buf,
) -> Result<(), CryptoError> {
    out.clear();

    let hash_len = hash.output_len();
    let zero_salt: Vec<u8>;
    let actual_salt = if salt.is_empty() {
        zero_salt = vec![0u8; hash_len];
        &zero_salt[..]
    } else {
        salt
    };

    let mut prk = [0u8; MAX_HASH_LEN];
    let prk_len = hmac.hmac(hash, actual_salt, ikm, &mut prk)?;
    out.extend_from_slice(&prk[..prk_len]);
    Ok(())
}

/// HKDF-Expand: expand `prk` to `output_len` bytes.
pub fn hkdf_expand(
    hmac: &dyn HmacProvider,
    hash: HashAlgorithm,
    prk: &[u8],
    info: &[u8],
    out: &mut Buf,
    output_len: usize,
) -> Result<(), CryptoError> {
    let hash_len = hash.output_len();
    let n = output_len.div_ceil(hash_len);
    if n > 255 {
        return Err(CryptoError::HkdfOutputTooLong);
    }

    let mut t_prev = [0u8; MAX_HASH_LEN];
    let mut t_prev_len = 0usize;

    out.clear();
    for i in 1..=n {
        let mut input = Vec::with_capacity(t_prev_len + info.len() + 1);
        input.extend_from_slice(&t_prev[..t_prev_len]);
        input.extend_from_slice(info);
        input.push(i as u8);

        t_prev_len = hmac.hmac(hash, prk, &input, &mut t_prev)?;

        let remaining = output_len - out.len();
        let to_copy = remaining.min(t_prev_len);
        out.extend_from_slice(&t_prev[..to_copy]);
    }

    Ok(())
}

/// HKDF-Expand-Label for TLS 1.3 (RFC 8446 Section 7.1).
///
/// Uses the `"tls13 "` prefix.
pub fn hkdf_expand_label(
    hmac: &dyn HmacProvider,
    hash: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut Buf,
    output_len: usize,
) -> Result<(), CryptoError> {
    let info = build_hkdf_label(b"tls13 ", label, context, output_len)?;
    hkdf_expand(hmac, hash, secret, &info, out, output_len)
}

/// HKDF-Expand-Label for DTLS 1.3 (RFC 9147).
///
/// Uses the `"dtls13"` prefix (no trailing space).
pub fn hkdf_expand_label_dtls13(
    hmac: &dyn HmacProvider,
    hash: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut Buf,
    output_len: usize,
) -> Result<(), CryptoError> {
    let info = build_hkdf_label(b"dtls13", label, context, output_len)?;
    hkdf_expand(hmac, hash, secret, &info, out, output_len)
}

/// Build the HkdfLabel structure.
///
/// ```text
/// struct {
///     uint16 length;
///     opaque label<6..255> = prefix + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
fn build_hkdf_label(
    prefix: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let full_label_len = prefix.len() + label.len();

    if full_label_len > 255 {
        return Err(CryptoError::HkdfLabelTooLong);
    }
    if context.len() > 255 {
        return Err(CryptoError::HkdfContextTooLong);
    }
    if output_len > 65535 {
        return Err(CryptoError::HkdfOutputLengthTooLarge);
    }

    let info_len = 2 + 1 + full_label_len + 1 + context.len();
    let mut info = Vec::with_capacity(info_len);

    // uint16 length
    info.extend_from_slice(&(output_len as u16).to_be_bytes());
    // opaque label
    info.push(full_label_len as u8);
    info.extend_from_slice(prefix);
    info.extend_from_slice(label);
    // opaque context
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    Ok(info)
}
