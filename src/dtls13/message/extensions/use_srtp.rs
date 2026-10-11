//! The use_srtp extension is framed the same way in DTLS 1.3 (RFC 5764 carried over by RFC 9147), so it
//! shares the DTLS 1.2 definitions: one place holds the profile list and its wire value.
pub use crate::dtls12::message::{SrtpProfileId, UseSrtpExtension};
