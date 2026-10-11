use crate::SrtpProfile;
use crate::buffer::Buf;
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u8, be_u16};
use nom::{Err, IResult};

pub type SrtpProfileVec = ArrayVec<SrtpProfileId, { SrtpProfileId::supported().len() }>;

/// Wire value of the ChaCha20-Poly1305 SRTP profile.
///
/// IANA's DTLS-SRTP registry (RFC 5764, "Specification Required") has no ChaCha20 profile and no
/// private-use range, so this is a placeholder kept far from the assigned {0x00, 0x..} block. It only has
/// to agree between peers running this stack; change it here when a profile is registered.
pub const SRTP_AEAD_CHACHA20_POLY1305_ID: u16 = 0xFF01;

/// DTLS-SRTP protection profile identifiers (RFC 5764 Section 4.1.2 framing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(non_camel_case_types)]
pub enum SrtpProfileId {
    #[default]
    SRTP_AEAD_CHACHA20_POLY1305 = SRTP_AEAD_CHACHA20_POLY1305_ID as isize,
}

impl SrtpProfileId {
    pub fn parse(input: &[u8]) -> IResult<&[u8], SrtpProfileId> {
        let (input, value) = be_u16(input)?;
        match Self::from_u16(value) {
            Some(profile) => Ok((input, profile)),
            None => Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Switch,
            ))),
        }
    }

    fn from_u16(value: u16) -> Option<SrtpProfileId> {
        match value {
            SRTP_AEAD_CHACHA20_POLY1305_ID => Some(SrtpProfileId::SRTP_AEAD_CHACHA20_POLY1305),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> u16 {
        *self as u16
    }

    /// All recognized SRTP profile IDs.
    pub const fn all() -> &'static [SrtpProfileId; 1] {
        &[SrtpProfileId::SRTP_AEAD_CHACHA20_POLY1305]
    }

    /// Supported SRTP profile IDs.
    pub const fn supported() -> &'static [SrtpProfileId; 1] {
        Self::all()
    }
}

impl From<SrtpProfile> for SrtpProfileId {
    fn from(profile: SrtpProfile) -> Self {
        match profile {
            SrtpProfile::CHACHA20_POLY1305 => SrtpProfileId::SRTP_AEAD_CHACHA20_POLY1305,
        }
    }
}

impl From<SrtpProfileId> for SrtpProfile {
    fn from(profile: SrtpProfileId) -> Self {
        match profile {
            SrtpProfileId::SRTP_AEAD_CHACHA20_POLY1305 => SrtpProfile::CHACHA20_POLY1305,
        }
    }
}

/// UseSrtp extension as defined in RFC 5764
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseSrtpExtension {
    pub profiles: SrtpProfileVec,
    pub mki: ArrayVec<u8, 255>, // MKI value (usually empty)
}

impl UseSrtpExtension {
    pub fn new(profiles: SrtpProfileVec, mki: ArrayVec<u8, 255>) -> Self {
        UseSrtpExtension { profiles, mki }
    }

    /// The extension offering every supported profile, with an empty MKI (RFC 5764).
    pub fn default() -> Self {
        let mut profiles = SrtpProfileVec::new();
        for profile in SrtpProfileId::supported() {
            profiles.push(*profile);
        }
        UseSrtpExtension {
            profiles,
            mki: ArrayVec::new(),
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], UseSrtpExtension> {
        let (input, profiles_length) = be_u16(input)?;
        let (input, profiles_data) = take(profiles_length)(input)?;

        // Parse the profiles (ignore unknown profile IDs instead of failing)
        let mut profiles = SrtpProfileVec::new();
        let mut profiles_rest = profiles_data;

        while profiles_rest.len() >= 2 {
            let profile_input = profiles_rest;
            let (rest, value) = be_u16(profile_input)?;
            profiles_rest = rest;
            if let Some(profile) = SrtpProfileId::from_u16(value) {
                profiles
                    .try_push(profile)
                    .map_err(|_| Err::Failure(Error::new(profile_input, ErrorKind::LengthValue)))?;
            }
        }
        if !profiles_rest.is_empty() {
            return Err(Err::Failure(Error::new(
                profiles_rest,
                ErrorKind::LengthValue,
            )));
        }

        // Parse MKI
        let (input, mki_length) = be_u8(input)?;
        let (input, mki) = take(mki_length)(input)?;
        if !input.is_empty() {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }

        Ok((
            input,
            UseSrtpExtension {
                profiles,
                mki: ArrayVec::try_from(mki).unwrap_or_default(),
            },
        ))
    }

    pub fn serialize(&self, output: &mut Buf) {
        // Length of all profiles (2 bytes per profile)
        output.extend_from_slice(&((self.profiles.len() * 2) as u16).to_be_bytes());

        // Write each profile
        for profile in &self.profiles {
            output.extend_from_slice(&profile.as_u16().to_be_bytes());
        }

        // MKI length and data
        output.push(self.mki.len() as u8);
        output.extend_from_slice(&self.mki);
    }
}
