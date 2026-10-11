use super::{CompressionMethod, Dtls13CipherSuite, ProtocolVersion};
use super::{Cookie, Extension, Random, SessionId};
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u8, be_u16};
use nom::{Err, IResult};

use crate::buffer::Buf;
use crate::util::{many0, many1};

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: ProtocolVersion,
    pub random: Random,
    pub legacy_session_id: SessionId,
    pub legacy_cookie: Cookie,
    pub cipher_suites: ArrayVec<Dtls13CipherSuite, 3>,
    pub legacy_compression_methods: ArrayVec<CompressionMethod, 1>,
    pub extensions: ArrayVec<Extension, 8>,
}

impl ClientHello {
    pub fn new(
        legacy_version: ProtocolVersion,
        random: Random,
        legacy_session_id: SessionId,
        legacy_cookie: Cookie,
        cipher_suites: ArrayVec<Dtls13CipherSuite, 3>,
        legacy_compression_methods: ArrayVec<CompressionMethod, 1>,
    ) -> Self {
        ClientHello {
            legacy_version,
            random,
            legacy_session_id,
            legacy_cookie,
            cipher_suites,
            legacy_compression_methods,
            extensions: ArrayVec::new(),
        }
    }

    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], ClientHello> {
        Self::parse_with_options(input, base_offset, false)
    }

    pub(crate) fn parse_allow_unknown_suites(
        input: &[u8],
        base_offset: usize,
    ) -> IResult<&[u8], ClientHello> {
        Self::parse_with_options(input, base_offset, true)
    }

    fn parse_with_options(
        input: &[u8],
        base_offset: usize,
        allow_unknown_suites: bool,
    ) -> IResult<&[u8], ClientHello> {
        let original_input = input;
        let (input, legacy_version) = ProtocolVersion::parse(input)?;
        let (input, random) = Random::parse(input)?;
        let (input, legacy_session_id) = SessionId::parse(input)?;
        let (input, legacy_cookie) = Cookie::parse(input)?;
        let (input, cipher_suites_len) = be_u16(input)?;
        if cipher_suites_len == 0 || cipher_suites_len % 2 != 0 {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, input_cipher) = take(cipher_suites_len)(input)?;
        // Retain the previously parsed wire values so retired offers reach
        // negotiation and are rejected against the configured provider.
        let recognized = |suite: &Dtls13CipherSuite| matches!(suite.as_u16(), 0x1301..=0x1303);
        let (rest, cipher_suites) = if allow_unknown_suites {
            many0(Dtls13CipherSuite::parse, recognized)(input_cipher)?
        } else {
            many1(Dtls13CipherSuite::parse, recognized)(input_cipher)?
        };
        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
        }
        let (input, compression_methods_len) = be_u8(input)?;
        let (input, input_compression) = take(compression_methods_len)(input)?;
        let (rest, legacy_compression_methods) =
            many1(CompressionMethod::parse, CompressionMethod::is_supported)(input_compression)?;
        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
        }

        let consumed = input.as_ptr() as usize - original_input.as_ptr() as usize;
        let extensions_base_offset = base_offset + consumed;

        let (remaining_input, extensions) = Self::parse_extensions(input, extensions_base_offset)?;

        Ok((
            remaining_input,
            ClientHello {
                legacy_version,
                random,
                legacy_session_id,
                legacy_cookie,
                cipher_suites,
                legacy_compression_methods,
                extensions,
            },
        ))
    }

    fn parse_extensions(
        input: &[u8],
        base_offset: usize,
    ) -> IResult<&[u8], ArrayVec<Extension, 8>> {
        let mut extensions = ArrayVec::new();

        if input.is_empty() {
            return Ok((input, extensions));
        }

        let original_input = input;
        let (remaining, extensions_len) = be_u16(input)?;

        let (remaining, extensions_data) = take(extensions_len)(remaining)?;
        if !remaining.is_empty() {
            return Err(Err::Failure(Error::new(remaining, ErrorKind::LengthValue)));
        }

        let consumed = extensions_data.as_ptr() as usize - original_input.as_ptr() as usize;
        let data_base_offset = base_offset + consumed;

        let mut extensions_rest = extensions_data;
        let mut current_offset = data_base_offset;
        while !extensions_rest.is_empty() {
            let before_len = extensions_rest.len();
            let (rest, extension) = Extension::parse(extensions_rest, current_offset)?;
            let parsed_len = before_len - rest.len();
            current_offset += parsed_len;

            if extension.extension_type.is_supported() {
                if extensions
                    .iter()
                    .any(|existing| existing.extension_type == extension.extension_type)
                {
                    return Err(Err::Failure(Error::new(
                        extensions_rest,
                        ErrorKind::LengthValue,
                    )));
                }
                extensions.try_push(extension).map_err(|_| {
                    Err::Failure(Error::new(extensions_rest, ErrorKind::LengthValue))
                })?;
            }
            extensions_rest = rest;
        }

        Ok((remaining, extensions))
    }

    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        output.extend_from_slice(&self.legacy_version.as_u16().to_be_bytes());
        self.random.serialize(output);
        output.push(self.legacy_session_id.len() as u8);
        output.extend_from_slice(&self.legacy_session_id);
        output.push(self.legacy_cookie.len() as u8);
        output.extend_from_slice(&self.legacy_cookie);
        output.extend_from_slice(&(self.cipher_suites.len() as u16 * 2).to_be_bytes());
        for suite in &self.cipher_suites {
            output.extend_from_slice(&suite.as_u16().to_be_bytes());
        }
        output.push(self.legacy_compression_methods.len() as u8);
        for method in &self.legacy_compression_methods {
            output.push(method.as_u8());
        }

        if !self.extensions.is_empty() {
            let mut extensions_len = 0;
            for ext in &self.extensions {
                let ext_data = ext.extension_data(source_buf);
                extensions_len += 4 + ext_data.len();
            }

            output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

            for ext in &self.extensions {
                ext.serialize(source_buf, output);
            }
        }
    }
}
