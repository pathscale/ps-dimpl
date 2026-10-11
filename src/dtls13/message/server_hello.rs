use super::{CompressionMethod, Dtls13CipherSuite, Extension};
use super::{ProtocolVersion, Random, SessionId};
use crate::buffer::Buf;
use arrayvec::ArrayVec;
use nom::Err;
use nom::error::{Error, ErrorKind};
use nom::{IResult, bytes::complete::take, number::complete::be_u16};

/// Magic random value indicating HelloRetryRequest (RFC 8446 Section 4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

#[derive(Debug, PartialEq, Eq)]
pub struct ServerHello {
    pub legacy_version: ProtocolVersion,
    pub random: Random,
    pub legacy_session_id: SessionId,
    pub cipher_suite: Dtls13CipherSuite,
    pub legacy_compression_method: CompressionMethod,
    pub extensions: Option<ArrayVec<Extension, 5>>,
}

impl ServerHello {
    pub fn new(
        legacy_version: ProtocolVersion,
        random: Random,
        legacy_session_id: SessionId,
        cipher_suite: Dtls13CipherSuite,
        legacy_compression_method: CompressionMethod,
        extensions: Option<ArrayVec<Extension, 5>>,
    ) -> Self {
        ServerHello {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suite,
            legacy_compression_method,
            extensions,
        }
    }

    /// Returns true if this ServerHello is actually a HelloRetryRequest.
    pub fn is_hello_retry_request(&self) -> bool {
        self.random.bytes == HRR_RANDOM
    }

    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], ServerHello> {
        let original_input = input;
        let (input, legacy_version) = ProtocolVersion::parse(input)?;
        let (input, random) = Random::parse(input)?;
        let (input, legacy_session_id) = SessionId::parse(input)?;
        let (input, cipher_suite) = Dtls13CipherSuite::parse(input)?;
        let (input, legacy_compression_method) = CompressionMethod::parse(input)?;

        let (input, extensions) = if !input.is_empty() {
            if input.len() < 2 {
                return Err(Err::Failure(Error::new(input, ErrorKind::Eof)));
            }
            let (input, extensions_len) = be_u16(input)?;

            if input.len() < extensions_len as usize {
                return Err(Err::Failure(Error::new(input, ErrorKind::Eof)));
            }

            if extensions_len > 0 {
                let (rest, input_ext) = take(extensions_len)(input)?;
                if !rest.is_empty() {
                    return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
                }
                let consumed_to_ext_data =
                    input_ext.as_ptr() as usize - original_input.as_ptr() as usize;
                let ext_base_offset = base_offset + consumed_to_ext_data;

                let mut extensions_vec: ArrayVec<Extension, 5> = ArrayVec::new();
                let mut current_input = input_ext;
                let mut current_offset = ext_base_offset;
                while !current_input.is_empty() {
                    let before_len = current_input.len();
                    let (new_rest, ext) = Extension::parse(current_input, current_offset)?;
                    let parsed_len = before_len - new_rest.len();
                    current_offset += parsed_len;
                    if ext.extension_type.is_supported() {
                        if extensions_vec
                            .iter()
                            .any(|existing| existing.extension_type == ext.extension_type)
                        {
                            return Err(Err::Failure(Error::new(
                                current_input,
                                ErrorKind::LengthValue,
                            )));
                        }
                        extensions_vec.try_push(ext).map_err(|_| {
                            Err::Failure(Error::new(current_input, ErrorKind::LengthValue))
                        })?;
                    }
                    current_input = new_rest;
                }
                (rest, Some(extensions_vec))
            } else {
                (input, None)
            }
        } else {
            (input, None)
        };

        Ok((
            input,
            ServerHello {
                legacy_version,
                random,
                legacy_session_id,
                cipher_suite,
                legacy_compression_method,
                extensions,
            },
        ))
    }

    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        output.extend_from_slice(&self.legacy_version.as_u16().to_be_bytes());
        self.random.serialize(output);
        output.push(self.legacy_session_id.len() as u8);
        output.extend_from_slice(&self.legacy_session_id);
        output.extend_from_slice(&self.cipher_suite.as_u16().to_be_bytes());
        output.push(self.legacy_compression_method.as_u8());
        if let Some(extensions) = &self.extensions {
            let mut extensions_len = 0;
            for ext in extensions.iter() {
                let ext_data = ext.extension_data(source_buf);
                extensions_len += 2 + 2 + ext_data.len();
            }

            output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

            for ext in extensions {
                ext.serialize(source_buf, output);
            }
        }
    }
}
