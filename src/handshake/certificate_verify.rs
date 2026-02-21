use crate::ProtocolError;
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::parse_buffer::ParseBuffer;

use super::CryptoBuffer;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HandshakeVerifyRef<'a> {
    pub signature_scheme: SignatureScheme,
    pub signature: &'a [u8],
}

impl<'a> HandshakeVerifyRef<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<HandshakeVerifyRef<'a>, ProtocolError> {
        let signature_scheme =
            SignatureScheme::parse(buf).map_err(|_| ProtocolError::InvalidSignatureScheme)?;

        let len = buf
            .read_u16()
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature = buf
            .slice(len as usize)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        Ok(Self {
            signature_scheme,
            signature: signature.as_slice(),
        })
    }
}

#[cfg(feature = "rsa")]
const SIGNATURE_SIZE: usize = 512;
#[cfg(not(feature = "rsa"))]
const SIGNATURE_SIZE: usize = 104;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HandshakeVerify {
    pub(crate) signature_scheme: SignatureScheme,
    pub(crate) signature: heapless::Vec<u8, SIGNATURE_SIZE>,
}

impl HandshakeVerify {
    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), ProtocolError> {
        buf.push_u16(self.signature_scheme.as_u16())?;
        buf.with_u16_length(|buf| buf.extend_from_slice(self.signature.as_slice()))?;
        Ok(())
    }
}
