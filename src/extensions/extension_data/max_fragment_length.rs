use crate::{
    ProtocolError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
};

#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MaxFragmentLength {
    Bits9 = 1,
    Bits10 = 2,
    Bits11 = 3,
    Bits12 = 4,
}

impl MaxFragmentLength {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        match buf.read_u8()? {
            1 => Ok(Self::Bits9),
            2 => Ok(Self::Bits10),
            3 => Ok(Self::Bits11),
            4 => Ok(Self::Bits12),
            other => {
                warn!("Read unknown MaxFragmentLength: {}", other);
                Err(ParseError::InvalidData)
            }
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), ProtocolError> {
        buf.push(*self as u8)
            .map_err(|_| ProtocolError::EncodeError)
    }
}
