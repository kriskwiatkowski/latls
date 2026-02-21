use crate::{
    ProtocolError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AlpnProtocolNameList<'a> {
    pub protocols: &'a [&'a [u8]],
}

impl<'a> AlpnProtocolNameList<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let list_len = buf.read_u16()? as usize;
        let mut list_buf = buf.slice(list_len)?;

        while !list_buf.is_empty() {
            let name_len = list_buf.read_u8()? as usize;
            if name_len == 0 {
                return Err(ParseError::InvalidData);
            }
            let _name = list_buf.slice(name_len)?;
        }

        Ok(Self { protocols: &[] })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), ProtocolError> {
        buf.with_u16_length(|buf| {
            for protocol in self.protocols {
                buf.push(protocol.len() as u8)
                    .map_err(|_| ProtocolError::EncodeError)?;
                buf.extend_from_slice(protocol)?;
            }
            Ok(())
        })
    }
}
