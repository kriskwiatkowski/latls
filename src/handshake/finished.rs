use crate::ProtocolError;
use crate::buffer::CryptoBuffer;
use crate::parse_buffer::ParseBuffer;
use core::fmt::{Debug, Formatter};
use generic_array::{ArrayLength, GenericArray};

/// TLS Finished message: contains an HMAC over the handshake transcript (RFC 8446 §4.4.4).
///
/// `hash` holds the transcript hash snapshot taken just before this message was received;
/// it is `None` when the struct is used for a locally-generated Finished message.
pub struct Finished<N: ArrayLength<u8>> {
    pub verify: GenericArray<u8, N>,
    pub hash: Option<GenericArray<u8, N>>,
}

#[cfg(feature = "defmt")]
impl<N: ArrayLength<u8>> defmt::Format for Finished<N> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "verify length:{}", &self.verify.len());
    }
}

impl<N: ArrayLength<u8>> Debug for Finished<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Finished")
            .field("verify", &self.hash)
            .finish()
    }
}

impl<N: ArrayLength<u8>> Finished<N> {
    pub fn parse(buf: &mut ParseBuffer, _len: u32) -> Result<Self, ProtocolError> {
        let mut verify = GenericArray::default();
        buf.fill(&mut verify)?;
        Ok(Self { verify, hash: None })
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), ProtocolError> {
        buf.extend_from_slice(&self.verify[..self.verify.len()])
            .map_err(|_| ProtocolError::EncodeError)?;
        Ok(())
    }
}
