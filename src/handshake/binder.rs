use crate::ProtocolError;
use crate::buffer::CryptoBuffer;
use core::fmt::{Debug, Formatter};
use generic_array::{ArrayLength, GenericArray};

pub struct PskBinder<N: ArrayLength<u8>> {
    pub verify: GenericArray<u8, N>,
}

#[cfg(feature = "defmt")]
impl<N: ArrayLength<u8>> defmt::Format for PskBinder<N> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "verify length:{}", &self.verify.len());
    }
}

impl<N: ArrayLength<u8>> Debug for PskBinder<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PskBinder").finish()
    }
}

impl<N: ArrayLength<u8>> PskBinder<N> {
    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), ProtocolError> {
        let len = self.verify.len() as u8;
        buf.push(len).map_err(|_| ProtocolError::EncodeError)?;
        buf.extend_from_slice(&self.verify[..self.verify.len()])
            .map_err(|_| ProtocolError::EncodeError)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn len() -> usize {
        N::to_usize()
    }
}
