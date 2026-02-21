use core::ops::Range;

use crate::{
    ProtocolError, alert::AlertDescription, common::decrypted_buffer_info::DecryptedBufferInfo,
    config::TlsCipherSuite, handshake::ServerHandshake, record::ServerRecord,
};

pub struct DecryptedReadHandler<'a> {
    pub source_buffer: Range<*const u8>,
    pub buffer_info: &'a mut DecryptedBufferInfo,
    pub is_open: &'a mut bool,
}

impl DecryptedReadHandler<'_> {
    pub fn handle<CipherSuite: TlsCipherSuite>(
        &mut self,
        record: ServerRecord<'_, CipherSuite>,
    ) -> Result<(), ProtocolError> {
        match record {
            ServerRecord::ApplicationData(data) => {
                let slice = data.data.as_slice();
                let slice_ptrs = slice.as_ptr_range();

                debug_assert!(
                    self.source_buffer.contains(&slice_ptrs.start)
                        && self.source_buffer.contains(&slice_ptrs.end)
                );

                let offset =
                    unsafe { slice_ptrs.start.offset_from(self.source_buffer.start) as usize };

                self.buffer_info.offset = offset;
                self.buffer_info.len = slice.len();
                self.buffer_info.consumed = 0;
                Ok(())
            }
            ServerRecord::Alert(alert) => {
                if let AlertDescription::CloseNotify = alert.description {
                    *self.is_open = false;
                    Err(ProtocolError::ConnectionClosed)
                } else {
                    Err(ProtocolError::InternalError)
                }
            }
            ServerRecord::ChangeCipherSpec(_) => Err(ProtocolError::InternalError),
            ServerRecord::Handshake(ServerHandshake::NewSessionTicket(_)) => Ok(()),
            ServerRecord::Handshake(_) => {
                unimplemented!()
            }
        }
    }
}
