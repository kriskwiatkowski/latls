use crate::key_schedule::ReadKeySchedule;
use embedded_io::{Error as _, Read as BlockingRead};
use embedded_io_async::Read as AsyncRead;

use crate::{
    ProtocolError,
    config::TlsCipherSuite,
    record::{RecordHeader, ServerRecord},
};

/// Stateful reader that reassembles TLS records from a byte stream into the shared receive buffer.
///
/// `decoded` tracks how many bytes at the start of `buf` have already been handed to the caller;
/// `pending` tracks bytes that have been read from the transport but not yet consumed as a record.
pub struct RecordReader<'a> {
    pub(crate) buf: &'a mut [u8],
    decoded: usize,
    pending: usize,
}

pub struct RecordReaderBorrowMut<'a> {
    pub(crate) buf: &'a mut [u8],
    decoded: &'a mut usize,
    pending: &'a mut usize,
}

impl<'a> RecordReader<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        // TLS 1.3 max plaintext record is 16 384 bytes + 256 bytes overhead = 16 640 bytes
        if buf.len() < 16640 {
            warn!("Read buffer is smaller than 16640 bytes, which may cause problems!");
        }
        Self {
            buf,
            decoded: 0,
            pending: 0,
        }
    }

    pub fn reborrow_mut(&mut self) -> RecordReaderBorrowMut<'_> {
        RecordReaderBorrowMut {
            buf: self.buf,
            decoded: &mut self.decoded,
            pending: &mut self.pending,
        }
    }

    pub async fn read<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, ProtocolError> {
        read(
            self.buf,
            &mut self.decoded,
            &mut self.pending,
            transport,
            key_schedule,
        )
        .await
    }

    pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, ProtocolError> {
        read_blocking(
            self.buf,
            &mut self.decoded,
            &mut self.pending,
            transport,
            key_schedule,
        )
    }
}

impl RecordReaderBorrowMut<'_> {
    pub async fn read<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, ProtocolError> {
        read(
            self.buf,
            self.decoded,
            self.pending,
            transport,
            key_schedule,
        )
        .await
    }

    pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, ProtocolError> {
        read_blocking(
            self.buf,
            self.decoded,
            self.pending,
            transport,
            key_schedule,
        )
    }
}

pub async fn read<'m, CipherSuite: TlsCipherSuite>(
    buf: &'m mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl AsyncRead,
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
) -> Result<ServerRecord<'m, CipherSuite>, ProtocolError> {
    let header: RecordHeader = next_record_header(transport).await?;

    advance(buf, decoded, pending, transport, header.content_length()).await?;
    consume(
        buf,
        decoded,
        pending,
        header,
        key_schedule.transcript_hash(),
    )
}

pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
    buf: &'m mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl BlockingRead,
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
) -> Result<ServerRecord<'m, CipherSuite>, ProtocolError> {
    let header: RecordHeader = next_record_header_blocking(transport)?;

    advance_blocking(buf, decoded, pending, transport, header.content_length())?;
    consume(
        buf,
        decoded,
        pending,
        header,
        key_schedule.transcript_hash(),
    )
}

async fn next_record_header(transport: &mut impl AsyncRead) -> Result<RecordHeader, ProtocolError> {
    let mut buf: [u8; RecordHeader::LEN] = [0; RecordHeader::LEN];
    let mut total_read: usize = 0;
    while total_read != RecordHeader::LEN {
        let read: usize = transport
            .read(&mut buf[total_read..])
            .await
            .map_err(|e| ProtocolError::Io(e.kind()))?;
        if read == 0 {
            return Err(ProtocolError::IoError);
        }
        total_read += read;
    }
    RecordHeader::decode(buf)
}

fn next_record_header_blocking(
    transport: &mut impl BlockingRead,
) -> Result<RecordHeader, ProtocolError> {
    let mut buf: [u8; RecordHeader::LEN] = [0; RecordHeader::LEN];
    let mut total_read: usize = 0;
    while total_read != RecordHeader::LEN {
        let read: usize = transport
            .read(&mut buf[total_read..])
            .map_err(|e| ProtocolError::Io(e.kind()))?;
        if read == 0 {
            return Err(ProtocolError::IoError);
        }
        total_read += read;
    }
    RecordHeader::decode(buf)
}

async fn advance(
    buf: &mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl AsyncRead,
    amount: usize,
) -> Result<(), ProtocolError> {
    ensure_contiguous(buf, decoded, pending, amount)?;

    let mut remain: usize = amount;
    while *pending < amount {
        let read = transport
            .read(&mut buf[*decoded + *pending..][..remain])
            .await
            .map_err(|e| ProtocolError::Io(e.kind()))?;
        if read == 0 {
            return Err(ProtocolError::IoError);
        }
        remain -= read;
        *pending += read;
    }

    Ok(())
}

fn advance_blocking(
    buf: &mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl BlockingRead,
    amount: usize,
) -> Result<(), ProtocolError> {
    ensure_contiguous(buf, decoded, pending, amount)?;

    let mut remain: usize = amount;
    while *pending < amount {
        let read = transport
            .read(&mut buf[*decoded + *pending..][..remain])
            .map_err(|e| ProtocolError::Io(e.kind()))?;
        if read == 0 {
            return Err(ProtocolError::IoError);
        }
        remain -= read;
        *pending += read;
    }

    Ok(())
}

fn consume<'m, CipherSuite: TlsCipherSuite>(
    buf: &'m mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    header: RecordHeader,
    digest: &mut CipherSuite::Hash,
) -> Result<ServerRecord<'m, CipherSuite>, ProtocolError> {
    let content_len = header.content_length();

    let slice = &mut buf[*decoded..][..content_len];

    *decoded += content_len;
    *pending -= content_len;

    ServerRecord::decode(header, slice, digest)
}

fn ensure_contiguous(
    buf: &mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    len: usize,
) -> Result<(), ProtocolError> {
    // If the next record would overflow the end of the buffer, rotate unconsumed bytes to the front
    if *decoded + len > buf.len() {
        if len > buf.len() {
            error!(
                "Record too large for buffer. Size: {} Buffer size: {}",
                len,
                buf.len()
            );
            return Err(ProtocolError::InsufficientSpace);
        }
        buf.copy_within(*decoded..*decoded + *pending, 0);
        *decoded = 0;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::*;
    use crate::{Aes128GcmSha256, content_types::ContentType, key_schedule::KeySchedule};

    struct ChunkRead<'a>(&'a [u8], usize);

    impl embedded_io::ErrorType for ChunkRead<'_> {
        type Error = Infallible;
    }

    impl BlockingRead for ChunkRead<'_> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let len = usize::min(self.1, buf.len());
            let len = usize::min(len, self.0.len());
            buf[..len].copy_from_slice(&self.0[..len]);
            self.0 = &self.0[len..];
            Ok(len)
        }
    }

    #[test]
    fn can_read_blocking() {
        can_read_blocking_case(1);
        can_read_blocking_case(2);
        can_read_blocking_case(3);
        can_read_blocking_case(4);
        can_read_blocking_case(5);
        can_read_blocking_case(6);
        can_read_blocking_case(7);
        can_read_blocking_case(8);
        can_read_blocking_case(9);
        can_read_blocking_case(10);
        can_read_blocking_case(11);
        can_read_blocking_case(12);
        can_read_blocking_case(13);
        can_read_blocking_case(14);
        can_read_blocking_case(15);
        can_read_blocking_case(16);
    }

    fn can_read_blocking_case(chunk_size: usize) {
        let mut transport = ChunkRead(
            &[
                ContentType::ApplicationData as u8,
                0x03,
                0x03,
                0x00,
                0x04,
                0xde,
                0xad,
                0xbe,
                0xef,
                ContentType::ApplicationData as u8,
                0x03,
                0x03,
                0x00,
                0x02,
                0xaa,
                0xbb,
            ],
            chunk_size,
        );

        let mut buf = [0; 32];
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xde, 0xad, 0xbe, 0xef], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(4, reader.decoded);
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xaa, 0xbb], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(6, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }

    #[test]
    fn can_read_blocking_must_rotate_buffer() {
        let mut transport = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x04,
            0xde,
            0xad,
            0xbe,
            0xef,
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x02,
            0xaa,
            0xbb,
        ]
        .as_slice();

        let mut buf = [0; 4];
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xde, 0xad, 0xbe, 0xef], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(4, reader.decoded);
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xaa, 0xbb], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(2, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }

    #[test]
    fn can_read_empty_record() {
        let mut transport = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x00,
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x00,
        ]
        .as_slice();

        let mut buf = [0; 32];
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert!(data.data.is_empty());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(0, reader.decoded);
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert!(data.data.is_empty());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(0, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }
}
