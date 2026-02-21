use core::sync::atomic::{AtomicBool, Ordering};

use crate::ProtocolError;
use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
use crate::common::decrypted_read_handler::DecryptedReadHandler;
use crate::connection::{Handshake, State, decrypt_record};
use crate::key_schedule::KeySchedule;
use crate::key_schedule::{ReadKeySchedule, WriteKeySchedule};
use crate::read_buffer::ReadBuffer;
use crate::record::{ClientRecord, ClientRecordHeader};
use crate::record_reader::{RecordReader, RecordReaderBorrowMut};
use crate::send_policy::FlushPolicy;
use crate::write_buffer::{WriteBuffer, WriteBufferBorrowMut};
use embedded_io::Error as _;
use embedded_io::ErrorType;
use embedded_io_async::{BufRead, Read as AsyncRead, Write as AsyncWrite};

pub use crate::config::*;

/// An async TLS 1.3 client stream wrapping an underlying async transport.
///
/// Call [`open`](SecureStream::open) to perform the handshake before reading or writing.
pub struct SecureStream<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    opened: AtomicBool,
    key_schedule: KeySchedule<CipherSuite>,
    record_reader: RecordReader<'a>,
    record_write_buf: WriteBuffer<'a>,
    decrypted: DecryptedBufferInfo,
    flush_policy: FlushPolicy,
}

impl<'a, Socket, CipherSuite> SecureStream<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    pub fn is_opened(&mut self) -> bool {
        *self.opened.get_mut()
    }
    pub fn new(
        delegate: Socket,
        record_read_buf: &'a mut [u8],
        record_write_buf: &'a mut [u8],
    ) -> Self {
        Self {
            delegate,
            opened: AtomicBool::new(false),
            key_schedule: KeySchedule::new(),
            record_reader: RecordReader::new(record_read_buf),
            record_write_buf: WriteBuffer::new(record_write_buf),
            decrypted: DecryptedBufferInfo::default(),
            flush_policy: FlushPolicy::default(),
        }
    }

    #[inline]
    pub fn flush_policy(&self) -> FlushPolicy {
        self.flush_policy
    }

    #[inline]
    pub fn set_flush_policy(&mut self, policy: FlushPolicy) {
        self.flush_policy = policy;
    }

    pub async fn open<CP>(
        &mut self,
        mut context: ConnectContext<'_, CP>,
    ) -> Result<(), ProtocolError>
    where
        CP: CryptoBackend<CipherSuite = CipherSuite>,
    {
        let mut handshake: Handshake<CipherSuite> = Handshake::new();
        if let (Ok(verifier), Some(server_name)) = (
            context.crypto_provider.verifier(),
            context.config.server_name,
        ) {
            verifier.set_hostname_verification(server_name)?;
        }
        let mut state = State::ClientHello;

        while state != State::ApplicationData {
            let next_state = state
                .process(
                    &mut self.delegate,
                    &mut handshake,
                    &mut self.record_reader,
                    &mut self.record_write_buf,
                    &mut self.key_schedule,
                    context.config,
                    &mut context.crypto_provider,
                )
                .await?;
            trace!("State {:?} -> {:?}", state, next_state);
            state = next_state;
        }
        *self.opened.get_mut() = true;

        Ok(())
    }

    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, ProtocolError> {
        if self.is_opened() {
            // Start a new ApplicationData record if none is in progress
            if !self
                .record_write_buf
                .contains(ClientRecordHeader::ApplicationData)
            {
                self.flush().await?;
                self.record_write_buf
                    .start_record(ClientRecordHeader::ApplicationData)?;
            }

            let buffered = self.record_write_buf.append(buf);

            if self.record_write_buf.is_full() {
                self.flush().await?;
            }

            Ok(buffered)
        } else {
            Err(ProtocolError::MissingHandshake)
        }
    }

    pub async fn flush(&mut self) -> Result<(), ProtocolError> {
        if !self.record_write_buf.is_empty() {
            let key_schedule = self.key_schedule.write_state();
            let slice = self.record_write_buf.close_record(key_schedule)?;

            self.delegate
                .write_all(slice)
                .await
                .map_err(|e| ProtocolError::Io(e.kind()))?;

            key_schedule.increment_counter();

            if self.flush_policy.flush_transport() {
                self.flush_transport().await?;
            }
        }

        Ok(())
    }

    #[inline]
    async fn flush_transport(&mut self) -> Result<(), ProtocolError> {
        self.delegate
            .flush()
            .await
            .map_err(|e| ProtocolError::Io(e.kind()))
    }

    fn create_read_buffer(&mut self) -> ReadBuffer<'_> {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProtocolError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut buffer = self.read_buffered().await?;

        let len = buffer.pop_into(buf);
        trace!("Copied {} bytes", len);

        Ok(len)
    }

    pub async fn read_buffered(&mut self) -> Result<ReadBuffer<'_>, ProtocolError> {
        if self.is_opened() {
            while self.decrypted.is_empty() {
                self.read_application_data().await?;
            }

            Ok(self.create_read_buffer())
        } else {
            Err(ProtocolError::MissingHandshake)
        }
    }

    async fn read_application_data(&mut self) -> Result<(), ProtocolError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let record = self
            .record_reader
            .read(&mut self.delegate, self.key_schedule.read_state())
            .await?;

        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: self.opened.get_mut(),
        };
        decrypt_record(
            self.key_schedule.read_state(),
            record,
            |_key_schedule, record| handler.handle(record),
        )?;

        Ok(())
    }

    async fn close_internal(&mut self) -> Result<(), ProtocolError> {
        self.flush().await?;

        let is_opened = self.is_opened();
        let (write_key_schedule, read_key_schedule) = self.key_schedule.as_split();
        // Send a close_notify alert to signal clean shutdown (RFC 8446 §6.1)
        let slice = self.record_write_buf.write_record(
            &ClientRecord::close_notify(is_opened),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        self.delegate
            .write_all(slice)
            .await
            .map_err(|e| ProtocolError::Io(e.kind()))?;

        self.key_schedule.write_state().increment_counter();

        self.flush_transport().await
    }

    pub async fn close(mut self) -> Result<Socket, (Socket, ProtocolError)> {
        match self.close_internal().await {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
    }

    pub fn split(
        &mut self,
    ) -> (
        TlsReader<'_, Socket, CipherSuite>,
        TlsWriter<'_, Socket, CipherSuite>,
    )
    where
        Socket: Clone,
    {
        // Split requires a Clone socket so both halves can independently drive the same connection
        let (wks, rks) = self.key_schedule.as_split();

        let reader = TlsReader {
            opened: &self.opened,
            delegate: self.delegate.clone(),
            key_schedule: rks,
            record_reader: self.record_reader.reborrow_mut(),
            decrypted: &mut self.decrypted,
        };
        let writer = TlsWriter {
            opened: &self.opened,
            delegate: self.delegate.clone(),
            key_schedule: wks,
            record_write_buf: self.record_write_buf.reborrow_mut(),
            flush_policy: self.flush_policy,
        };

        (reader, writer)
    }
}

impl<'a, Socket, CipherSuite> ErrorType for SecureStream<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = ProtocolError;
}

impl<'a, Socket, CipherSuite> AsyncRead for SecureStream<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        SecureStream::read(self, buf).await
    }
}

impl<'a, Socket, CipherSuite> BufRead for SecureStream<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn fill_buf(&mut self) -> Result<&[u8], Self::Error> {
        self.read_buffered().await.map(|mut buf| buf.peek_all())
    }

    fn consume(&mut self, amt: usize) {
        self.create_read_buffer().pop(amt);
    }
}

impl<'a, Socket, CipherSuite> AsyncWrite for SecureStream<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        SecureStream::write(self, buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        SecureStream::flush(self).await
    }
}

pub struct TlsReader<'a, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    opened: &'a AtomicBool,
    delegate: Socket,
    key_schedule: &'a mut ReadKeySchedule<CipherSuite>,
    record_reader: RecordReaderBorrowMut<'a>,
    decrypted: &'a mut DecryptedBufferInfo,
}

impl<Socket, CipherSuite> AsRef<Socket> for TlsReader<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    fn as_ref(&self) -> &Socket {
        &self.delegate
    }
}

impl<'a, Socket, CipherSuite> TlsReader<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn create_read_buffer(&mut self) -> ReadBuffer<'_> {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    pub async fn read_buffered(&mut self) -> Result<ReadBuffer<'_>, ProtocolError> {
        if self.opened.load(Ordering::Acquire) {
            while self.decrypted.is_empty() {
                self.read_application_data().await?;
            }

            Ok(self.create_read_buffer())
        } else {
            Err(ProtocolError::MissingHandshake)
        }
    }

    async fn read_application_data(&mut self) -> Result<(), ProtocolError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let record = self
            .record_reader
            .read(&mut self.delegate, self.key_schedule)
            .await?;

        let mut opened = self.opened.load(Ordering::Acquire);
        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: self.decrypted,
            is_open: &mut opened,
        };
        let result = decrypt_record(self.key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        });

        if !opened {
            self.opened.store(false, Ordering::Release);
        }
        result
    }
}

pub struct TlsWriter<'a, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    opened: &'a AtomicBool,
    delegate: Socket,
    key_schedule: &'a mut WriteKeySchedule<CipherSuite>,
    record_write_buf: WriteBufferBorrowMut<'a>,
    flush_policy: FlushPolicy,
}

impl<'a, Socket, CipherSuite> TlsWriter<'a, Socket, CipherSuite>
where
    Socket: AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    #[inline]
    async fn flush_transport(&mut self) -> Result<(), ProtocolError> {
        self.delegate
            .flush()
            .await
            .map_err(|e| ProtocolError::Io(e.kind()))
    }
}

impl<Socket, CipherSuite> AsRef<Socket> for TlsWriter<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    fn as_ref(&self) -> &Socket {
        &self.delegate
    }
}

impl<Socket, CipherSuite> ErrorType for TlsWriter<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = ProtocolError;
}

impl<Socket, CipherSuite> ErrorType for TlsReader<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = ProtocolError;
}

impl<'a, Socket, CipherSuite> AsyncRead for TlsReader<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut buffer = self.read_buffered().await?;

        let len = buffer.pop_into(buf);
        trace!("Copied {} bytes", len);

        Ok(len)
    }
}

impl<'a, Socket, CipherSuite> BufRead for TlsReader<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn fill_buf(&mut self) -> Result<&[u8], Self::Error> {
        self.read_buffered().await.map(|mut buf| buf.peek_all())
    }

    fn consume(&mut self, amt: usize) {
        self.create_read_buffer().pop(amt);
    }
}

impl<'a, Socket, CipherSuite> AsyncWrite for TlsWriter<'a, Socket, CipherSuite>
where
    Socket: AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if self.opened.load(Ordering::Acquire) {
            if !self
                .record_write_buf
                .contains(ClientRecordHeader::ApplicationData)
            {
                self.flush().await?;
                self.record_write_buf
                    .start_record(ClientRecordHeader::ApplicationData)?;
            }

            let buffered = self.record_write_buf.append(buf);

            if self.record_write_buf.is_full() {
                self.flush().await?;
            }

            Ok(buffered)
        } else {
            Err(ProtocolError::MissingHandshake)
        }
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        if !self.record_write_buf.is_empty() {
            let slice = self.record_write_buf.close_record(self.key_schedule)?;

            self.delegate
                .write_all(slice)
                .await
                .map_err(|e| ProtocolError::Io(e.kind()))?;

            self.key_schedule.increment_counter();

            if self.flush_policy.flush_transport() {
                self.flush_transport().await?;
            }
        }

        Ok(())
    }
}
