use crate::config::{ConnectConfig, TlsCipherSuite};
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::{KeySchedule, ReadKeySchedule, WriteKeySchedule};
use crate::record::{ClientRecord, ServerRecord};
use crate::record_reader::RecordReader;
use crate::write_buffer::WriteBuffer;
use crate::{CryptoBackend, HandshakeVerify, ProtocolError, Verifier};
use crate::{
    alert::{Alert, AlertDescription, AlertLevel},
    handshake::{certificate::CertificateRef, certificate_request::CertificateRequest},
};
use core::fmt::Debug;
use digest::Digest;
use embedded_io::Error as _;
use embedded_io::{Read as BlockingRead, Write as BlockingWrite};
use embedded_io_async::{Read as AsyncRead, Write as AsyncWrite};

use crate::application_data::ApplicationData;
use crate::buffer::CryptoBuffer;
use digest::generic_array::typenum::Unsigned;
use crate::ecdh::{EphemeralKey, P256_SHARED_SECRET_LEN};
use signature::SignerMut;

use crate::content_types::ContentType;
use crate::parse_buffer::ParseBuffer;
use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit};

// Decrypts an ApplicationData record in-place, then dispatches the inner content type to `cb`.
// Plaintext records (Handshake, ChangeCipherSpec) are forwarded to `cb` without decryption.
pub(crate) fn decrypt_record<CipherSuite>(
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
    record: ServerRecord<'_, CipherSuite>,
    mut cb: impl FnMut(
        &mut ReadKeySchedule<CipherSuite>,
        ServerRecord<'_, CipherSuite>,
    ) -> Result<(), ProtocolError>,
) -> Result<(), ProtocolError>
where
    CipherSuite: TlsCipherSuite,
{
    if let ServerRecord::ApplicationData(ApplicationData {
        header,
        data: mut app_data,
    }) = record
    {
        let server_key = key_schedule.get_key();
        let nonce = key_schedule.get_nonce();

        let crypto = <CipherSuite::Cipher as KeyInit>::new(server_key);
        crypto
            .decrypt_in_place(&nonce, header.data(), &mut app_data)
            .map_err(|_| ProtocolError::CryptoError)?;

        // Strip TLS 1.3 inner-content padding: trailing zero bytes before the real content type
        let padding = app_data
            .as_slice()
            .iter()
            .enumerate()
            .rfind(|(_, b)| **b != 0);
        if let Some((index, _)) = padding {
            app_data.truncate(index + 1);
        }

        // The last byte of the decrypted payload is the actual ContentType (RFC 8446 §5.4)
        let content_type = ContentType::of(*app_data.as_slice().last().unwrap())
            .ok_or(ProtocolError::InvalidRecord)?;

        trace!("Decrypting: content type = {:?}", content_type);

        app_data.truncate(app_data.len() - 1);

        let mut buf = ParseBuffer::new(app_data.as_slice());
        match content_type {
            ContentType::Handshake => {
                while buf.remaining() > 0 {
                    let inner = ServerHandshake::read(&mut buf, key_schedule.transcript_hash())?;
                    cb(key_schedule, ServerRecord::Handshake(inner))?;
                }
            }
            ContentType::ApplicationData => {
                let inner = ApplicationData::new(app_data, header);
                cb(key_schedule, ServerRecord::ApplicationData(inner))?;
            }
            ContentType::Alert => {
                let alert = Alert::parse(&mut buf)?;
                cb(key_schedule, ServerRecord::Alert(alert))?;
            }
            _ => return Err(ProtocolError::Unimplemented),
        }
        key_schedule.increment_counter();
    } else {
        trace!("Not decrypting: content_type = {:?}", record.content_type());
        cb(key_schedule, record)?;
    }
    Ok(())
}

pub(crate) fn encrypt<CipherSuite>(
    key_schedule: &WriteKeySchedule<CipherSuite>,
    buf: &mut CryptoBuffer<'_>,
) -> Result<(), ProtocolError>
where
    CipherSuite: TlsCipherSuite,
{
    let client_key = key_schedule.get_key();
    let nonce = key_schedule.get_nonce();
    let crypto = <CipherSuite::Cipher as KeyInit>::new(client_key);
    let len = buf.len() + <CipherSuite::Cipher as AeadCore>::TagSize::to_usize();

    if len > buf.capacity() {
        return Err(ProtocolError::InsufficientSpace);
    }

    trace!("output size {}", len);
    let len_bytes = (len as u16).to_be_bytes();
    // Additional data is the TLS record header (type=ApplicationData, legacy version 0x0303, length)
    let additional_data = [
        ContentType::ApplicationData as u8,
        0x03,
        0x03,
        len_bytes[0],
        len_bytes[1],
    ];

    crypto
        .encrypt_in_place(&nonce, &additional_data, buf)
        .map_err(|_| ProtocolError::InvalidApplicationData)
}

/// Ephemeral state held between handshake steps — discarded once the handshake completes.
pub struct Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    // Saved pre-master transcript hash used for Finished after a certificate exchange
    traffic_hash: Option<CipherSuite::Hash>,
    secret: Option<EphemeralKey>,
    certificate_request: Option<CertificateRequest>,
}

impl<CipherSuite> Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Handshake<CipherSuite> {
        Handshake {
            traffic_hash: None,
            secret: None,
            certificate_request: None,
        }
    }
}

/// TLS handshake state machine. Drives the client through all stages of the TLS 1.3 handshake.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    ClientHello,
    ServerHello,
    ServerVerify,
    ClientCert,
    ClientCertVerify,
    ClientFinished,
    ApplicationData,
}

impl<'a> State {
    #[allow(clippy::too_many_arguments)]
    pub async fn process<'v, Transport, CP>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<CP::CipherSuite>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer<'_>,
        key_schedule: &mut KeySchedule<CP::CipherSuite>,
        config: &ConnectConfig<'a>,
        crypto_provider: &mut CP,
    ) -> Result<State, ProtocolError>
    where
        Transport: AsyncRead + AsyncWrite + 'a,
        CP: CryptoBackend,
    {
        match self {
            State::ClientHello => {
                let (state, tx) =
                    client_hello(key_schedule, config, crypto_provider, tx_buf, handshake)?;

                respond(tx, transport, key_schedule).await?;

                Ok(state)
            }
            State::ServerHello => {
                let record = record_reader
                    .read(transport, key_schedule.read_state())
                    .await?;

                let result = process_server_hello(handshake, key_schedule, record);

                handle_processing_error(result, transport, key_schedule, tx_buf).await
            }
            State::ServerVerify => {
                let record = record_reader
                    .read(transport, key_schedule.read_state())
                    .await?;

                let result =
                    process_server_verify(handshake, key_schedule, crypto_provider, record);

                handle_processing_error(result, transport, key_schedule, tx_buf).await
            }
            State::ClientCert => {
                let (state, tx) = client_cert(handshake, key_schedule, crypto_provider, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) = client_cert_verify(key_schedule, crypto_provider, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                client_finished_finalize(key_schedule, handshake)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_blocking<'v, Transport, CP>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<CP::CipherSuite>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer,
        key_schedule: &mut KeySchedule<CP::CipherSuite>,
        config: &ConnectConfig<'a>,
        crypto_provider: &mut CP,
    ) -> Result<State, ProtocolError>
    where
        Transport: BlockingRead + BlockingWrite + 'a,
        CP: CryptoBackend,
    {
        match self {
            State::ClientHello => {
                let (state, tx) =
                    client_hello(key_schedule, config, crypto_provider, tx_buf, handshake)?;

                respond_blocking(tx, transport, key_schedule)?;

                Ok(state)
            }
            State::ServerHello => {
                let record = record_reader.read_blocking(transport, key_schedule.read_state())?;

                let result = process_server_hello(handshake, key_schedule, record);

                handle_processing_error_blocking(result, transport, key_schedule, tx_buf)
            }
            State::ServerVerify => {
                let record = record_reader.read_blocking(transport, key_schedule.read_state())?;

                let result =
                    process_server_verify(handshake, key_schedule, crypto_provider, record);

                handle_processing_error_blocking(result, transport, key_schedule, tx_buf)
            }
            State::ClientCert => {
                let (state, tx) = client_cert(handshake, key_schedule, crypto_provider, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) = client_cert_verify(key_schedule, crypto_provider, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                client_finished_finalize(key_schedule, handshake)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }
}

fn handle_processing_error_blocking<CipherSuite>(
    result: Result<State, ProtocolError>,
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
    tx_buf: &mut WriteBuffer,
) -> Result<State, ProtocolError>
where
    CipherSuite: TlsCipherSuite,
{
    if let Err(ProtocolError::AbortHandshake(level, description)) = result {
        let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
        let tx = tx_buf.write_record(
            &ClientRecord::Alert(Alert { level, description }, false),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        respond_blocking(tx, transport, key_schedule)?;
    }

    result
}

fn respond_blocking<CipherSuite>(
    tx: &[u8],
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), ProtocolError>
where
    CipherSuite: TlsCipherSuite,
{
    transport
        .write_all(tx)
        .map_err(|e| ProtocolError::Io(e.kind()))?;

    key_schedule.write_state().increment_counter();

    transport.flush().map_err(|e| ProtocolError::Io(e.kind()))?;

    Ok(())
}

async fn handle_processing_error<CipherSuite>(
    result: Result<State, ProtocolError>,
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
    tx_buf: &mut WriteBuffer<'_>,
) -> Result<State, ProtocolError>
where
    CipherSuite: TlsCipherSuite,
{
    if let Err(ProtocolError::AbortHandshake(level, description)) = result {
        let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
        let tx = tx_buf.write_record(
            &ClientRecord::Alert(Alert { level, description }, false),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        respond(tx, transport, key_schedule).await?;
    }

    result
}

async fn respond<CipherSuite>(
    tx: &[u8],
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), ProtocolError>
where
    CipherSuite: TlsCipherSuite,
{
    transport
        .write_all(tx)
        .await
        .map_err(|e| ProtocolError::Io(e.kind()))?;

    key_schedule.write_state().increment_counter();

    transport
        .flush()
        .await
        .map_err(|e| ProtocolError::Io(e.kind()))?;

    Ok(())
}

fn client_hello<'r, CP>(
    key_schedule: &mut KeySchedule<CP::CipherSuite>,
    config: &ConnectConfig,
    crypto_provider: &mut CP,
    tx_buf: &'r mut WriteBuffer,
    handshake: &mut Handshake<CP::CipherSuite>,
) -> Result<(State, &'r [u8]), ProtocolError>
where
    CP: CryptoBackend,
{
    key_schedule.initialize_early_secret(config.psk.as_ref().map(|p| p.0))?;
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
    let client_hello = ClientRecord::client_hello(config, crypto_provider)?;
    let slice = tx_buf.write_record(&client_hello, write_key_schedule, Some(read_key_schedule))?;

    if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello), _) = client_hello {
        handshake.secret.replace(client_hello.secret);
        Ok((State::ServerHello, slice))
    } else {
        Err(ProtocolError::EncodeError)
    }
}

fn process_server_hello<CipherSuite>(
    handshake: &mut Handshake<CipherSuite>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    record: ServerRecord<'_, CipherSuite>,
) -> Result<State, ProtocolError>
where
    CipherSuite: TlsCipherSuite,
{
    match record {
        ServerRecord::Handshake(server_handshake) => match server_handshake {
            ServerHandshake::ServerHello(server_hello) => {
                trace!("********* ServerHello");
                let secret = handshake
                    .secret
                    .take()
                    .ok_or(ProtocolError::InvalidHandshake)?;
                let mut shared = [0u8; P256_SHARED_SECRET_LEN];
                let shared_len = server_hello
                    .calculate_shared_secret(&secret, &mut shared)
                    .ok_or(ProtocolError::InvalidKeyShare)?;
                key_schedule.initialize_handshake_secret(&shared[..shared_len])?;
                Ok(State::ServerVerify)
            }
            _ => Err(ProtocolError::InvalidHandshake),
        },
        ServerRecord::Alert(alert) => Err(ProtocolError::HandshakeAborted(
            alert.level,
            alert.description,
        )),
        _ => Err(ProtocolError::InvalidRecord),
    }
}

fn process_server_verify<CP>(
    handshake: &mut Handshake<CP::CipherSuite>,
    key_schedule: &mut KeySchedule<CP::CipherSuite>,
    crypto_provider: &mut CP,
    record: ServerRecord<'_, CP::CipherSuite>,
) -> Result<State, ProtocolError>
where
    CP: CryptoBackend,
{
    let mut state = State::ServerVerify;
    decrypt_record(key_schedule.read_state(), record, |key_schedule, record| {
        match record {
            ServerRecord::Handshake(server_handshake) => {
                match server_handshake {
                    ServerHandshake::EncryptedExtensions(_) => {}
                    ServerHandshake::Certificate(certificate) => {
                        let transcript = key_schedule.transcript_hash();
                        if let Ok(verifier) = crypto_provider.verifier() {
                            verifier.verify_certificate(transcript, certificate)?;
                            debug!("Certificate verified!");
                        } else {
                            debug!("Certificate verification skipped due to no verifier!");
                        }
                    }
                    ServerHandshake::HandshakeVerify(verify) => {
                        if let Ok(verifier) = crypto_provider.verifier() {
                            verifier.verify_signature(verify)?;
                            debug!("Signature verified!");
                        } else {
                            debug!("Signature verification skipped due to no verifier!");
                        }
                    }
                    ServerHandshake::CertificateRequest(request) => {
                        handshake.certificate_request.replace(request.try_into()?);
                    }
                    ServerHandshake::Finished(finished) => {
                        if !key_schedule.verify_server_finished(&finished)? {
                            warn!("Server signature verification failed");
                            return Err(ProtocolError::InvalidSignature);
                        }

                        // If the server sent a CertificateRequest we must respond with a cert before Finished
                        state = if handshake.certificate_request.is_some() {
                            State::ClientCert
                        } else {
                            handshake
                                .traffic_hash
                                .replace(key_schedule.transcript_hash().clone());
                            State::ClientFinished
                        };
                    }
                    _ => return Err(ProtocolError::InvalidHandshake),
                }
            }
            ServerRecord::ChangeCipherSpec(_) => {}
            _ => return Err(ProtocolError::InvalidRecord),
        }

        Ok(())
    })?;
    Ok(state)
}

fn client_cert<'r, CP>(
    handshake: &mut Handshake<CP::CipherSuite>,
    key_schedule: &mut KeySchedule<CP::CipherSuite>,
    crypto_provider: &mut CP,
    buffer: &'r mut WriteBuffer,
) -> Result<(State, &'r [u8]), ProtocolError>
where
    CP: CryptoBackend,
{
    handshake
        .traffic_hash
        .replace(key_schedule.transcript_hash().clone());

    let request_context = &handshake
        .certificate_request
        .as_ref()
        .ok_or(ProtocolError::InvalidHandshake)?
        .request_context;

    let cert = crypto_provider.client_cert();
    let mut certificate = CertificateRef::with_context(request_context);
    let next_state = if let Some(ref cert) = cert {
        certificate.add(cert.into())?;
        State::ClientCertVerify
    } else {
        State::ClientFinished
    };
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer
        .write_record(
            &ClientRecord::Handshake(ClientHandshake::ClientCert(certificate), true),
            write_key_schedule,
            Some(read_key_schedule),
        )
        .map(|slice| (next_state, slice))
}

fn client_cert_verify<'r, CP>(
    key_schedule: &mut KeySchedule<CP::CipherSuite>,
    crypto_provider: &mut CP,
    buffer: &'r mut WriteBuffer,
) -> Result<(Result<State, ProtocolError>, &'r [u8]), ProtocolError>
where
    CP: CryptoBackend,
{
    let (result, record) = match crypto_provider.signer() {
        Ok((mut signing_key, signature_scheme)) => {
            // CertificateVerify message format: 64 spaces + context string + \0 + transcript hash (RFC 8446 §4.4.3)
            let ctx_str = b"TLS 1.3, client CertificateVerify\x00";

            let mut msg: heapless::Vec<u8, 146> = heapless::Vec::new();
            msg.resize(64, 0x20)
                .map_err(|_| ProtocolError::EncodeError)?;
            msg.extend_from_slice(ctx_str)
                .map_err(|_| ProtocolError::EncodeError)?;
            msg.extend_from_slice(&key_schedule.transcript_hash().clone().finalize())
                .map_err(|_| ProtocolError::EncodeError)?;

            let signature = signing_key.sign(&msg);

            trace!(
                "Signature: {:?} ({})",
                signature.as_ref(),
                signature.as_ref().len()
            );

            let certificate_verify = HandshakeVerify {
                signature_scheme,
                signature: heapless::Vec::from_slice(signature.as_ref()).unwrap(),
            };

            (
                Ok(State::ClientFinished),
                ClientRecord::Handshake(
                    ClientHandshake::ClientCertVerify(certificate_verify),
                    true,
                ),
            )
        }
        Err(e) => {
            error!("Failed to obtain signing key: {:?}", e);
            (
                Err(e),
                ClientRecord::Alert(
                    Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
                    true,
                ),
            )
        }
    };

    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer
        .write_record(&record, write_key_schedule, Some(read_key_schedule))
        .map(|slice| (result, slice))
}

fn client_finished<'r, CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    buffer: &'r mut WriteBuffer,
) -> Result<&'r [u8], ProtocolError>
where
    CipherSuite: TlsCipherSuite,
{
    let client_finished = key_schedule
        .create_client_finished()
        .map_err(|_| ProtocolError::InvalidHandshake)?;

    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer.write_record(
        &ClientRecord::Handshake(ClientHandshake::Finished(client_finished), true),
        write_key_schedule,
        Some(read_key_schedule),
    )
}

fn client_finished_finalize<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    handshake: &mut Handshake<CipherSuite>,
) -> Result<State, ProtocolError>
where
    CipherSuite: TlsCipherSuite,
{
    // Restore the transcript hash captured before the client cert exchange, then derive app traffic secrets
    key_schedule.replace_transcript_hash(
        handshake
            .traffic_hash
            .take()
            .ok_or(ProtocolError::InvalidHandshake)?,
    );
    key_schedule.initialize_master_secret()?;

    Ok(State::ApplicationData)
}
