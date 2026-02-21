#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc
)]

pub(crate) mod fmt;

use parse_buffer::ParseError;
pub mod alert;
mod application_data;
pub mod blocking;
mod buffer;
mod change_cipher_spec;
mod cipher;
mod cipher_suites;
mod common;
mod config;
mod connection;
mod content_types;
mod extensions;
mod handshake;
mod key_schedule;
mod parse_buffer;
pub mod read_buffer;
mod record;
mod record_reader;
pub mod send_policy;
mod write_buffer;

pub use config::SkipVerifyProvider;
pub use extensions::extension_data::signature_algorithms::SignatureScheme;
pub use handshake::certificate_verify::HandshakeVerify;
pub use rand_core::{CryptoRng, CryptoRngCore};

#[cfg(feature = "webpki")]
pub mod cert_verify;

#[cfg(feature = "native-pki")]
mod certificate;
#[cfg(feature = "native-pki")]
pub mod native_pki;

mod asynch;
pub use asynch::*;

pub use send_policy::*;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ProtocolError {
    ConnectionClosed,
    Unimplemented,
    MissingHandshake,
    HandshakeAborted(alert::AlertLevel, alert::AlertDescription),
    AbortHandshake(alert::AlertLevel, alert::AlertDescription),
    IoError,
    InternalError,
    InvalidRecord,
    UnknownContentType,
    InvalidNonceLength,
    InvalidTicketLength,
    UnknownExtensionType,
    InsufficientSpace,
    InvalidHandshake,
    InvalidCipherSuite,
    InvalidSignatureScheme,
    InvalidSignature,
    InvalidExtensionsLength,
    InvalidSessionIdLength,
    InvalidSupportedVersions,
    InvalidApplicationData,
    InvalidKeyShare,
    InvalidCertificate,
    InvalidCertificateEntry,
    InvalidCertificateRequest,
    InvalidPrivateKey,
    UnableToInitializeCryptoEngine,
    ParseError(ParseError),
    OutOfMemory,
    CryptoError,
    EncodeError,
    DecodeError,
    Io(embedded_io::ErrorKind),
}

impl embedded_io::Error for ProtocolError {
    fn kind(&self) -> embedded_io::ErrorKind {
        if let Self::Io(k) = self {
            *k
        } else {
            error!("TLS error: {:?}", self);
            embedded_io::ErrorKind::Other
        }
    }
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for ProtocolError {}

#[cfg(feature = "std")]
mod stdlib {
    use crate::config::TlsClock;

    use std::time::SystemTime;
    impl TlsClock for SystemTime {
        fn now() -> Option<u64> {
            Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
        }
    }
}

fn unused<T>(_: T) {}
