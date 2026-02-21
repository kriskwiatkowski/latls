use heapless::Vec;

use crate::cipher::CryptoEngine;
use crate::cipher_suites::CipherSuite;
use crate::extensions::extension_data::key_share::KeyShareEntry;
use crate::extensions::messages::ServerHelloExtension;
use crate::parse_buffer::ParseBuffer;
use crate::{ProtocolError, unused};
use p256::PublicKey;
use p256::ecdh::{EphemeralSecret, SharedSecret};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerHello<'a> {
    extensions: Vec<ServerHelloExtension<'a>, 4>,
}

impl<'a> ServerHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<ServerHello<'a>, ProtocolError> {
        // legacy_version is always 0x0303 in TLS 1.3; actual version is negotiated via extensions
        let _version = buf
            .read_u16()
            .map_err(|_| ProtocolError::InvalidHandshake)?;

        let mut random = [0; 32];
        buf.fill(&mut random)?;

        let session_id_length = buf
            .read_u8()
            .map_err(|_| ProtocolError::InvalidSessionIdLength)?;

        // Legacy session ID echo: TLS 1.3 servers echo the client's session ID for middlebox compatibility
        let session_id = buf
            .slice(session_id_length as usize)
            .map_err(|_| ProtocolError::InvalidSessionIdLength)?;

        let cipher_suite =
            CipherSuite::parse(buf).map_err(|_| ProtocolError::InvalidCipherSuite)?;

        // compression_method: always 0x00 in TLS 1.3
        buf.read_u8()?;

        let extensions = ServerHelloExtension::parse_vector(buf)?;

        debug!("server cipher_suite {:?}", cipher_suite);
        debug!("server extensions {:?}", extensions);

        unused(session_id);
        Ok(Self { extensions })
    }

    pub fn key_share(&self) -> Option<&KeyShareEntry<'_>> {
        self.extensions.iter().find_map(|e| {
            if let ServerHelloExtension::KeyShare(entry) = e {
                Some(&entry.0)
            } else {
                None
            }
        })
    }

    /// Performs ECDH with the server's key share to derive the shared secret used in the handshake.
    pub fn calculate_shared_secret(&self, secret: &EphemeralSecret) -> Option<SharedSecret> {
        let server_key_share = self.key_share()?;
        let server_public_key = PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
        Some(secret.diffie_hellman(&server_public_key))
    }

    #[allow(dead_code)]
    pub fn initialize_crypto_engine(&self, secret: &EphemeralSecret) -> Option<CryptoEngine> {
        let server_key_share = self.key_share()?;

        let group = server_key_share.group;

        let server_public_key = PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
        let shared = secret.diffie_hellman(&server_public_key);

        Some(CryptoEngine::new(group, shared))
    }
}
