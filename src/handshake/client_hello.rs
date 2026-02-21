use core::marker::PhantomData;

use digest::{Digest, OutputSizeUser};
use heapless::Vec;
use p256::EncodedPoint;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::RngCore;
use typenum::Unsigned;

use crate::ProtocolError;
use crate::config::{ConnectConfig, TlsCipherSuite};
use crate::extensions::extension_data::alpn::AlpnProtocolNameList;
use crate::extensions::extension_data::key_share::{KeyShareClientHello, KeyShareEntry};
use crate::extensions::extension_data::pre_shared_key::PreSharedKeyClientHello;
use crate::extensions::extension_data::psk_key_exchange_modes::{
    PskKeyExchangeMode, PskKeyExchangeModes,
};
use crate::extensions::extension_data::server_name::ServerNameList;
use crate::extensions::extension_data::signature_algorithms::SignatureAlgorithms;
use crate::extensions::extension_data::supported_groups::{NamedGroup, SupportedGroups};
use crate::extensions::extension_data::supported_versions::{SupportedVersionsClientHello, TLS13};
use crate::extensions::messages::ClientHelloExtension;
use crate::handshake::{LEGACY_VERSION, Random};
use crate::key_schedule::{HashOutputSize, WriteKeySchedule};
use crate::{CryptoBackend, buffer::CryptoBuffer};

pub struct ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) config: &'config ConnectConfig<'config>,
    random: Random,
    cipher_suite: PhantomData<CipherSuite>,
    pub(crate) secret: EphemeralSecret,
}

impl<'config, CipherSuite> ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new<CP>(config: &'config ConnectConfig<'config>, mut provider: CP) -> Self
    where
        CP: CryptoBackend,
    {
        let mut random = [0; 32];
        provider.rng().fill_bytes(&mut random);

        Self {
            config,
            random,
            cipher_suite: PhantomData,
            secret: EphemeralSecret::random(&mut provider.rng()),
        }
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), ProtocolError> {
        let public_key = EncodedPoint::from(&self.secret.public_key());
        let public_key = public_key.as_ref();

        buf.push_u16(LEGACY_VERSION)
            .map_err(|_| ProtocolError::EncodeError)?;
        buf.extend_from_slice(&self.random)
            .map_err(|_| ProtocolError::EncodeError)?;

        // Empty legacy session ID — TLS 1.3 doesn't use it, but the field must be present
        buf.push(0).map_err(|_| ProtocolError::EncodeError)?;

        // Exactly one cipher suite entry (2-byte length prefix + 2-byte code point)
        buf.push_u16(2).map_err(|_| ProtocolError::EncodeError)?;
        buf.push_u16(CipherSuite::CODE_POINT)
            .map_err(|_| ProtocolError::EncodeError)?;

        // Legacy compression methods: one entry, 0x00 = no compression
        buf.push(1).map_err(|_| ProtocolError::EncodeError)?;
        buf.push(0).map_err(|_| ProtocolError::EncodeError)?;

        buf.with_u16_length(|buf| {
            ClientHelloExtension::SupportedVersions(SupportedVersionsClientHello {
                versions: Vec::from_slice(&[TLS13]).unwrap(),
            })
            .encode(buf)?;

            ClientHelloExtension::SignatureAlgorithms(SignatureAlgorithms {
                supported_signature_algorithms: self.config.signature_schemes.clone(),
            })
            .encode(buf)?;

            if let Some(max_fragment_length) = self.config.max_fragment_length {
                ClientHelloExtension::MaxFragmentLength(max_fragment_length).encode(buf)?;
            }

            ClientHelloExtension::SupportedGroups(SupportedGroups {
                supported_groups: self.config.named_groups.clone(),
            })
            .encode(buf)?;

            ClientHelloExtension::PskKeyExchangeModes(PskKeyExchangeModes {
                modes: Vec::from_slice(&[PskKeyExchangeMode::PskDheKe]).unwrap(),
            })
            .encode(buf)?;

            ClientHelloExtension::KeyShare(KeyShareClientHello {
                client_shares: Vec::from_slice(&[KeyShareEntry {
                    group: NamedGroup::Secp256r1,
                    opaque: public_key,
                }])
                .unwrap(),
            })
            .encode(buf)?;

            if let Some(server_name) = self.config.server_name {
                ClientHelloExtension::ServerName(ServerNameList::single(server_name))
                    .encode(buf)?;
            }

            if let Some(alpn_protocols) = self.config.alpn_protocols {
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(AlpnProtocolNameList {
                    protocols: alpn_protocols,
                })
                .encode(buf)?;
            }

            if let Some((_, identities)) = &self.config.psk {
                ClientHelloExtension::PreSharedKey(PreSharedKeyClientHello {
                    identities: identities.clone(),
                    hash_size: <CipherSuite::Hash as OutputSizeUser>::output_size(),
                })
                .encode(buf)?;
            }

            Ok(())
        })?;

        Ok(())
    }

    pub fn finalize(
        &self,
        enc_buf: &mut [u8],
        transcript: &mut CipherSuite::Hash,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), ProtocolError> {
        if let Some((_, identities)) = &self.config.psk {
            // PSK binders depend on the transcript up to (but not including) the binder values,
            // so we hash the partial message, compute binders, then hash the remainder (RFC 8446 §4.2.11.2)
            let binders_len = identities.len() * (1 + HashOutputSize::<CipherSuite>::to_usize());

            let binders_pos = enc_buf.len() - binders_len;

            transcript.update(&enc_buf[0..binders_pos - 2]);

            let mut buf = CryptoBuffer::wrap(&mut enc_buf[binders_pos..]);
            for _id in identities {
                let binder = write_key_schedule.create_psk_binder(transcript)?;
                binder.encode(&mut buf)?;
            }

            transcript.update(&enc_buf[binders_pos - 2..]);
        } else {
            transcript.update(enc_buf);
        }

        Ok(())
    }
}
