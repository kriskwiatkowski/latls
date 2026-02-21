use core::marker::PhantomData;

use crate::ProtocolError;
use crate::cipher_suites::CipherSuite;
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::extensions::extension_data::supported_groups::NamedGroup;
pub use crate::handshake::certificate::{CertificateEntryRef, CertificateRef};
pub use crate::handshake::certificate_verify::HandshakeVerifyRef;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit};
use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutput, OutputSizeUser, Reset};
use ecdsa::elliptic_curve::SecretKey;
use generic_array::ArrayLength;
use heapless::Vec;
use p256::ecdsa::SigningKey;
use rand_core::CryptoRngCore;
pub use sha2::{Sha256, Sha384};
use typenum::{Sum, U10, U12, U16, U32};

pub use crate::extensions::extension_data::max_fragment_length::MaxFragmentLength;

/// Extra bytes required per record for the TLS 1.3 header, authentication tag, and inner content type.
pub const TLS_RECORD_OVERHEAD: usize = 128;

type LongestLabel = U12;
type LabelOverhead = U10;
type LabelBuffer<CipherSuite> = Sum<
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize,
    Sum<LongestLabel, LabelOverhead>,
>;

/// Associates a cipher, key/IV lengths, hash algorithm, and label buffer size for a TLS 1.3 cipher suite.
pub trait TlsCipherSuite {
    const CODE_POINT: u16;
    type Cipher: KeyInit<KeySize = Self::KeyLen> + AeadInPlace<NonceSize = Self::IvLen>;
    type KeyLen: ArrayLength<u8>;
    type IvLen: ArrayLength<u8>;

    type Hash: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser + FixedOutput;
    type LabelBufferSize: ArrayLength<u8>;
}

pub struct Aes128GcmSha256;
impl TlsCipherSuite for Aes128GcmSha256 {
    const CODE_POINT: u16 = CipherSuite::TlsAes128GcmSha256 as u16;
    type Cipher = Aes128Gcm;
    type KeyLen = U16;
    type IvLen = U12;

    type Hash = Sha256;
    type LabelBufferSize = LabelBuffer<Self>;
}

pub struct Aes256GcmSha384;
impl TlsCipherSuite for Aes256GcmSha384 {
    const CODE_POINT: u16 = CipherSuite::TlsAes256GcmSha384 as u16;
    type Cipher = Aes256Gcm;
    type KeyLen = U32;
    type IvLen = U12;

    type Hash = Sha384;
    type LabelBufferSize = LabelBuffer<Self>;
}

/// Certificate and server-identity verification interface. Implement to enforce PKI validation.
pub trait Verifier<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), crate::ProtocolError>;

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        cert: CertificateRef,
    ) -> Result<(), ProtocolError>;

    fn verify_signature(&mut self, verify: HandshakeVerifyRef) -> Result<(), crate::ProtocolError>;
}

/// A [`Verifier`] that accepts any certificate without validation. Useful for testing only.
pub struct NoVerify;

impl<CipherSuite> Verifier<CipherSuite> for NoVerify
where
    CipherSuite: TlsCipherSuite,
{
    fn set_hostname_verification(&mut self, _hostname: &str) -> Result<(), crate::ProtocolError> {
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        _transcript: &CipherSuite::Hash,
        _cert: CertificateRef,
    ) -> Result<(), ProtocolError> {
        Ok(())
    }

    fn verify_signature(
        &mut self,
        _verify: HandshakeVerifyRef,
    ) -> Result<(), crate::ProtocolError> {
        Ok(())
    }
}

/// Configuration for a single TLS client connection: server name, PSK, cipher preferences, etc.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "ConnectConfig does nothing unless consumed"]
pub struct ConnectConfig<'a> {
    pub(crate) server_name: Option<&'a str>,
    pub(crate) alpn_protocols: Option<&'a [&'a [u8]]>,
    // PSK value and the list of identity labels to offer in the ClientHello
    pub(crate) psk: Option<(&'a [u8], Vec<&'a [u8], 4>)>,
    pub(crate) signature_schemes: Vec<SignatureScheme, 25>,
    pub(crate) named_groups: Vec<NamedGroup, 13>,
    pub(crate) max_fragment_length: Option<MaxFragmentLength>,
}

pub trait TlsClock {
    fn now() -> Option<u64>;
}

pub struct NoClock;

impl TlsClock for NoClock {
    fn now() -> Option<u64> {
        None
    }
}

/// Provides the RNG, cipher suite, optional certificate verifier, and optional client signing key.
pub trait CryptoBackend {
    type CipherSuite: TlsCipherSuite;
    type Signature: AsRef<[u8]>;

    fn rng(&mut self) -> impl CryptoRngCore;

    fn verifier(&mut self) -> Result<&mut impl Verifier<Self::CipherSuite>, crate::ProtocolError> {
        Err::<&mut NoVerify, _>(crate::ProtocolError::Unimplemented)
    }

    fn signer(
        &mut self,
    ) -> Result<(impl signature::SignerMut<Self::Signature>, SignatureScheme), crate::ProtocolError>
    {
        Err::<(NoSign, _), crate::ProtocolError>(crate::ProtocolError::Unimplemented)
    }

    fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
        None::<Certificate<&[u8]>>
    }
}

impl<T: CryptoBackend> CryptoBackend for &mut T {
    type CipherSuite = T::CipherSuite;

    type Signature = T::Signature;

    fn rng(&mut self) -> impl CryptoRngCore {
        T::rng(self)
    }

    fn verifier(&mut self) -> Result<&mut impl Verifier<Self::CipherSuite>, crate::ProtocolError> {
        T::verifier(self)
    }

    fn signer(
        &mut self,
    ) -> Result<(impl signature::SignerMut<Self::Signature>, SignatureScheme), crate::ProtocolError>
    {
        T::signer(self)
    }

    fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
        T::client_cert(self)
    }
}

pub struct NoSign;

impl<S> signature::Signer<S> for NoSign {
    fn try_sign(&self, _msg: &[u8]) -> Result<S, signature::Error> {
        unimplemented!()
    }
}

/// A [`CryptoBackend`] that skips certificate verification. Suitable for testing or constrained environments.
pub struct SkipVerifyProvider<'a, CipherSuite, RNG> {
    rng: RNG,
    priv_key: Option<&'a [u8]>,
    client_cert: Option<Certificate<&'a [u8]>>,
    _marker: PhantomData<CipherSuite>,
}

impl<RNG: CryptoRngCore> SkipVerifyProvider<'_, (), RNG> {
    pub fn new<CipherSuite: TlsCipherSuite>(
        rng: RNG,
    ) -> SkipVerifyProvider<'static, CipherSuite, RNG> {
        SkipVerifyProvider {
            rng,
            priv_key: None,
            client_cert: None,
            _marker: PhantomData,
        }
    }
}

impl<'a, CipherSuite: TlsCipherSuite, RNG: CryptoRngCore> SkipVerifyProvider<'a, CipherSuite, RNG> {
    #[must_use]
    pub fn with_priv_key(mut self, priv_key: &'a [u8]) -> Self {
        self.priv_key = Some(priv_key);
        self
    }

    #[must_use]
    pub fn with_cert(mut self, cert: Certificate<&'a [u8]>) -> Self {
        self.client_cert = Some(cert);
        self
    }
}

impl<CipherSuite: TlsCipherSuite, RNG: CryptoRngCore> CryptoBackend
    for SkipVerifyProvider<'_, CipherSuite, RNG>
{
    type CipherSuite = CipherSuite;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }

    fn signer(
        &mut self,
    ) -> Result<(impl signature::SignerMut<Self::Signature>, SignatureScheme), crate::ProtocolError>
    {
        let key_der = self.priv_key.ok_or(ProtocolError::InvalidPrivateKey)?;
        let secret_key =
            SecretKey::from_sec1_der(key_der).map_err(|_| ProtocolError::InvalidPrivateKey)?;

        Ok((
            SigningKey::from(&secret_key),
            SignatureScheme::EcdsaSecp256r1Sha256,
        ))
    }

    fn client_cert(&mut self) -> Option<Certificate<impl AsRef<[u8]>>> {
        self.client_cert.clone()
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectContext<'a, CP>
where
    CP: CryptoBackend,
{
    pub(crate) config: &'a ConnectConfig<'a>,
    pub(crate) crypto_provider: CP,
}

impl<'a, CP> ConnectContext<'a, CP>
where
    CP: CryptoBackend,
{
    pub fn new(config: &'a ConnectConfig<'a>, crypto_provider: CP) -> Self {
        Self {
            config,
            crypto_provider,
        }
    }
}

impl<'a> ConnectConfig<'a> {
    pub fn new() -> Self {
        let mut config = Self {
            signature_schemes: Vec::new(),
            named_groups: Vec::new(),
            max_fragment_length: None,
            psk: None,
            server_name: None,
            alpn_protocols: None,
        };

        // RSA signature schemes are disabled by default to save code size; opt in via `alloc` feature
        if cfg!(feature = "alloc") {
            config = config.enable_rsa_signatures();
        }

        unwrap!(
            config
                .signature_schemes
                .push(SignatureScheme::EcdsaSecp256r1Sha256)
                .ok()
        );
        unwrap!(
            config
                .signature_schemes
                .push(SignatureScheme::EcdsaSecp384r1Sha384)
                .ok()
        );
        unwrap!(config.signature_schemes.push(SignatureScheme::Ed25519).ok());

        unwrap!(config.named_groups.push(NamedGroup::Secp256r1));

        config
    }

    pub fn enable_rsa_signatures(mut self) -> Self {
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha256)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha384)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha512)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha256)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha384)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha512)
                .ok()
        );
        self
    }

    pub fn with_server_name(mut self, server_name: &'a str) -> Self {
        self.server_name = Some(server_name);
        self
    }

    pub fn with_alpn(mut self, protocols: &'a [&'a [u8]]) -> Self {
        self.alpn_protocols = Some(protocols);
        self
    }

    pub fn with_max_fragment_length(mut self, max_fragment_length: MaxFragmentLength) -> Self {
        self.max_fragment_length = Some(max_fragment_length);
        self
    }

    pub fn reset_max_fragment_length(mut self) -> Self {
        self.max_fragment_length = None;
        self
    }

    pub fn with_psk(mut self, psk: &'a [u8], identities: &[&'a [u8]]) -> Self {
        self.psk = Some((psk, unwrap!(Vec::from_slice(identities).ok())));
        self
    }
}

impl Default for ConnectConfig<'_> {
    fn default() -> Self {
        ConnectConfig::new()
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Certificate<D> {
    X509(D),
    RawPublicKey(D),
}
