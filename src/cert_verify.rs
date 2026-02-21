use crate::ProtocolError;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, Verifier};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        Certificate as OwnedCertificate, CertificateEntryRef, CertificateRef as ServerCertificate,
    },
    certificate_verify::HandshakeVerifyRef,
};
use core::marker::PhantomData;
use digest::Digest;
use heapless::Vec;
#[cfg(all(not(feature = "alloc"), feature = "webpki"))]
impl TryInto<&'static webpki::SignatureAlgorithm> for SignatureScheme {
    type Error = ProtocolError;
    fn try_into(self) -> Result<&'static webpki::SignatureAlgorithm, Self::Error> {
        #[allow(clippy::match_same_arms)]
        match self {
            SignatureScheme::RsaPkcs1Sha256
            | SignatureScheme::RsaPkcs1Sha384
            | SignatureScheme::RsaPkcs1Sha512 => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::EcdsaSecp256r1Sha256 => Ok(&webpki::ECDSA_P256_SHA256),
            SignatureScheme::EcdsaSecp384r1Sha384 => Ok(&webpki::ECDSA_P384_SHA384),
            SignatureScheme::EcdsaSecp521r1Sha512 => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::RsaPssRsaeSha256
            | SignatureScheme::RsaPssRsaeSha384
            | SignatureScheme::RsaPssRsaeSha512 => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::Ed25519 => Ok(&webpki::ED25519),
            SignatureScheme::Ed448
            | SignatureScheme::Sha224Ecdsa
            | SignatureScheme::Sha224Rsa
            | SignatureScheme::Sha224Dsa => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::RsaPssPssSha256
            | SignatureScheme::RsaPssPssSha384
            | SignatureScheme::RsaPssPssSha512 => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::RsaPkcs1Sha1 | SignatureScheme::EcdsaSha1 => {
                Err(ProtocolError::InvalidSignatureScheme)
            }

            SignatureScheme::MlDsa44 | SignatureScheme::MlDsa65 | SignatureScheme::MlDsa87 => {
                Err(ProtocolError::InvalidSignatureScheme)
            }

            SignatureScheme::Sha256BrainpoolP256r1
            | SignatureScheme::Sha384BrainpoolP384r1
            | SignatureScheme::Sha512BrainpoolP512r1 => Err(ProtocolError::InvalidSignatureScheme),
        }
    }
}

#[cfg(all(feature = "alloc", feature = "webpki"))]
impl TryInto<&'static webpki::SignatureAlgorithm> for SignatureScheme {
    type Error = ProtocolError;
    fn try_into(self) -> Result<&'static webpki::SignatureAlgorithm, Self::Error> {
        match self {
            SignatureScheme::RsaPkcs1Sha256 => Ok(&webpki::RSA_PKCS1_2048_8192_SHA256),
            SignatureScheme::RsaPkcs1Sha384 => Ok(&webpki::RSA_PKCS1_2048_8192_SHA384),
            SignatureScheme::RsaPkcs1Sha512 => Ok(&webpki::RSA_PKCS1_2048_8192_SHA512),

            SignatureScheme::EcdsaSecp256r1Sha256 => Ok(&webpki::ECDSA_P256_SHA256),
            SignatureScheme::EcdsaSecp384r1Sha384 => Ok(&webpki::ECDSA_P384_SHA384),
            SignatureScheme::EcdsaSecp521r1Sha512 => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::RsaPssRsaeSha256 => Ok(&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
            SignatureScheme::RsaPssRsaeSha384 => Ok(&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
            SignatureScheme::RsaPssRsaeSha512 => Ok(&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),

            SignatureScheme::Ed25519 => Ok(&webpki::ED25519),
            SignatureScheme::Ed448 => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::Sha224Ecdsa => Err(ProtocolError::InvalidSignatureScheme),
            SignatureScheme::Sha224Rsa => Err(ProtocolError::InvalidSignatureScheme),
            SignatureScheme::Sha224Dsa => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::RsaPssPssSha256 => Err(ProtocolError::InvalidSignatureScheme),
            SignatureScheme::RsaPssPssSha384 => Err(ProtocolError::InvalidSignatureScheme),
            SignatureScheme::RsaPssPssSha512 => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::RsaPkcs1Sha1 => Err(ProtocolError::InvalidSignatureScheme),
            SignatureScheme::EcdsaSha1 => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::MlDsa44 => Err(ProtocolError::InvalidSignatureScheme),
            SignatureScheme::MlDsa65 => Err(ProtocolError::InvalidSignatureScheme),
            SignatureScheme::MlDsa87 => Err(ProtocolError::InvalidSignatureScheme),

            SignatureScheme::Sha256BrainpoolP256r1 => Err(ProtocolError::InvalidSignatureScheme),
            SignatureScheme::Sha384BrainpoolP384r1 => Err(ProtocolError::InvalidSignatureScheme),
            SignatureScheme::Sha512BrainpoolP512r1 => Err(ProtocolError::InvalidSignatureScheme),
        }
    }
}

static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
];

pub struct CertVerifier<'a, CipherSuite, Clock, const CERT_SIZE: usize>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    ca: Certificate<&'a [u8]>,
    host: Option<heapless::String<64>>,
    certificate_transcript: Option<CipherSuite::Hash>,
    certificate: Option<OwnedCertificate<CERT_SIZE>>,
    _clock: PhantomData<Clock>,
}

impl<'a, CipherSuite, Clock, const CERT_SIZE: usize> CertVerifier<'a, CipherSuite, Clock, CERT_SIZE>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    #[must_use]
    pub fn new(ca: Certificate<&'a [u8]>) -> Self {
        Self {
            ca,
            host: None,
            certificate_transcript: None,
            certificate: None,
            _clock: PhantomData,
        }
    }
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> Verifier<CipherSuite>
    for CertVerifier<'_, CipherSuite, Clock, CERT_SIZE>
where
    CipherSuite: TlsCipherSuite,
    Clock: TlsClock,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), ProtocolError> {
        self.host.replace(
            heapless::String::try_from(hostname).map_err(|_| ProtocolError::InsufficientSpace)?,
        );
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        cert: ServerCertificate,
    ) -> Result<(), ProtocolError> {
        verify_certificate(self.host.as_deref(), &self.ca, &cert, Clock::now())?;
        self.certificate.replace(cert.try_into()?);
        self.certificate_transcript.replace(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: HandshakeVerifyRef) -> Result<(), ProtocolError> {
        let handshake_hash = unwrap!(self.certificate_transcript.take());
        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg: Vec<u8, 130> = Vec::new();
        msg.resize(64, 0x20)
            .map_err(|_| ProtocolError::EncodeError)?;
        msg.extend_from_slice(ctx_str)
            .map_err(|_| ProtocolError::EncodeError)?;
        msg.extend_from_slice(&handshake_hash.finalize())
            .map_err(|_| ProtocolError::EncodeError)?;

        let certificate = unwrap!(self.certificate.as_ref()).try_into()?;
        verify_signature(&msg[..], &certificate, &verify)?;
        Ok(())
    }
}

fn verify_signature(
    message: &[u8],
    certificate: &ServerCertificate,
    verify: &HandshakeVerifyRef,
) -> Result<(), ProtocolError> {
    let mut verified = false;
    if !certificate.entries.is_empty() {
        if let CertificateEntryRef::X509(certificate) = certificate.entries[0] {
            let cert = webpki::EndEntityCert::try_from(certificate).map_err(|e| {
                warn!("ProtocolError loading cert: {:?}", e);
                ProtocolError::DecodeError
            })?;

            trace!(
                "Verifying with signature scheme {:?}",
                verify.signature_scheme
            );
            info!("Signature: {:x?}", verify.signature);
            let pkisig = verify.signature_scheme.try_into()?;
            match cert.verify_signature(pkisig, message, verify.signature) {
                Ok(()) => {
                    verified = true;
                }
                Err(e) => {
                    info!("ProtocolError verifying signature: {:?}", e);
                }
            }
        }
    }
    if !verified {
        return Err(ProtocolError::InvalidSignature);
    }
    Ok(())
}

fn verify_certificate(
    verify_host: Option<&str>,
    ca: &Certificate<&[u8]>,
    certificate: &ServerCertificate,
    now: Option<u64>,
) -> Result<(), ProtocolError> {
    let mut verified = false;
    let mut host_verified = false;
    if let Certificate::X509(ca) = ca {
        let trust = webpki::TrustAnchor::try_from_cert_der(ca).map_err(|e| {
            warn!("ProtocolError loading CA: {:?}", e);
            ProtocolError::DecodeError
        })?;

        trace!("We got {} certificate entries", certificate.entries.len());

        if !certificate.entries.is_empty() {
            if let CertificateEntryRef::X509(certificate) = certificate.entries[0] {
                let cert = webpki::EndEntityCert::try_from(certificate).map_err(|e| {
                    warn!("ProtocolError loading cert: {:?}", e);
                    ProtocolError::DecodeError
                })?;

                let time = if let Some(now) = now {
                    webpki::Time::from_seconds_since_unix_epoch(now)
                } else {
                    webpki::Time::from_seconds_since_unix_epoch(0)
                };
                info!("Certificate is loaded!");
                match cert.verify_for_usage(
                    ALL_SIGALGS,
                    &[trust],
                    &[],
                    time,
                    webpki::KeyUsage::server_auth(),
                    &[],
                ) {
                    Ok(()) => verified = true,
                    Err(e) => {
                        warn!("ProtocolError verifying certificate: {:?}", e);
                    }
                }

                if let Some(server_name) = verify_host {
                    match webpki::SubjectNameRef::try_from_ascii(server_name.as_bytes()) {
                        Ok(subject) => match cert.verify_is_valid_for_subject_name(subject) {
                            Ok(()) => host_verified = true,
                            Err(e) => {
                                warn!("ProtocolError verifying host: {:?}", e);
                            }
                        },
                        Err(e) => {
                            warn!("ProtocolError verifying host: {:?}", e);
                        }
                    }
                }
            }
        }
    }

    if !verified {
        return Err(ProtocolError::InvalidCertificate);
    }

    if !host_verified && verify_host.is_some() {
        return Err(ProtocolError::InvalidCertificate);
    }
    Ok(())
}
