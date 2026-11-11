use crate::ProtocolError;
#[cfg(feature = "p384")]
use crate::certificate::ECDSA_SHA384;
#[cfg(feature = "ed25519")]
use crate::certificate::ED25519;
use crate::certificate::{DecodedCertificate, ECDSA_SHA256, Time};
#[cfg(feature = "rsa")]
use crate::certificate::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512};
use crate::config::{Certificate, TlsCipherSuite, TlsClock, Verifier};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        Certificate as OwnedCertificate, CertificateEntryRef, CertificateRef as ServerCertificate,
    },
    certificate_verify::HandshakeVerifyRef,
};
use crate::parse_buffer::ParseError;
use const_oid::ObjectIdentifier;
use core::marker::PhantomData;
use der::Decode;
use digest::Digest;
use heapless::{String, Vec};

const HOSTNAME_MAXLEN: usize = 64;
const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

pub struct CertificateChain<'a> {
    prev: Option<&'a CertificateEntryRef<'a>>,
    chain: &'a ServerCertificate<'a>,
    idx: isize,
}

impl<'a> CertificateChain<'a> {
    pub fn new(ca: &'a CertificateEntryRef, chain: &'a ServerCertificate<'a>) -> Self {
        Self {
            prev: Some(ca),
            chain,
            idx: chain.entries.len() as isize - 1,
        }
    }
}

impl<'a> Iterator for CertificateChain<'a> {
    type Item = (&'a CertificateEntryRef<'a>, &'a CertificateEntryRef<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx < 0 {
            return None;
        }

        let cur = &self.chain.entries[self.idx as usize];
        let out = (self.prev.unwrap(), cur);

        self.prev = Some(cur);
        self.idx -= 1;

        Some(out)
    }
}

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
        let mut cn = None;
        for (p, q) in CertificateChain::new(&(&self.ca).into(), &cert) {
            cn = verify_certificate(p, q, Clock::now())?;
        }
        if self.host.ne(&cn) {
            error!(
                "Hostname ({:?}) does not match CommonName ({:?})",
                self.host, cn
            );
            return Err(ProtocolError::InvalidCertificate);
        }

        self.certificate.replace(cert.try_into()?);
        self.certificate_transcript.replace(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: HandshakeVerifyRef) -> Result<(), ProtocolError> {
        let handshake_hash = unwrap!(self.certificate_transcript.take());
        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg: Vec<u8, 146> = Vec::new();
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
    let verified;

    let certificate =
        if let Some(CertificateEntryRef::X509(certificate)) = certificate.entries.first() {
            certificate
        } else {
            return Err(ProtocolError::DecodeError);
        };

    let certificate =
        DecodedCertificate::from_der(certificate).map_err(|_| ProtocolError::DecodeError)?;

    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .public_key
        .as_bytes()
        .ok_or(ProtocolError::DecodeError)?;

    match verify.signature_scheme {
        SignatureScheme::EcdsaSecp256r1Sha256 => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| ProtocolError::DecodeError)?;
            let signature =
                Signature::from_der(&verify.signature).map_err(|_| ProtocolError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "p384")]
        SignatureScheme::EcdsaSecp384r1Sha384 => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| ProtocolError::DecodeError)?;
            let signature =
                Signature::from_der(&verify.signature).map_err(|_| ProtocolError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "ed25519")]
        SignatureScheme::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let verifying_key: VerifyingKey =
                VerifyingKey::from_bytes(public_key.try_into().unwrap())
                    .map_err(|_| ProtocolError::DecodeError)?;
            let signature =
                Signature::try_from(verify.signature).map_err(|_| ProtocolError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha256 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha256;

            let der_pubkey = RsaPublicKey::from_pkcs1_der(public_key).unwrap();
            let verifying_key = VerifyingKey::<Sha256>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| ProtocolError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha384 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha384;

            let der_pubkey =
                RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| ProtocolError::DecodeError)?;
            let verifying_key = VerifyingKey::<Sha384>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| ProtocolError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha512 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha512;

            let der_pubkey =
                RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| ProtocolError::DecodeError)?;
            let verifying_key = VerifyingKey::<Sha512>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| ProtocolError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        _ => {
            error!(
                "InvalidSignatureScheme: {:?} Are you missing a feature?",
                verify.signature_scheme
            );
            return Err(ProtocolError::InvalidSignatureScheme);
        }
    }

    if !verified {
        return Err(ProtocolError::InvalidSignature);
    }
    Ok(())
}

fn get_certificate_tlv_bytes<'a>(input: &[u8]) -> der::Result<&[u8]> {
    use der::{Decode, Reader, SliceReader};

    let mut reader = SliceReader::new(input)?;
    let top_header = der::Header::decode(&mut reader)?;
    top_header.tag().assert_eq(der::Tag::Sequence)?;

    let header = der::Header::peek(&mut reader)?;
    header.tag().assert_eq(der::Tag::Sequence)?;

    reader.tlv_bytes()
}

fn get_cert_time(time: Time) -> u64 {
    match time {
        Time::UtcTime(utc_time) => utc_time.to_unix_duration().as_secs(),
        Time::GeneralTime(generalized_time) => generalized_time.to_unix_duration().as_secs(),
    }
}

fn verify_certificate(
    verifier: &CertificateEntryRef,
    certificate: &CertificateEntryRef,
    now: Option<u64>,
) -> Result<Option<heapless::String<HOSTNAME_MAXLEN>>, ProtocolError> {
    let mut verified = false;
    let mut common_name = None;

    let ca_certificate = if let CertificateEntryRef::X509(verifier) = verifier {
        DecodedCertificate::from_der(verifier).map_err(|_| ProtocolError::DecodeError)?
    } else {
        return Err(ProtocolError::DecodeError);
    };

    if let CertificateEntryRef::X509(certificate) = certificate {
        let parsed_certificate =
            DecodedCertificate::from_der(certificate).map_err(|_| ProtocolError::DecodeError)?;

        let ca_public_key = ca_certificate
            .tbs_certificate
            .subject_public_key_info
            .public_key
            .as_bytes()
            .ok_or(ProtocolError::DecodeError)?;

        for elems in parsed_certificate.tbs_certificate.subject.iter() {
            let attrs = elems
                .get(0)
                .ok_or(ProtocolError::ParseError(ParseError::InvalidData))?;
            if attrs.oid == COMMON_NAME_OID {
                let mut v: Vec<u8, HOSTNAME_MAXLEN> = Vec::new();
                v.extend_from_slice(attrs.value.value())
                    .map_err(|_| ProtocolError::ParseError(ParseError::InvalidData))?;
                common_name = String::from_utf8(v).ok();
                debug!("CommonName: {:?}", common_name);
            }
        }

        if let Some(now) = now {
            if get_cert_time(parsed_certificate.tbs_certificate.validity.not_before) > now
                || get_cert_time(parsed_certificate.tbs_certificate.validity.not_after) < now
            {
                return Err(ProtocolError::InvalidCertificate);
            }
            debug!("Epoch is {} and certificate is valid!", now)
        }

        let certificate_data =
            get_certificate_tlv_bytes(certificate).map_err(|_| ProtocolError::DecodeError)?;

        match parsed_certificate.signature_algorithm {
            ECDSA_SHA256 => {
                use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
                let verifying_key = VerifyingKey::from_sec1_bytes(ca_public_key)
                    .map_err(|_| ProtocolError::DecodeError)?;

                let signature = Signature::from_der(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(ProtocolError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| ProtocolError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(&certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "p384")]
            ECDSA_SHA384 => {
                use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
                let verifying_key = VerifyingKey::from_sec1_bytes(ca_public_key)
                    .map_err(|_| ProtocolError::DecodeError)?;

                let signature = Signature::from_der(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(ProtocolError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| ProtocolError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(&certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "ed25519")]
            ED25519 => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let verifying_key: VerifyingKey =
                    VerifyingKey::from_bytes(ca_public_key.try_into().unwrap())
                        .map_err(|_| ProtocolError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(ProtocolError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| ProtocolError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "rsa")]
            a if a == RSA_PKCS1_SHA256 => {
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };
                use sha2::Sha256;

                let verifying_key =
                    VerifyingKey::<Sha256>::from_pkcs1_der(ca_public_key).map_err(|e| {
                        error!("VerifyingKey: {}", fmt_err!(e));
                        ProtocolError::DecodeError
                    })?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(ProtocolError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|e| {
                    error!("Signature: {}", fmt_err!(e));
                    ProtocolError::ParseError(ParseError::InvalidData)
                })?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "rsa")]
            a if a == RSA_PKCS1_SHA384 => {
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };
                use sha2::Sha384;

                let verifying_key = VerifyingKey::<Sha384>::from_pkcs1_der(ca_public_key)
                    .map_err(|_| ProtocolError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(ProtocolError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| ProtocolError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "rsa")]
            a if a == RSA_PKCS1_SHA512 => {
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };
                use sha2::Sha512;

                let verifying_key = VerifyingKey::<Sha512>::from_pkcs1_der(ca_public_key)
                    .map_err(|_| ProtocolError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(ProtocolError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| ProtocolError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            _ => {
                error!(
                    "Unsupported signature alg: {:?}",
                    parsed_certificate.signature_algorithm
                );
                return Err(ProtocolError::InvalidSignatureScheme);
            }
        }
    }

    if !verified {
        return Err(ProtocolError::InvalidCertificate);
    }

    Ok(common_name)
}
