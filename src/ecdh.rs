use crate::ProtocolError;
#[cfg(feature = "std")]
use crate::psa::PsaCryptoLock;
#[cfg(feature = "std")]
use psa_crypto::operations::{key_agreement, key_management};
#[cfg(feature = "std")]
use psa_crypto::types::algorithm::{KeyAgreement, RawKeyAgreement};
#[cfg(feature = "std")]
use psa_crypto::types::key::{Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags};
#[cfg(not(feature = "std"))]
use p256::ecdh::EphemeralSecret;
#[cfg(not(feature = "std"))]
use p256::elliptic_curve::rand_core::OsRng;
#[cfg(not(feature = "std"))]
use p256::elliptic_curve::sec1::ToEncodedPoint;

/// Uncompressed P-256 public key length: 0x04 || x (32 B) || y (32 B).
pub const P256_PUBLIC_KEY_LEN: usize = 65;
/// P-256 raw ECDH shared secret length (x-coordinate only).
pub const P256_SHARED_SECRET_LEN: usize = 32;

/// Ephemeral P-256 ECDH key pair backed by PSA Crypto.
///
/// The underlying PSA volatile key is destroyed when this value is dropped.
#[cfg(feature = "std")]
pub struct EphemeralKey(psa_crypto::types::key::Id);

#[cfg(not(feature = "std"))]
pub struct EphemeralKey(EphemeralSecret);

impl EphemeralKey {
    /// Generate a fresh ephemeral P-256 key pair via PSA Crypto.
    #[cfg(feature = "std")]
    pub fn generate() -> Result<Self, ProtocolError> {
        let _lock = PsaCryptoLock::acquire();
        psa_crypto::init().map_err(|_| ProtocolError::CryptoError)?;

        let mut usage_flags = UsageFlags::default();
        usage_flags.set_derive();
        let id = key_management::generate(
            Attributes {
                key_type: Type::EccKeyPair {
                    curve_family: EccFamily::SecpR1,
                },
                bits: 256,
                lifetime: Lifetime::Volatile,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: KeyAgreement::Raw(RawKeyAgreement::Ecdh).into(),
                },
            },
            None,
        )
        .map_err(|_| ProtocolError::CryptoError)?;
        Ok(EphemeralKey(id))
    }

    #[cfg(not(feature = "std"))]
    pub fn generate() -> Result<Self, ProtocolError> {
        Ok(EphemeralKey(EphemeralSecret::random(&mut OsRng)))
    }

    /// Export the uncompressed public key into `buf` (must be ≥ 65 bytes).
    /// Returns the number of bytes written.
    #[cfg(feature = "std")]
    pub fn public_key_bytes(&self, buf: &mut [u8]) -> Result<usize, ProtocolError> {
        let _lock = PsaCryptoLock::acquire();
        key_management::export_public(self.0, buf).map_err(|_| ProtocolError::CryptoError)
    }

    #[cfg(not(feature = "std"))]
    pub fn public_key_bytes(&self, buf: &mut [u8]) -> Result<usize, ProtocolError> {
        let public_key = self.0.public_key().to_encoded_point(false);
        let bytes = public_key.as_bytes();
        buf.get_mut(..bytes.len())
            .ok_or(ProtocolError::CryptoError)?
            .copy_from_slice(bytes);
        Ok(bytes.len())
    }

    /// Perform raw ECDH with a peer SEC1-encoded public key, writing the
    /// raw shared secret (x-coordinate, 32 bytes for P-256) into `output`.
    #[cfg(feature = "std")]
    pub fn diffie_hellman(
        &self,
        peer_public_key: &[u8],
        output: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        let _lock = PsaCryptoLock::acquire();
        key_agreement::raw_key_agreement(RawKeyAgreement::Ecdh, self.0, peer_public_key, output)
            .map_err(|_| ProtocolError::CryptoError)
    }

    #[cfg(not(feature = "std"))]
    pub fn diffie_hellman(
        &self,
        peer_public_key: &[u8],
        output: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        let peer = p256::PublicKey::from_sec1_bytes(peer_public_key)
            .map_err(|_| ProtocolError::CryptoError)?;
        let shared = self.0.diffie_hellman(&peer);
        let bytes = shared.raw_secret_bytes();
        output
            .get_mut(..bytes.len())
            .ok_or(ProtocolError::CryptoError)?
            .copy_from_slice(bytes.as_slice());
        Ok(bytes.len())
    }
}

#[cfg(feature = "std")]
impl Drop for EphemeralKey {
    fn drop(&mut self) {
        // Safety: volatile key, not concurrently used or shared.
        let _lock = PsaCryptoLock::acquire();
        unsafe { key_management::destroy(self.0) }.ok();
    }
}
