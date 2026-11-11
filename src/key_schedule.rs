use crate::handshake::binder::PskBinder;
use crate::handshake::finished::Finished;
use crate::{ProtocolError, config::TlsCipherSuite};
use digest::OutputSizeUser;
use digest::generic_array::ArrayLength;
#[cfg(not(feature = "std"))]
use hmac::{Mac, SimpleHmac};
#[cfg(feature = "std")]
use crate::psa::PsaCryptoLock;
#[cfg(feature = "std")]
use psa_crypto::operations::{key_management, mac as psa_mac};
#[cfg(feature = "std")]
use psa_crypto::types::algorithm::{Algorithm, FullLengthMac, Mac as PsaMac};
#[cfg(feature = "std")]
use psa_crypto::types::key::{Attributes, Lifetime, Policy, Type, UsageFlags};
use sha2::Digest;
use sha2::digest::generic_array::{GenericArray, typenum::Unsigned};

pub type HashOutputSize<CipherSuite> =
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize;
pub type LabelBufferSize<CipherSuite> = <CipherSuite as TlsCipherSuite>::LabelBufferSize;

pub type IvArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::IvLen>;
pub type KeyArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::KeyLen>;
/// Hash-sized byte array, used as the HKDF secret at each key schedule stage.
pub type HashArray<CipherSuite> = GenericArray<u8, HashOutputSize<CipherSuite>>;

/// Compute HMAC-Hash(key, message) → output using PSA Crypto.
///
/// This is the core primitive for both HKDF-Extract and HKDF-Expand:
/// - HKDF-Extract(salt, IKM)  = HMAC-Hash(key=salt,  message=IKM)
/// - HKDF-Expand T(1)         = HMAC-Hash(key=PRK,   message=info || 0x01)
#[cfg(feature = "std")]
fn psa_hmac<CipherSuite: TlsCipherSuite>(
    key_bytes: &[u8],
    message: &[u8],
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    let _lock = PsaCryptoLock::acquire();
    psa_crypto::init().map_err(|_| ProtocolError::CryptoError)?;

    let mac_alg = PsaMac::FullLength(FullLengthMac::Hmac {
        hash_alg: CipherSuite::PSA_HASH,
    });

    let mut usage_flags = UsageFlags::default();
    usage_flags.set_sign_hash().set_verify_hash();
    let key_id = key_management::import(
        Attributes {
            key_type: Type::Hmac,
            bits: key_bytes.len() * 8,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: Algorithm::Mac(mac_alg),
            },
        },
        None,
        key_bytes,
    )
    .map_err(|_| ProtocolError::CryptoError)?;

    let result = psa_mac::compute_mac(key_id, mac_alg, message, output);
    unsafe { key_management::destroy(key_id) }.ok();
    result.map(|_| ()).map_err(|_| ProtocolError::CryptoError)
}

#[cfg(not(feature = "std"))]
fn psa_hmac<CipherSuite: TlsCipherSuite>(
    key_bytes: &[u8],
    message: &[u8],
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    let mut mac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(key_bytes)
        .map_err(|_| ProtocolError::CryptoError)?;
    Mac::update(&mut mac, message);
    output.copy_from_slice(&Mac::finalize(mac).into_bytes());
    Ok(())
}

enum Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    Uninitialized,
    /// Stores the PRK (Pseudo-Random Key) for HKDF-Expand operations.
    Initialized(HashArray<CipherSuite>),
}

impl<CipherSuite> Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn replace(&mut self, prk: HashArray<CipherSuite>) {
        *self = Self::Initialized(prk);
    }

    fn as_ref(&self) -> Result<&HashArray<CipherSuite>, ProtocolError> {
        match self {
            Secret::Initialized(prk) => Ok(prk),
            Secret::Uninitialized => Err(ProtocolError::InternalError),
        }
    }

    // HKDF-Expand-Label as defined in RFC 8446 §7.1
    fn make_expanded_hkdf_label<N: ArrayLength<u8>>(
        &self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<GenericArray<u8, N>, ProtocolError> {
        let prk = self.as_ref()?;

        let mut hkdf_label = heapless_typenum::Vec::<u8, LabelBufferSize<CipherSuite>>::new();
        // Length field: desired output length as u16 big-endian
        hkdf_label
            .extend_from_slice(&N::to_u16().to_be_bytes())
            .map_err(|()| ProtocolError::InternalError)?;

        // TLS 1.3 labels are prefixed with "tls13 " (6 bytes)
        let label_len = 6 + label.len() as u8;
        hkdf_label
            .extend_from_slice(&label_len.to_be_bytes())
            .map_err(|()| ProtocolError::InternalError)?;
        hkdf_label
            .extend_from_slice(b"tls13 ")
            .map_err(|()| ProtocolError::InternalError)?;
        hkdf_label
            .extend_from_slice(label)
            .map_err(|()| ProtocolError::InternalError)?;

        match context_type {
            ContextType::None => {
                hkdf_label
                    .push(0)
                    .map_err(|_| ProtocolError::InternalError)?;
            }
            ContextType::Hash(context) => {
                hkdf_label
                    .extend_from_slice(&(context.len() as u8).to_be_bytes())
                    .map_err(|()| ProtocolError::InternalError)?;
                hkdf_label
                    .extend_from_slice(&context)
                    .map_err(|()| ProtocolError::InternalError)?;
            }
        }

        // HKDF-Expand T(1) = HMAC-Hash(PRK, info || 0x01)
        // T(0) is empty, so the HMAC message is: "" || info || 0x01 = info || 0x01.
        // All TLS 1.3 HKDF-Expand-Label outputs are ≤ HashLen, so only T(1) is needed.
        let mut expand_input = [0u8; 128]; // ≥ max(LabelBufferSize) + 1 for any cipher suite
        let info_len = hkdf_label.len();
        expand_input[..info_len].copy_from_slice(&hkdf_label);
        expand_input[info_len] = 1u8; // HKDF counter for T(1)

        let mut t1 = HashArray::<CipherSuite>::default();
        psa_hmac::<CipherSuite>(prk, &expand_input[..=info_len], t1.as_mut())?;

        let mut okm = GenericArray::default();
        okm.copy_from_slice(&t1[..N::to_usize()]);
        Ok(okm)
    }
}

pub struct SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    secret: HashArray<CipherSuite>,
    hkdf: Secret<CipherSuite>,
}

impl<CipherSuite> SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            secret: GenericArray::default(),
            hkdf: Secret::Uninitialized,
        }
    }

    // HKDF-Extract, chaining the previous stage's secret as the salt (RFC 8446 §7.1)
    fn initialize(&mut self, ikm: &[u8]) -> Result<(), ProtocolError> {
        // HKDF-Extract: PRK = HMAC-Hash(salt=self.secret, IKM=ikm)
        let mut prk = HashArray::<CipherSuite>::default();
        psa_hmac::<CipherSuite>(&self.secret, ikm, prk.as_mut())?;
        self.hkdf.replace(prk.clone());
        self.secret = prk;
        Ok(())
    }

    fn derive_secret(
        &mut self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<HashArray<CipherSuite>, ProtocolError> {
        self.hkdf
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(label, context_type)
    }

    // "Derive-Secret(Secret, "derived", "")" — used to chain stages per RFC 8446 §7.1
    fn derived(&mut self) -> Result<(), ProtocolError> {
        self.secret = self.derive_secret(b"derived", ContextType::empty_hash())?;
        Ok(())
    }
}

pub(crate) struct KeyScheduleState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    traffic_secret: Secret<CipherSuite>,
    counter: u64,
    key: KeyArray<CipherSuite>,
    iv: IvArray<CipherSuite>,
}

impl<CipherSuite> KeyScheduleState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            traffic_secret: Secret::Uninitialized,
            counter: 0,
            key: KeyArray::<CipherSuite>::default(),
            iv: IvArray::<CipherSuite>::default(),
        }
    }

    #[inline]
    pub fn get_key(&self) -> &KeyArray<CipherSuite> {
        &self.key
    }

    #[inline]
    pub fn get_iv(&self) -> &IvArray<CipherSuite> {
        &self.iv
    }

    pub fn get_nonce(&self) -> IvArray<CipherSuite> {
        let iv = self.get_iv();
        KeySchedule::<CipherSuite>::get_nonce(self.counter, iv)
    }

    fn calculate_traffic_secret(
        &mut self,
        label: &[u8],
        shared: &mut SharedState<CipherSuite>,
        transcript_hash: &CipherSuite::Hash,
    ) -> Result<(), ProtocolError> {
        let secret = shared.derive_secret(label, ContextType::transcript_hash(transcript_hash))?;
        // secret is the traffic secret PRK; store it directly for subsequent Expand calls
        self.traffic_secret.replace(secret);
        // Derive per-record key and IV from the traffic secret (RFC 8446 §7.3)
        self.key = self
            .traffic_secret
            .make_expanded_hkdf_label(b"key", ContextType::None)?;
        self.iv = self
            .traffic_secret
            .make_expanded_hkdf_label(b"iv", ContextType::None)?;
        self.counter = 0;
        Ok(())
    }

    pub fn increment_counter(&mut self) {
        self.counter = unwrap!(self.counter.checked_add(1));
    }
}

enum ContextType<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    None,
    Hash(HashArray<CipherSuite>),
}

impl<CipherSuite> ContextType<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn transcript_hash(hash: &CipherSuite::Hash) -> Self {
        Self::Hash(hash.clone().finalize())
    }

    fn empty_hash() -> Self {
        Self::Hash(
            <CipherSuite::Hash as Digest>::new()
                .chain_update([])
                .finalize(),
        )
    }
}

pub struct KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    shared: SharedState<CipherSuite>,
    client_state: WriteKeySchedule<CipherSuite>,
    server_state: ReadKeySchedule<CipherSuite>,
}

impl<CipherSuite> KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Self {
        Self {
            shared: SharedState::new(),
            client_state: WriteKeySchedule {
                state: KeyScheduleState::new(),
                binder_key: Secret::Uninitialized,
            },
            server_state: ReadKeySchedule {
                state: KeyScheduleState::new(),
                transcript_hash: <CipherSuite::Hash as Digest>::new(),
            },
        }
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut CipherSuite::Hash {
        &mut self.server_state.transcript_hash
    }

    pub(crate) fn replace_transcript_hash(&mut self, hash: CipherSuite::Hash) {
        self.server_state.transcript_hash = hash;
    }

    pub fn as_split(
        &mut self,
    ) -> (
        &mut WriteKeySchedule<CipherSuite>,
        &mut ReadKeySchedule<CipherSuite>,
    ) {
        (&mut self.client_state, &mut self.server_state)
    }

    pub(crate) fn write_state(&mut self) -> &mut WriteKeySchedule<CipherSuite> {
        &mut self.client_state
    }

    pub(crate) fn read_state(&mut self) -> &mut ReadKeySchedule<CipherSuite> {
        &mut self.server_state
    }

    pub fn create_client_finished(
        &self,
    ) -> Result<Finished<HashOutputSize<CipherSuite>>, ProtocolError> {
        let key = self
            .client_state
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;

        let transcript = self.server_state.transcript_hash.clone().finalize();
        let mut verify = HashArray::<CipherSuite>::default();
        psa_hmac::<CipherSuite>(&key, &transcript, verify.as_mut())?;

        Ok(Finished { verify, hash: None })
    }

    fn get_nonce(counter: u64, iv: &IvArray<CipherSuite>) -> IvArray<CipherSuite> {
        // Per-record nonce: XOR the static IV with the zero-padded sequence counter (RFC 8446 §5.3)
        let counter = Self::pad::<CipherSuite::IvLen>(&counter.to_be_bytes());

        let mut nonce = GenericArray::default();

        for (index, (l, r)) in iv[0..CipherSuite::IvLen::to_usize()]
            .iter()
            .zip(counter.iter())
            .enumerate()
        {
            nonce[index] = l ^ r;
        }

        nonce
    }

    // Right-aligns `input` bytes in a zero-padded array of length N (big-endian padding)
    fn pad<N: ArrayLength<u8>>(input: &[u8]) -> GenericArray<u8, N> {
        let mut padded = GenericArray::default();
        for (index, byte) in input.iter().rev().enumerate() {
            padded[(N::to_usize() - index) - 1] = *byte;
        }
        padded
    }

    fn zero() -> HashArray<CipherSuite> {
        GenericArray::default()
    }

    pub fn initialize_early_secret(&mut self, psk: Option<&[u8]>) -> Result<(), ProtocolError> {
        // IKM is 0-bytes when no PSK is used — still required to derive the binder key
        self.shared.initialize(
            #[allow(clippy::or_fun_call)]
            psk.unwrap_or(Self::zero().as_slice()),
        )?;

        let binder_key = self
            .shared
            .derive_secret(b"ext binder", ContextType::empty_hash())?;
        self.client_state.binder_key.replace(binder_key);
        self.shared.derived()
    }

    pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) -> Result<(), ProtocolError> {
        self.shared.initialize(ikm)?;

        self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic")?;
        self.shared.derived()
    }

    pub fn initialize_master_secret(&mut self) -> Result<(), ProtocolError> {
        // IKM is all-zeros at the master secret stage (RFC 8446 §7.1)
        self.shared.initialize(Self::zero().as_slice())?;

        self.calculate_traffic_secrets(b"c ap traffic", b"s ap traffic")?;
        self.shared.derived()
    }

    fn calculate_traffic_secrets(
        &mut self,
        client_label: &[u8],
        server_label: &[u8],
    ) -> Result<(), ProtocolError> {
        self.client_state.state.calculate_traffic_secret(
            client_label,
            &mut self.shared,
            &self.server_state.transcript_hash,
        )?;

        self.server_state.state.calculate_traffic_secret(
            server_label,
            &mut self.shared,
            &self.server_state.transcript_hash,
        )?;

        Ok(())
    }
}

impl<CipherSuite> Default for KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn default() -> Self {
        KeySchedule::new()
    }
}

pub struct WriteKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    state: KeyScheduleState<CipherSuite>,
    binder_key: Secret<CipherSuite>,
}
impl<CipherSuite> WriteKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) fn increment_counter(&mut self) {
        self.state.increment_counter();
    }

    pub(crate) fn get_key(&self) -> &KeyArray<CipherSuite> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(&self) -> IvArray<CipherSuite> {
        self.state.get_nonce()
    }

    pub fn create_psk_binder(
        &self,
        transcript_hash: &CipherSuite::Hash,
    ) -> Result<PskBinder<HashOutputSize<CipherSuite>>, ProtocolError> {
        let key = self
            .binder_key
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;

        let transcript = transcript_hash.clone().finalize();
        let mut verify = HashArray::<CipherSuite>::default();
        psa_hmac::<CipherSuite>(&key, &transcript, verify.as_mut())?;
        Ok(PskBinder { verify })
    }
}

pub struct ReadKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    state: KeyScheduleState<CipherSuite>,
    transcript_hash: CipherSuite::Hash,
}

impl<CipherSuite> ReadKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) fn increment_counter(&mut self) {
        self.state.increment_counter();
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut CipherSuite::Hash {
        &mut self.transcript_hash
    }

    pub(crate) fn get_key(&self) -> &KeyArray<CipherSuite> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(&self) -> IvArray<CipherSuite> {
        self.state.get_nonce()
    }

    pub fn verify_server_finished(
        &self,
        finished: &Finished<HashOutputSize<CipherSuite>>,
    ) -> Result<bool, ProtocolError> {
        let key = self
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;
        let hash = finished.hash.as_ref().ok_or_else(|| {
            warn!("No hash in Finished");
            ProtocolError::InternalError
        })?;
        let mut computed = HashArray::<CipherSuite>::default();
        psa_hmac::<CipherSuite>(&key, hash, computed.as_mut())?;
        Ok(computed.as_slice() == finished.verify.as_slice())
    }
}
