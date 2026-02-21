use crate::handshake::binder::PskBinder;
use crate::handshake::finished::Finished;
use crate::{ProtocolError, config::TlsCipherSuite};
use digest::OutputSizeUser;
use digest::generic_array::ArrayLength;
use hmac::{Mac, SimpleHmac};
use sha2::Digest;
use sha2::digest::generic_array::{GenericArray, typenum::Unsigned};

pub type HashOutputSize<CipherSuite> =
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize;
pub type LabelBufferSize<CipherSuite> = <CipherSuite as TlsCipherSuite>::LabelBufferSize;

pub type IvArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::IvLen>;
pub type KeyArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::KeyLen>;
/// Hash-sized byte array, used as the HKDF secret at each key schedule stage.
pub type HashArray<CipherSuite> = GenericArray<u8, HashOutputSize<CipherSuite>>;

type Hkdf<CipherSuite> = hkdf::Hkdf<
    <CipherSuite as TlsCipherSuite>::Hash,
    SimpleHmac<<CipherSuite as TlsCipherSuite>::Hash>,
>;

enum Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    Uninitialized,
    Initialized(Hkdf<CipherSuite>),
}

impl<CipherSuite> Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn replace(&mut self, secret: Hkdf<CipherSuite>) {
        *self = Self::Initialized(secret);
    }

    fn as_ref(&self) -> Result<&Hkdf<CipherSuite>, ProtocolError> {
        match self {
            Secret::Initialized(secret) => Ok(secret),
            Secret::Uninitialized => Err(ProtocolError::InternalError),
        }
    }

    // HKDF-Expand-Label as defined in RFC 8446 §7.1
    fn make_expanded_hkdf_label<N: ArrayLength<u8>>(
        &self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<GenericArray<u8, N>, ProtocolError> {
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

        let mut okm = GenericArray::default();
        self.as_ref()?
            .expand(&hkdf_label, &mut okm)
            .map_err(|_| ProtocolError::CryptoError)?;
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
    fn initialize(&mut self, ikm: &[u8]) {
        let (secret, hkdf) = Hkdf::<CipherSuite>::extract(Some(self.secret.as_ref()), ikm);
        self.hkdf.replace(hkdf);
        self.secret = secret;
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
        let traffic_secret =
            Hkdf::<CipherSuite>::from_prk(&secret).map_err(|_| ProtocolError::InternalError)?;

        self.traffic_secret.replace(traffic_secret);
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

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| ProtocolError::CryptoError)?;
        Mac::update(
            &mut hmac,
            &self.server_state.transcript_hash.clone().finalize(),
        );
        let verify = hmac.finalize().into_bytes();

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
        );

        let binder_key = self
            .shared
            .derive_secret(b"ext binder", ContextType::empty_hash())?;
        self.client_state.binder_key.replace(
            Hkdf::<CipherSuite>::from_prk(&binder_key).map_err(|_| ProtocolError::InternalError)?,
        );
        self.shared.derived()
    }

    pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) -> Result<(), ProtocolError> {
        self.shared.initialize(ikm);

        self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic")?;
        self.shared.derived()
    }

    pub fn initialize_master_secret(&mut self) -> Result<(), ProtocolError> {
        // IKM is all-zeros at the master secret stage (RFC 8446 §7.1)
        self.shared.initialize(Self::zero().as_slice());

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

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| ProtocolError::CryptoError)?;
        Mac::update(&mut hmac, &transcript_hash.clone().finalize());
        let verify = hmac.finalize().into_bytes();
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
        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| ProtocolError::InternalError)?;
        Mac::update(
            &mut hmac,
            finished.hash.as_ref().ok_or_else(|| {
                warn!("No hash in Finished");
                ProtocolError::InternalError
            })?,
        );
        Ok(hmac.verify(&finished.verify).is_ok())
    }
}
