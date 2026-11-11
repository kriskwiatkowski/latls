use portable_atomic::{AtomicBool, Ordering};

static PSA_CRYPTO_LOCK: AtomicBool = AtomicBool::new(false);

pub(crate) struct PsaCryptoLock;

impl PsaCryptoLock {
    pub(crate) fn acquire() -> Self {
        while PSA_CRYPTO_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for PsaCryptoLock {
    fn drop(&mut self) {
        PSA_CRYPTO_LOCK.store(false, Ordering::Release);
    }
}
