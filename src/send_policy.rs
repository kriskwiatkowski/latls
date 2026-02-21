/// Controls whether `flush()` calls also flush the underlying transport.
///
/// `Strict` (the default) ensures bytes reach the network immediately after every record.
/// `Relaxed` leaves transport flushing to the caller, which can reduce syscall overhead.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushPolicy {
    /// Only encrypt and hand bytes to the transport; do not call `transport.flush()`.
    Relaxed,

    /// Call `transport.flush()` after writing each TLS record.
    #[default]
    Strict,
}

impl FlushPolicy {
    #[must_use]
    pub fn flush_transport(&self) -> bool {
        matches!(self, Self::Strict)
    }
}
