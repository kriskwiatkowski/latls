#![macro_use]
#![allow(unused_macros)]

macro_rules! assert {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt"))]
            ::core::assert!($($x)*);
            #[cfg(feature = "defmt")]
            ::defmt::assert!($($x)*);
        }
    };
}

macro_rules! assert_eq {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt"))]
            ::core::assert_eq!($($x)*);
            #[cfg(feature = "defmt")]
            ::defmt::assert_eq!($($x)*);
        }
    };
}

macro_rules! assert_ne {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt"))]
            ::core::assert_ne!($($x)*);
            #[cfg(feature = "defmt")]
            ::defmt::assert_ne!($($x)*);
        }
    };
}

macro_rules! debug_assert {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt"))]
            ::core::debug_assert!($($x)*);
            #[cfg(feature = "defmt")]
            ::defmt::debug_assert!($($x)*);
        }
    };
}

macro_rules! debug_assert_eq {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt"))]
            ::core::debug_assert_eq!($($x)*);
            #[cfg(feature = "defmt")]
            ::defmt::debug_assert_eq!($($x)*);
        }
    };
}

macro_rules! debug_assert_ne {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt"))]
            ::core::debug_assert_ne!($($x)*);
            #[cfg(feature = "defmt")]
            ::defmt::debug_assert_ne!($($x)*);
        }
    };
}

macro_rules! todo {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt"))]
            ::core::todo!($($x)*);
            #[cfg(feature = "defmt")]
            ::defmt::todo!($($x)*);
        }
    };
}

macro_rules! unreachable {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt"))]
            ::core::unreachable!($($x)*);
            #[cfg(feature = "defmt")]
            ::defmt::unreachable!($($x)*);
        }
    };
}

macro_rules! panic {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt"))]
            ::core::panic!($($x)*);
            #[cfg(feature = "defmt")]
            ::defmt::panic!($($x)*);
        }
    };
}

macro_rules! trace {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::trace!($s $(, $x)*);
            #[cfg(feature = "defmt")]
            ::defmt::trace!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt")))]
            let _ = ($( & $x ),*);
        }
    };
}

macro_rules! debug {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::debug!($s $(, $x)*);
            #[cfg(feature = "defmt")]
            ::defmt::debug!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt")))]
            let _ = ($( & $x ),*);
        }
    };
}

macro_rules! info {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::info!($s $(, $x)*);
            #[cfg(feature = "defmt")]
            ::defmt::info!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt")))]
            let _ = ($( & $x ),*);
        }
    };
}

macro_rules! warn {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::warn!($s $(, $x)*);
            #[cfg(feature = "defmt")]
            ::defmt::warn!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt")))]
            let _ = ($( & $x ),*);
        }
    };
}

macro_rules! error {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::error!($s $(, $x)*);
            #[cfg(feature = "defmt")]
            ::defmt::error!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt")))]
            let _ = ($( & $x ),*);
        }
    };
}

/// Wraps a value that implements `core::fmt::Display` but not `defmt::Format`
/// (e.g. error types from third-party crates), so it can be passed to a log
/// macro that may expand to both `log` and `defmt` calls.
#[cfg(feature = "defmt")]
macro_rules! fmt_err {
    ($e:expr) => {
        ::defmt::Display2Format(&$e)
    };
}

#[cfg(not(feature = "defmt"))]
macro_rules! fmt_err {
    ($e:expr) => {
        &$e
    };
}

#[cfg(feature = "defmt")]
macro_rules! unwrap {
    ($($x:tt)*) => {
        ::defmt::unwrap!($($x)*)
    };
}

#[cfg(not(feature = "defmt"))]
macro_rules! unwrap {
    ($arg:expr) => {
        match $crate::fmt::Try::into_result($arg) {
            ::core::result::Result::Ok(t) => t,
            ::core::result::Result::Err(e) => {
                ::core::panic!("unwrap of `{}` failed: {:?}", ::core::stringify!($arg), e);
            }
        }
    };
    ($arg:expr, $($msg:expr),+ $(,)? ) => {
        match $crate::fmt::Try::into_result($arg) {
            ::core::result::Result::Ok(t) => t,
            ::core::result::Result::Err(e) => {
                ::core::panic!("unwrap of `{}` failed: {}: {:?}", ::core::stringify!($arg), ::core::format_args!($($msg,)*), e);
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NoneError;

pub trait Try {
    type Ok;
    type Error;
    fn into_result(self) -> Result<Self::Ok, Self::Error>;
}

impl<T> Try for Option<T> {
    type Ok = T;
    type Error = NoneError;

    #[inline]
    fn into_result(self) -> Result<T, NoneError> {
        self.ok_or(NoneError)
    }
}

impl<T, E> Try for Result<T, E> {
    type Ok = T;
    type Error = E;

    #[inline]
    fn into_result(self) -> Self {
        self
    }
}

/// `defmt` requires exactly one `#[defmt::global_logger]` to be linked into
/// the binary. There's no embedded target here, so this is a no-op logger
/// that just satisfies the linker when running `cargo test` with the
/// `defmt` feature enabled.
#[cfg(all(test, feature = "defmt"))]
#[defmt::global_logger]
struct NoopLogger;

#[cfg(all(test, feature = "defmt"))]
unsafe impl defmt::Logger for NoopLogger {
    fn acquire() {}
    unsafe fn flush() {}
    unsafe fn release() {}
    unsafe fn write(_bytes: &[u8]) {}
}

#[cfg(all(test, feature = "defmt"))]
defmt::timestamp!("{=u32}", 0);

#[cfg(all(test, feature = "defmt"))]
#[defmt::panic_handler]
fn defmt_panic() -> ! {
    panic!("defmt panic")
}
