use std::io::Error as IoError;

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[cfg(feature = "rust-hpke")]
    #[error("a problem occurred with the AEAD")]
    Aead(#[from] aead::Error),
    #[cfg(feature = "stream")]
    #[error("a stream chunk was larger than the maximum allowed size")]
    ChunkTooLarge,
    #[cfg(feature = "nss")]
    #[error("a problem occurred during cryptographic processing: {0}")]
    Crypto(#[from] crate::nss::Error),
    #[cfg(feature = "stream")]
    #[error("a stream contained a zero-length chunk that was not the last chunk")]
    EmptyChunk,
    #[cfg(feature = "stream")]
    #[error("a stream contained data after the last chunk")]
    ExtraData,
    #[error("an error was found in the format")]
    Format,
    #[cfg(feature = "rust-hpke")]
    #[error("a problem occurred with HPKE: {0}")]
    Hpke(#[from] ::hpke::HpkeError),
    #[error("an internal error occurred")]
    Internal,
    #[error("the wrong type of key was provided for the selected KEM")]
    InvalidKeyType,
    #[error("the wrong KEM was specified")]
    InvalidKem,
    #[error("io error: {0}")]
    Io(#[from] IoError),
    #[error("the key ID was invalid")]
    KeyId,
    #[cfg(feature = "stream")]
    #[error("the object was not ready")]
    NotReady,
    #[error("the configuration contained too many symmetric suites")]
    TooManySymmetricSuites,
    #[error("a field was truncated")]
    Truncated,
    #[error("the configuration was not supported")]
    Unsupported,
    #[cfg(feature = "stream")]
    #[error("writes are not supported after closing")]
    WriteAfterClose,
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_v: std::num::TryFromIntError) -> Self {
        Self::TooManySymmetricSuites
    }
}

// If this happens, it's a programming error in this crate.
impl From<std::array::TryFromSliceError> for Error {
    fn from(_v: std::array::TryFromSliceError) -> Self {
        Self::Internal
    }
}

impl Error {
    /// Produce a copy of this error.
    /// This is exact, except for `Io`, which loses any inner error value
    /// (see `duplicate_io`).
    #[cfg(feature = "stream")]
    pub(crate) fn duplicate(&self) -> Self {
        match self {
            #[cfg(feature = "rust-hpke")]
            Self::Aead(e) => Self::Aead(*e),
            Self::ChunkTooLarge => Self::ChunkTooLarge,
            #[cfg(feature = "nss")]
            Self::Crypto(e) => Self::Crypto(e.clone()),
            Self::EmptyChunk => Self::EmptyChunk,
            Self::ExtraData => Self::ExtraData,
            Self::Format => Self::Format,
            #[cfg(feature = "rust-hpke")]
            Self::Hpke(e) => Self::Hpke(*e),
            Self::Internal => Self::Internal,
            Self::InvalidKeyType => Self::InvalidKeyType,
            Self::InvalidKem => Self::InvalidKem,
            Self::Io(e) => Self::Io(duplicate_io(e)),
            Self::KeyId => Self::KeyId,
            Self::NotReady => Self::NotReady,
            Self::TooManySymmetricSuites => Self::TooManySymmetricSuites,
            Self::Truncated => Self::Truncated,
            Self::Unsupported => Self::Unsupported,
            Self::WriteAfterClose => Self::WriteAfterClose,
        }
    }
}

/// Produce a copy of an I/O error, which does not implement `Clone`.
/// The kind and any OS error code are kept.
/// An inner `Error` is duplicated; any other inner error is replaced
/// with its string form.
#[cfg(feature = "stream")]
pub(crate) fn duplicate_io(e: &IoError) -> IoError {
    if let Some(code) = e.raw_os_error() {
        return IoError::from_raw_os_error(code);
    }
    match e.get_ref() {
        Some(inner) => {
            if let Some(inner) = inner.downcast_ref::<Error>() {
                IoError::new(e.kind(), inner.duplicate())
            } else {
                IoError::new(e.kind(), inner.to_string())
            }
        }
        None => IoError::from(e.kind()),
    }
}

pub type Res<T> = Result<T, Error>;
