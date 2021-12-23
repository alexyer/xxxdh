//! Crate custom errors.

use cryptimitives::errors::{AeadError, KdfError, KeyPairError, SignatureError};
use thiserror::Error;

/// X3DH protocol errors.
#[derive(Debug, Error)]
pub enum XxxDhError {
    /// There are no prekeys available. Can't establish exchange.
    #[error("there are no one-time prekeys available")]
    EmptyPrekeyList,

    /// Unknown prekey received.
    #[error("unknown prekey")]
    UnknownPrekey,

    /// Error occurred in the underlying KDF function.
    #[error("{0:?}")]
    KdfError(KdfError),

    /// Error occurred in the underlying keypair.
    #[error("{0:?}")]
    KeypairError(KeyPairError),

    /// Error occurred in the underlying AEAD cipher.
    #[error("{0:?}")]
    AeadError(AeadError),

    /// Error occured in the underlying signature.
    #[error("{0:?}")]
    SignatureError(SignatureError),

    /// Storge related errors.
    #[error(transparent)]
    StorageError(#[from] StorageError),
}

/// Storage related errors
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum StorageError {
    /// Something went wrong.
    #[error("unknown error")]
    UnknownError,
}

impl From<KdfError> for XxxDhError {
    fn from(e: KdfError) -> Self {
        Self::KdfError(e)
    }
}

impl From<AeadError> for XxxDhError {
    fn from(e: AeadError) -> Self {
        Self::AeadError(e)
    }
}

impl From<SignatureError> for XxxDhError {
    fn from(e: SignatureError) -> Self {
        Self::SignatureError(e)
    }
}

/// `Result` specialized to this crate for convenience. Used for protocol related results.
pub type XxxDhResult<T> = Result<T, XxxDhError>;

/// `Result` specialized to this crate for convenience. Used for storage related results.
pub type StorageResult<T> = Result<T, StorageError>;
