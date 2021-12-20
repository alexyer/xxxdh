//! Crate custom errors.

use thiserror::Error;

/// Errors which may occur while processing keypairs.
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
#[derive(Debug, Error)]
pub enum KeypairError {
    #[error("being given bytes with a length different to what was expected")]
    BytesLengthError,

    #[error("underlying error: {0}")]
    UnderlyingError(String),
}

/// Errors which may occur while processing signatures.
#[derive(Debug, Error, PartialEq)]
pub enum SignatureError {
    /// A signature verification equation failed.
    #[error("signature verification equation failed")]
    EquationFalse,
}

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
    #[error(transparent)]
    KdfError(#[from] KdfError),

    /// Error occurred in the underlying keypair.
    #[error(transparent)]
    KeypairError(#[from] KeypairError),

    /// Error occurred in the underlying AEAD cipher.
    #[error(transparent)]
    AeadError(#[from] AeadError),

    /// Error occured in the underlying signature.
    #[error(transparent)]
    SignatureError(#[from] SignatureError),

    /// Storge related errors.
    #[error(transparent)]
    StorageError(#[from] StorageError),
}

/// Error which may occur while deriving keys.
#[derive(Debug, Error)]
pub enum KdfError {
    #[error("invalid length")]
    InvalidLength,
}

/// AEAD algorithm error.
#[derive(Debug, Error)]
#[error("AEAD error")]
pub struct AeadError;

/// Storage related errors
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum StorageError {
    /// Something went wrong.
    #[error("unknown error")]
    UnknownError,
}

/// `Result` specialized to this crate for convenience. Used for keypair related results.
pub type KeyResult<T> = Result<T, KeypairError>;

/// `Result` specialized to this crate for convenience. Used for signture related results.
pub type SignatureResult<T> = Result<T, SignatureError>;

/// `Result` specialized to this crate for convenience. Used for protocol related results.
pub type XxxDhResult<T> = Result<T, XxxDhError>;

/// `Result` specialized to this crate for convenience. Used for kdf related results.
pub type KdfResult<T> = Result<T, KdfError>;

/// `Result` specialized to this crate for convenience. Used for AEAD related results.
pub type AeadResult<T> = Result<T, AeadError>;

/// `Result` specialized to this crate for convenience. Used for storage related results.
pub type StorageResult<T> = Result<T, StorageError>;
