/// Errors which may occur while processing keypairs.
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
#[derive(Debug)]
pub enum KeypairError {
    BytesLengthError,
    UnderlyingError(String),
}

/// Errors which may occur while processing signatures.
#[derive(Debug, PartialEq)]
pub enum SignatureError {
    /// A signature verification equation failed.
    EquationFalse,
}

/// X3DH protocol errors.
#[derive(Debug)]
pub enum XxxDhError {
    /// There are no prekeys available. Can't establish exchange.
    EmptyPrekeyList,

    /// Unknown prekey received.
    UnknownPrekey,

    /// Error occurred in the underlying KDF function.
    KdfError(String),

    /// Error occurred in the underlying keypair.
    KeypairError(String),

    /// Error occurred in the underlying AEAD cipher.
    AeadError,

    /// Error occured in the underlying signature.
    SignatureError(String),
}

/// Error which may occur while deriving keys.
pub enum KdfError {
    InvalidLength,
}

/// AEAD algorithm error.
pub struct AeadError;

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