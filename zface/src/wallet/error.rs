use std::{error::Error, fmt, io};
use parity_crypto as crypto;
use serde_json;
use std::convert;

/// Defined keystore errors
#[derive(Debug)]
pub enum KeystoreError {
    InvalidPassword,
    InvalidKeyfile,
    InvalidPath,
    OverRetries,
    IoError(io::Error),
    CryptoError(crypto::Error),
    SerdeError(serde_json::Error),
    InfallibleError(convert::Infallible),
}

impl From<io::Error> for KeystoreError {
    fn from(e: io::Error) -> Self {
        KeystoreError::IoError(e)
    }
}

impl From<crypto::Error> for KeystoreError {
    fn from(e: crypto::Error) -> Self {
        KeystoreError::CryptoError(e)
    }
}

impl From<serde_json::Error> for KeystoreError {
    fn from(e: serde_json::Error) -> Self {
        KeystoreError::SerdeError(e)
    }
}

impl From<convert::Infallible> for KeystoreError {
    fn from(e: convert::Infallible) -> Self {
        KeystoreError::InfallibleError(e)
    }
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeystoreError::InvalidPassword => write!(f, "Invalid password"),
            KeystoreError::InvalidKeyfile => write!(f, "Invalid keyfile"),
            KeystoreError::OverRetries => write!(f, "Exceeded maximum retries when deduplicating filename."),
            KeystoreError::InvalidPath => write!(f, "Invalid path"),
            KeystoreError::IoError(ref err) => write!(f, "I/O error: {}", err),
            KeystoreError::CryptoError(ref err) => write!(f, "crypto error: {}", err),
            KeystoreError::SerdeError(ref err) => write!(f, "serde error: {}", err),
            KeystoreError::InfallibleError(ref err) => write!(f, "infallible: {}", err),
        }
    }
}

impl Error for KeystoreError {
    fn description(&self) -> &str {
        match *self {
            KeystoreError::InvalidPassword => "Invalid password",
            KeystoreError::InvalidKeyfile => "Invalid keyfile",
            KeystoreError::OverRetries => "Exceeded maximum retries when deduplicating filename.",
            KeystoreError::InvalidPath => "Invalid path",
            KeystoreError::IoError(ref err) => err.description(),
            KeystoreError::CryptoError(ref err) => err.description(),
            KeystoreError::SerdeError(ref err) => err.description(),
            KeystoreError::InfallibleError(ref err) => err.description(),
        }
    }
}

/// Alias for keystore operation result
pub type Result<T> = std::result::Result<T, KeystoreError>;
