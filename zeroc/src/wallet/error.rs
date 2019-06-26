use std::{error::Error, fmt, io, path::PathBuf};
use parity_crypto as crypto;
use serde_json;
use std::convert;

/// Defined keystore errors
#[derive(Debug)]
pub enum KeystoreError {
    InvalidPassword,
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
            KeystoreError::OverRetries => write!(f, "Exceeded maximum retries when deduplicating filename."),
            KeystoreError::IoError(_) => write!(f, "I/O error occurred"),
            KeystoreError::CryptoError(_) => write!(f, "crypto error occured"),
            KeystoreError::SerdeError(_) => write!(f, "Serialization or deserialization error occured"),
            KeystoreError::InfallibleError(_) => write!(f, "Need to be infallible"),
        }
    }
}

impl Error for KeystoreError {
    // fn source(&self) -> Option<&Error> {
    //     match self {
    //         Error::IoError(ref err) => Some(err),
    //     }
    //     unimplemented!();
    // }
}

/// Alias for keystore operation result
pub type Result<T> = std::result::Result<T, KeystoreError>;
