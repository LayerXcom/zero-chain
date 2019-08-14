// use ;
use parity_crypto as crypto;
use serde_json;
use std::{error::Error, fmt, io, convert};

/// Defined keystore errors
#[derive(Debug)]
pub enum KeystoreError {
    InvalidPassword,
    InvalidKeyfile,
    InvalidPath,
    OverRetries,
    IoError(io::Error),
    NostdIoError(zpairing::io::Error),
    CryptoError(crypto::Error),
    SerdeError(serde_json::Error),
    InfallibleError(convert::Infallible),
    SynthesisError(bellman::SynthesisError),
    RpcError(ws::Error),
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

impl From<bellman::SynthesisError> for KeystoreError {
    fn from(e: bellman::SynthesisError) -> Self {
        KeystoreError::SynthesisError(e)
    }
}

impl From<ws::Error> for KeystoreError {
    fn from(e: ws::Error) -> Self {
        KeystoreError::RpcError(e)
    }
}

impl From<zpairing::io::Error> for KeystoreError {
    fn from(e: zpairing::io::Error) -> Self {
        KeystoreError::NostdIoError(e)
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
            KeystoreError::SynthesisError(ref err) => write!(f, "synthesis error: {}", err),
            KeystoreError::RpcError(ref err) => write!(f, "rpc api error: {}", err),
            KeystoreError::NostdIoError(ref err) => write!(f, "No std I/O error: {}", err),
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
            KeystoreError::SynthesisError(ref err) => err.description(),
            KeystoreError::RpcError(ref err) => err.description(),
            KeystoreError::NostdIoError(ref err) => err.description(),
        }
    }
}

/// Alias for keystore operation result
pub type Result<T> = std::result::Result<T, KeystoreError>;
