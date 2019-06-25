use std::{error::Error, fmt, io, path::PathBuf};
use parity_crypto as crypto;

/// Defined wallet errors
#[derive(Debug)]
pub enum WalletError {
    InvalidPassword,
    OverRetries,
    IoError(io::Error),
    CryptoError(crypto::Error),
}

impl From<io::Error> for WalletError {
    fn from(e: io::Error) -> Self {
        WalletError::IoError(e)
    }
}

impl From<crypto::Error> for WalletError {
    fn from(e: crypto::Error) -> Self {
        WalletError::CryptoError(e)
    }
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WalletError::InvalidPassword => write!(f, "Invalid password"),
            WalletError::OverRetries => write!(f, "Exceeded maximum retries when deduplicating filename."),
            WalletError::IoError(_) => write!(f, "I/O error occurred"),
            WalletError::CryptoError(_) => write!(f, "crypto error occured"),
        }
    }
}

impl Error for WalletError {
    // fn source(&self) -> Option<&Error> {
    //     match self {
    //         Error::IoError(ref err) => Some(err),
    //     }
    //     unimplemented!();
    // }
}

/// Alias for wallet operation result
pub type Result<T> = std::result::Result<T, WalletError>;
