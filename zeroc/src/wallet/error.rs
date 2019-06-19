use std::{error::Error, fmt, io, path::PathBuf};

/// Defined wallet errors
#[derive(Debug)]
pub enum WalletError {
    IoError(io::Error),

}

impl From<io::Error> for WalletError {
    fn from(e: io::Error) -> Self {
        WalletError::IoError(e)
    }
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WalletError::IoError(_) => write!(f, "I/O error occurred")
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
