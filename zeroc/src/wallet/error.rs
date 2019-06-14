use std::{error, fmt, io, path::PathBuf};

/// Defined wallet errors
#[derive(Debug)]
pub enum Error {
    IoError(io::Error),

}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(_) => write!(f, "I/O error occurred")
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match self {
            Error::IoError(ref err) => Some(err),
        }
    }
}

/// Alias for wallet operation result
pub type Result<T> = std::result::Result<T, Error>;
