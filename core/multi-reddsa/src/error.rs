use pairing::io;

#[derive(Debug)]
pub enum MultiRedDSAError {
    IoError(io::Error),
    ShareError([u8; 32]),
}

impl From<io::Error> for MultiRedDSAError {
    fn from(e: io::Error) -> Self {
        MultiRedDSAError::IoError(e)
    }
}
