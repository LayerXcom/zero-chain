use rand::Rng;
use smallvec::SmallVec;

pub mod commands;
pub mod config;
mod keyfile;
mod disk;
pub use self::keyfile::KeyFile;
pub use self::disk::{KeystoreDirectory, WalletDirectory};
use crate::error::Result;

/// Operations in a keystore directory
pub trait DirOperations {
    /// Insert a new keyfile to this keystore directory.
    fn insert<R: Rng>(&self, keyfile: &mut KeyFile, rng: &mut R) -> Result<()>;

    /// Load a keyfile
    fn load(&self, keyfile_name: &str) -> Result<KeyFile>;

    /// Load all keyfiles in this keystore directory.
    fn load_all(&self) -> Result<Vec<KeyFile>>;

    /// Remove a keyfile from this keystore directory.
    fn remove(&self, keyfile: &mut KeyFile) -> Result<()>;
}

/// Serializable and deserializable bytes
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct SerdeBytes(
    #[serde(with = "serde_bytes")]
    pub Vec<u8>
);

impl From<Vec<u8>> for SerdeBytes {
    fn from(v: Vec<u8>) -> Self {
        SerdeBytes(v)
    }
}

impl From<SmallVec<[u8; 32]>> for SerdeBytes {
    fn from(v: SmallVec<[u8; 32]>) -> Self {
        SerdeBytes(v.into_vec())
    }
}

impl From<[u8; 32]> for SerdeBytes {
    fn from(v: [u8; 32]) -> Self {
        SerdeBytes(v.to_vec())
    }
}

impl From<[u8; 16]> for SerdeBytes {
    fn from(v: [u8; 16]) -> Self {
        SerdeBytes(v.to_vec())
    }
}

impl From<&[u8]> for SerdeBytes {
    fn from(v: &[u8]) -> Self {
        SerdeBytes(v.to_vec())
    }
}
