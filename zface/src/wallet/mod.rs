use rand::Rng;

pub mod commands;
mod config;
mod keyfile;
mod error;
mod disk;
pub use self::keyfile::{SerdeBytes, KeyFile};
pub use self::error::{Result, KeystoreError};
pub use self::disk::{KeystoreDirectory, WalletDirectory};

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
