//! Implementation of disk operations to store keyfiles.

use super::Directory;
use super::keyfile::KeyFile;
use super::error::{Result, WalletError};
use std::path::{PathBuf, Path};
use std::fs;
use libc;
use rand::Rng;
use chrono::Utc;
use serde_json;

/// Directory's path of keystore which is included bunch of keyfiles.
pub struct KeystoreDirectory{
    path: PathBuf,
}

impl Directory for KeystoreDirectory{
    fn insert<R: Rng>(&self, keyfile: &mut KeyFile, rng: &mut R) -> Result<()> {
        let filename = get_unique_filename(&self.path, rng)?;
        let keyfile_path = self.path.join(filename.as_str());

        keyfile.keyfile_name = Some(filename);

        let mut file = create_new_file(&keyfile_path)?;
        serde_json::to_writer(file, keyfile)?;

        Ok(())
    }

    fn load_all(&self) -> Result<Vec<KeyFile>> {
        unimplemented!();
    }

    fn remove(&self, keyfile: &mut KeyFile) -> Result<()> {
        unimplemented!();
    }
}

impl KeystoreDirectory {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        KeystoreDirectory {
            path: path.as_ref().to_path_buf(),
        }
    }
}

// fn get_keyfile_name(keyfile: &KeyFile) -> String {
//     keyfile.name
// }

#[cfg(unix)]
pub fn create_new_file(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode((libc::S_IWUSR | libc::S_IRUSR) as u32)
        .open(path)?;

    Ok(file)
}

#[cfg(not(unix))]
pub fn create_new_file(path: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    Ok(file)
}

/// Get a unique filename by appending random suffix.
pub fn get_unique_filename<R: Rng>(
    directory_path: &Path,
    rng: &mut R
) -> Result<String>
{
    let mut filename = Utc::now().format("Y-%m-%dT%H-%M-%S").to_string();
    let mut path = directory_path.join(filename.as_str());

    if path.exists() {
        const MAX_RETRIES: usize = 500;
        let mut retries = 0;

        while path.exists() {
            if retries >= MAX_RETRIES {
                return Err(WalletError::OverRetries);
            }

            let suffix: String = rng.gen_ascii_chars().take(4).collect();
            filename = format!("UTC--{}--{}", filename, suffix);
            path.set_file_name(&filename);
            retries += 1;
        }
    }

    Ok(filename)
}
