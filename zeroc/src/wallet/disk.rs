//! Implementation of file disk operations to store keyfiles.

use super::Directory;
use super::keyfile::KeyFile;
use super::error::{Result, WalletError};
use std::path::{PathBuf, Path};
use std::fs;
use std::io::Write;
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

        keyfile.file_name = Some(filename);

        let mut file = create_new_file(&keyfile_path)?;
        serde_json::to_writer(&mut file, keyfile)?;

        file.flush()?;
        file.sync_all()?;

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
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self> {
        fs::create_dir_all(path.as_ref())?;
        Ok(Self::from_path(path))
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        KeystoreDirectory {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[cfg(unix)]
pub fn create_new_file(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode((
            libc::S_IWUSR | // 00200 Owner read permission
            libc::S_IRUSR ) // 00400 Owner write permission
        as u32)
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
    let mut filename = Utc::now().format("%Y-%m-%dT%H-%M-%S").to_string();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use rand::{XorShiftRng, SeedableRng};
    use crate::derive::{ExtendedSpendingKey, Derivation};

    #[test]
    fn create_new_keyfile() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut dir = env::temp_dir();
        dir.push("create_new_keyfile");

        let seed: [u8; 32] = rng.gen();
        let xsk_master = ExtendedSpendingKey::master(&seed);
        let iters = 1024;
        let password = b"abcd";
        let version = 1;

        let directory = KeystoreDirectory::create(dir.clone()).unwrap();
        let mut keyfile = KeyFile::new("Test".to_string(), version, password, iters, &xsk_master, rng).unwrap();

        let res = directory.insert(&mut keyfile, rng);

        assert!(res.is_ok(), "Should save keyfile succesfuly.");
        assert!(keyfile.file_name.is_some(), "Filename has been assigned.");

        let _ = fs::remove_dir_all(dir);
    }
}
