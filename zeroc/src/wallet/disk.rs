//! Implementation of file disk operations to store keyfiles.

use super::DirOperations;
use super::keyfile::KeyFile;
use super::error::{Result, KeystoreError};
use crate::ss58;
use std::path::{PathBuf, Path};
use std::fs;
use std::io::{Write, BufReader};
use std::collections::HashMap;
use rand::Rng;
use chrono::Utc;
use serde_json;

/// Directory's path of keystore which is included bunch of keyfiles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeystoreDirectory{
    path: PathBuf,
}

impl DirOperations for KeystoreDirectory{
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
        Ok(self.get_all_keyfiles()?
            .into_iter()
            .map(|(_, keyfile)| keyfile)
            .collect()
        )
    }

    fn remove(&self, keyfile: &mut KeyFile) -> Result<()> {
        let removed_file = self.get_all_keyfiles()?
            .into_iter()
            .find(|(_, file)| file.ss58_address == keyfile.ss58_address);

        match removed_file {
            None => Err(KeystoreError::InvalidKeyfile),
            Some((path, _)) => fs::remove_file(path).map_err(From::from)
        }
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

    fn get_all_keyfiles(&self) -> Result<HashMap<PathBuf, KeyFile>> {
        Ok(fs::read_dir(&self.path)?
            .flat_map(|entry| {
                let path = entry?.path();
                fs::File::open(path.clone())
                    .map(|file| {
                        let reader = BufReader::new(file);
                        let keyfile = serde_json::from_reader(reader)
                            .expect("Should deserialize from json file.");

                        (path, keyfile)
                    })
            })
            .collect()
        )
    }
}

#[cfg(unix)]
pub fn create_new_file(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o660) // Owner's read & write permission
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
                return Err(KeystoreError::OverRetries);
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
    fn test_manage_keyfile() {
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

        // create
        let res_create = directory.insert(&mut keyfile, rng);

        assert!(res_create.is_ok(), "Should save keyfile successfully.");
        assert!(keyfile.file_name.is_some(), "Filename has been assigned.");

        // load
        let keyfile_loaded = &mut directory.load_all().unwrap()[0];

        assert_eq!(*keyfile_loaded, keyfile);

        // remove
        let res_remove = directory.remove(keyfile_loaded);

        assert!(res_remove.is_ok(), "Should remove keyfile successfully");
        dir.push(keyfile.file_name.unwrap());
        assert!(!dir.exists(), "Should be removed keyfile.")
    }
}
