use super::WalletDirectory;
use super::keyfile::KeyFile;
use super::error::{Result, WalletError};
use std::path::{PathBuf, Path};
use rand::Rng;
use chrono::Utc;

pub struct DiskDirectory<P: AsRef<Path>>{
    path: P,
}

impl<P: AsRef<Path>> WalletDirectory for DiskDirectory<P>{
    fn insert<R: Rng>(&self, keyfile: &mut KeyFile, rng: &mut R) -> Result<()> {
        let filename = get_unique_filename(&self.path.as_ref(), rng)?;

        Ok(())
    }

    fn load_all(&self) -> Result<Vec<KeyFile>> {
        unimplemented!();
    }

    fn remove(&self, keyfile: &mut KeyFile) -> Result<()> {
        unimplemented!();
    }
}

impl<P: AsRef<Path>> DiskDirectory<P> {
    pub fn new(path: P) -> Self {
        DiskDirectory {
            path,
        }
    }

    // pub fn insert_with_filename<R: Rng>(&self, keyfile: &mut KeyFile, rng: &mut R) -> Result<()> {
    //     let filename = get_unique_filename(&self.path, rng)?;

    //     let keyfile_path = sel

    //     // let keyfile_path = self.path.join(filename.as_str()):
    //     unimplemented!();
    // }
}

// fn get_keyfile_name(keyfile: &KeyFile) -> String {
//     keyfile.name
// }

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
