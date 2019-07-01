use std::path::{PathBuf, Path};
use std::io::{BufReader, Read};
use std::fs::File;
use crate::term::Term;
use crate::wallet::{WalletDirectory, KeystoreDirectory, Result, DirOperations};
use crate::wallet::commands::{wallet_keystore_dirs, get_default_index, get_default_keyfile_name};

pub fn send_conf_transfer(term: &mut Term, root_dir: PathBuf) -> Result<()> {
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // enter password
    term.info("Enter the wallet passowrd.\n")?;
    let password = term.passowrd("wallet password")?;

    let default_keyfile_name = get_default_keyfile_name(&wallet_dir)?;
    let keyfile = keystore_dir.load(&default_keyfile_name)?;

    Ok(())


}

pub fn read_zk_params_with_path(path: &str) -> Vec<u8> {
    let params_path = Path::new(path);
    let file = File::open(&params_path)
        .expect(&format!("couldn't open {}", params_path.display()));

    let mut params_reader = BufReader::new(file);
    let mut params_buf = vec![];
    params_reader.read_to_end(&mut params_buf)
        .expect(&format!("couldn't read {}", params_path.display()));

    params_buf
}

