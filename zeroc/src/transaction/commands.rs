use std::path::PathBuf;
use crate::term::Term;
use crate::wallet::{WalletDirectory, KeystoreDirectory, Result};
use crate::wallet::commands::{wallet_keystore_dirs, get_default_index};

// pub fn send_conf_transfer(term: &mut Term, root_dir: PathBuf) -> Result<()> {
//     let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

//     // enter password
//     term.info("Enter the wallet passowrd.\n")?;
//     let password = term.passowrd("wallet password")?;

//     let default_index = get_default_index(&wallet_dir)?;

// }
