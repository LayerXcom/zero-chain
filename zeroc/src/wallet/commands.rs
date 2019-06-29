use std::path::PathBuf;
use crate::term::Term;
use crate::derive::ChildIndex;
use super::{WalletDirectory, KeystoreDirectory, DirOperations};
use super::keyfile::{KeyFile, IndexFile};
use super::error::Result;
use super::config::*;
use bip39::{Mnemonic, Language, MnemonicType};
use rand::Rng;

/// Create a new wallet
pub fn new_wallet<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    rng: &mut R,
) -> Result<()> {
    // 1. configure wallet directory
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // 2. configure user-defined passoword
    term.info("Set a wallet password. This is for local usage only, allows you to protect your cached private key and prevent from creating non desired transactions.\n")?;
    let password = term.new_password("wallet password", "confirm wallet password", "password mismatch")?;

    // 3. generate the mnemonics
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = mnemonic.into_phrase();
    term.info("Please, note carefully the following mnemonic words. They will be needed to recover your wallet.\n")?;
    term.error(&format!("{}\n", phrase))?;

    // 4. create master keyfile
    let mut keyfile_master = KeyFile::create_master(MASTER_ACCOUNTNAME, VERSION, &password[..], ITERS, rng)?;

    // 5. store master keyfile
    wallet_dir.insert_master(&mut keyfile_master)?;

    // 6. create index keyfile
    let child_index = ChildIndex::from_index(0);
    let mut keyfile = get_new_keyfile(term, rng, &password[..], &wallet_dir, child_index)?;

    // 7. store a genesis keyfile
    keystore_dir.insert(&mut keyfile, rng)?;

    // 8. store new indexfile
    new_indexfile(&wallet_dir)?;

    term.success(&format!(
        "wallet and a new account successfully created.\n
        {}: {}\n",
        keyfile.account_name,
        keyfile.ss58_address
    ))?;

    Ok(())
}

pub fn show_list(
    term: &mut Term,
    root_dir: PathBuf,
) -> Result<()> {
    let (_, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    let keyfiles = keystore_dir.load_all()?;

    for keyfile in keyfiles.clone() {
        let (name, address) = (keyfile.account_name, keyfile.ss58_address);
        term.success(&format!("{}: {}\n", name, address))?;
    }

    if keyfiles.len() == 0 {
        term.warn("Not found accounts\n")?;
    }

    Ok(())
}

pub fn new_keyfile<R: Rng>(
    term: &mut Term,
    rng: &mut R,
    root_dir: PathBuf,
    child_index: ChildIndex,
) -> Result<()> {
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // enter password
    term.info("Enter the wallet password.\n")?;
    let password = term.passowrd("wallet password")?;

    // save a new keyfile
    let mut keyfile = get_new_keyfile(term, rng, &password[..], &wallet_dir, child_index)?;
    keystore_dir.insert(&mut keyfile, rng)?;

    term.success(&format!(
        "a new account successfully created.\n
        {}: {}\n",
        keyfile.account_name,
        keyfile.ss58_address
    ))?;

    Ok(())
}

fn get_new_keyfile<R: Rng>(
    term: &mut Term,
    rng: &mut R,
    password: &[u8],
    wallet_dir: &WalletDirectory,
    child_index: ChildIndex,
) -> Result<KeyFile> {
    // enter new account name
    term.info("Enter a new account name.\n")?;
    let account_name = term.account_name("new account name")?;

    let master_keyfile = wallet_dir.load_master()?;
    let xsk_child = master_keyfile.get_child_xsk(&password[..], child_index)?;

    // create new keyfile
    let keyfile = KeyFile::new(account_name.as_str(), VERSION, password, ITERS, &xsk_child, rng)?;

    Ok(keyfile)
}

/// Create a new index file in wallet directory.
fn new_indexfile(wallet_dir: &WalletDirectory) -> Result<()> {
    let mut indexfile: IndexFile = Default::default();
    wallet_dir.insert_indexfile(&mut indexfile)?;

    Ok(())
}

// /// Increment max index in indexfile and set default the new one.
// fn increment_indexfile(wallet_dir: &WalletDirectory) -> Result<()> {
//     let mut indexfile =
// }

fn wallet_keystore_dirs(root_dir: &PathBuf) -> Result<(WalletDirectory, KeystoreDirectory)> {
    // configure wallet directory
    let wallet_dir = WalletDirectory::create(&root_dir)?;

    // configure ketstore directory
    let keystore_dir_path = wallet_dir.get_default_keystore_dir();
    let keystore_dir = KeystoreDirectory::create(keystore_dir_path)?;

    Ok((wallet_dir, keystore_dir))
}
