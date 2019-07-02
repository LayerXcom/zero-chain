use std::path::PathBuf;
use crate::term::Term;
use crate::derive::ChildIndex;
use crate::utils::mnemonics::*;
use super::{WalletDirectory, KeystoreDirectory, DirOperations};
use super::keyfile::{KeyFile, IndexFile};
use super::error::{Result, KeystoreError};
use super::config::*;
use bip39::{Mnemonic, Language, MnemonicType, Seed};
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
    let phrase = mnemonic.phrase();
    term.info("Please, note carefully the following mnemonic words. They will be needed to recover your wallet.\n")?;
    term.error(&format!("{}\n", phrase))?;

    // 4. create master keyfile
    let master_seed = Seed::new(&mnemonic, "");
    let master_seed_bytes: &[u8] = master_seed.as_bytes();
    let mut keyfile_master = KeyFile::create_master(MASTER_ACCOUNTNAME, VERSION, &password[..], ITERS, rng, master_seed_bytes)?;

    // 5. store master keyfile
    wallet_dir.insert_master(&mut keyfile_master)?;

    // 6. create a genesis keyfile
    let child_index = ChildIndex::from_index(0);
    let mut keyfile = get_new_keyfile(term, rng, &password[..], &wallet_dir, child_index)?;

    // 7. store a genesis keyfile
    keystore_dir.insert(&mut keyfile, rng)?;

    // 8. store new indexfile
    new_indexfile(&wallet_dir)?;

    term.success(&format!(
        "wallet and a new account successfully created.\n
        {}: {}\n\n",
        keyfile.account_name,
        keyfile.ss58_address
    ))?;

    Ok(())
}

pub fn show_list(
    term: &mut Term,
    root_dir: PathBuf,
) -> Result<()> {
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    let keyfiles = keystore_dir.load_all()?;
    if keyfiles.len() == 0 {
        term.warn("Not found accounts\n")?;
        return Ok(());
    }

    let default_index = get_default_index(&wallet_dir)? as usize;

    for (i, keyfile) in keyfiles.iter().enumerate() {
        let (name, address) = (&*keyfile.account_name, &*keyfile.ss58_address);
        if i == default_index {
            term.success(&format!("* {}: {}\n", name, address))?;
        } else {
            term.success(&format!("{}: {}\n", name, address))?;
        }
    }

    Ok(())
}

pub fn new_keyfile<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    rng: &mut R,
) -> Result<()> {
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // enter password
    term.info("Enter the wallet password.\n")?;
    let password = term.passowrd("wallet password")?;

    // save a new keyfile
    let incremented_index = get_max_index(&wallet_dir)? + 1;
    let child_index = ChildIndex::from_index(incremented_index);
    let mut keyfile = get_new_keyfile(term, rng, &password[..], &wallet_dir, child_index)?;
    keystore_dir.insert(&mut keyfile, rng)?;

    let filename = keyfile.file_name.ok_or(KeystoreError::InvalidKeyfile)?;

    // set index to new account
    increment_indexfile(&wallet_dir, filename.as_str())?;

    term.success(&format!(
        "a new account successfully created.\n
        {}: {}\n\n",
        keyfile.account_name,
        keyfile.ss58_address
    ))?;

    Ok(())
}

pub fn recover(
    term: &mut Term,
    root_dir: PathBuf
) -> Result<()> {
    // 1. configure wallet directory
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // 2. Re-set a new passoword
    term.info("Re-set a new wallet password. This is for local usage only, allows you to protect your cached private key and prevent from creating non desired transactions.\n")?;
    let password = term.new_password("wallet password", "confirm wallet password", "password mismatch")?;

    let mnemonic_type = MnemonicType::Words12;
    let lang = Language::English;

    let phrase_str = input_mnemonic_phrase(mnemonic_type, lang);

    term.info("Please, note carefully the following mnemonic words. They will be needed to recover your wallet.\n")?;


    Ok(())
}

// pub fn change_default_index(
//     term: &mut Term,
//     root_dir: PathBuf
// ) -> Result<()> {

// }

fn get_new_keyfile<R: Rng>(
    term: &mut Term,
    rng: &mut R,
    password: &[u8],
    wallet_dir: &WalletDirectory,
    child_index: ChildIndex,
) -> Result<KeyFile> {
    let master_keyfile = wallet_dir.load_master()?;
    let xsk_child = master_keyfile.get_child_xsk(&password[..], child_index)?;

    // enter new account name
    term.info("Enter a new account name.\n")?;
    let account_name = term.account_name("new account name")?;

    // create new keyfile
    let keyfile = KeyFile::new(
        account_name.as_str(),
        VERSION,
        password,
        ITERS,
        &xsk_child,
        rng
    )?;

    Ok(keyfile)
}

/// Create a new index file in wallet directory.
fn new_indexfile(wallet_dir: &WalletDirectory) -> Result<()> {
    let mut indexfile: IndexFile = Default::default();
    wallet_dir.insert_indexfile(&mut indexfile)
}

/// Increment max index in indexfile and set default the new one.
fn increment_indexfile(wallet_dir: &WalletDirectory, filename: &str) -> Result<()> {
    let indexfile = wallet_dir.load_indexfile()?;
    let mut incremented_indexfile = indexfile.next_index(filename);
    wallet_dir.update_indexfile(&mut incremented_indexfile)
}

pub fn get_max_index(wallet_dir: &WalletDirectory) -> Result<u32> {
    let indexfile = wallet_dir.load_indexfile()?;
    Ok(indexfile.max_index)
}

pub fn get_default_index(wallet_dir: &WalletDirectory) -> Result<u32> {
    let indexfile = wallet_dir.load_indexfile()?;
    Ok(indexfile.default_index)
}

pub fn get_default_keyfile_name(wallet_dir: &WalletDirectory) -> Result<String> {
    let indexfile = wallet_dir.load_indexfile()?;
    Ok(indexfile.default_keyfile_name)
}

pub fn wallet_keystore_dirs(root_dir: &PathBuf) -> Result<(WalletDirectory, KeystoreDirectory)> {
    // configure wallet directory
    let wallet_dir = WalletDirectory::create(&root_dir)?;

    // configure ketstore directory
    let keystore_dir_path = wallet_dir.get_default_keystore_dir();
    let keystore_dir = KeystoreDirectory::create(keystore_dir_path)?;

    Ok((wallet_dir, keystore_dir))
}
