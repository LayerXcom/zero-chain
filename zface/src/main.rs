#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
#[macro_use]
extern crate matches;

use std::path::PathBuf;
use clap::{Arg, App, SubCommand, AppSettings, ArgMatches};
use rand::{OsRng, Rng};
use proofs::{
    EncryptionKey, SpendingKey, DecryptionKey,
    elgamal, MultiEncKeys, anonymous_setup,
    confidential_setup, PARAMS, KeyContext, ProofBuilder,
    Confidential,
    };
use primitives::{hexdisplay::{HexDisplay, AsBytesRef}, crypto::Ss58Codec};
use pairing::bls12_381::Bls12;
use polkadot_rs::{Api, Url};
use bip39::{Mnemonic, Language, MnemonicType};

mod utils;
mod config;
mod wallet;
mod transaction;
pub mod derive;
pub mod term;
pub mod ss58;
pub mod error;
use self::ss58::EncryptionKeyBytes;
use self::utils::*;
use self::config::*;
use self::wallet::commands::*;
use self::transaction::*;

fn main() {
    let default_root_dir = get_default_root_dir();

    let matches = App::new("zface")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version(crate_version!())
        .author(crate_authors!())
        .about("zface: Zerochain Command Line Interface")
        .arg(global_verbose_definition())
        .arg(global_quiet_difinition())
        .arg(global_color_definition())
        .arg(global_rootdir_definition(&default_root_dir))
        .subcommand(snark_commands_definition())
        .subcommand(wallet_commands_definition())
        .subcommand(tx_commands_definition())
        .subcommand(debug_commands_definition())
        .get_matches();

    let mut term = term::Term::new(config_terminal(&matches));
    let root_dir = global_rootdir_match(&default_root_dir, &matches);
    let rng = &mut OsRng::new().expect("should be able to construct RNG");

    match matches.subcommand() {
        (SNARK_COMMAND, Some(matches)) => subcommand_snark(term, matches, rng),
        (WALLET_COMMAND, Some(matches)) => subcommand_wallet(term, root_dir, matches, rng),
        (TX_COMMAND, Some(matches)) => subcommand_tx(term, root_dir, matches, rng),
        (DEBUG_COMMAND, Some(matches)) => subcommand_debug(term, matches, rng),
        _ => {
            term.error(matches.usage()).unwrap();
            ::std::process::exit(1);
        }
    }
}

//
//  Snark Sub Commands
//

const SNARK_COMMAND: &'static str = "snark";

fn snark_arg_confidential_setup_match<'a, R: Rng>(matches: &ArgMatches<'a>, rng: &mut R) {
    println!("Performing setup for confidential transfer...");
    let pk_path = matches.value_of("proving-key-path").unwrap();
    let vk_path = matches.value_of("verification-key-path").unwrap();

    confidential_setup(rng)
        .write_to_file(pk_path, vk_path)
        .unwrap();

    println!("Success! Output >> 'conf_pk.dat' and 'conf_vk.dat'");
}

fn snark_arg_anonymous_setup_match<'a, R: Rng>(matches: &ArgMatches<'a>, rng: &mut R) {
    println!("Performing setup for anonymous transfer...");
    let pk_path = matches.value_of("proving-key-path").unwrap();
    let vk_path = matches.value_of("verification-key-path").unwrap();

    anonymous_setup(rng)
        .write_to_file(pk_path, vk_path)
        .unwrap();

    println!("Success! Output >> 'anony_pk.dat' and 'anony_vk.dat'");
}

fn subcommand_snark<R: Rng>(mut term: term::Term, matches: &ArgMatches, rng: &mut R) {
    match matches.subcommand() {
        ("setup", Some(matches)) => {
            snark_arg_confidential_setup_match(matches, rng);
            snark_arg_anonymous_setup_match(matches, rng);
        },
        ("confidential-setup", Some(matches)) => {
            snark_arg_confidential_setup_match(matches, rng);
        },
        ("anonymous-setup", Some(matches)) => {
            snark_arg_anonymous_setup_match(matches, rng);
        }
        _ => {
            term.error(matches.usage()).unwrap();
            ::std::process::exit(1)
        }
    };
}

fn snark_commands_definition<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name(SNARK_COMMAND)
        .about("zk-snarks operations")
        .subcommand(SubCommand::with_name("setup")
            .about("Performs a trusted setup for a given constraint system")
            .arg(Arg::with_name("proving-key-path")
                .short("p")
                .long("proving-key-path")
                .help("Path of the generated proving key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(CONF_PK_PATH)
            )
            .arg(Arg::with_name("verification-key-path")
                .short("v")
                .long("verification-key-path")
                .help("Path of the generated verification key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(CONF_VK_PATH)
            )
             .arg(Arg::with_name("proving-key-path")
                .short("p")
                .long("proving-key-path")
                .help("Path of the generated proving key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(ANONY_PK_PATH)
            )
            .arg(Arg::with_name("verification-key-path")
                .short("v")
                .long("verification-key-path")
                .help("Path of the generated verification key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(ANONY_VK_PATH)
            )
        )
        .subcommand(SubCommand::with_name("confidential-setup")
            .about("Performs a trusted setup for a given constraint system")
            .arg(Arg::with_name("proving-key-path")
                .short("p")
                .long("proving-key-path")
                .help("Path of the generated proving key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(CONF_PK_PATH)
            )
            .arg(Arg::with_name("verification-key-path")
                .short("v")
                .long("verification-key-path")
                .help("Path of the generated verification key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(CONF_VK_PATH)
            )
        )
        .subcommand(SubCommand::with_name("anonymous-setup")
            .about("Performs a trusted setup for a given constraint system")
            .arg(Arg::with_name("proving-key-path")
                .short("p")
                .long("proving-key-path")
                .help("Path of the generated proving key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(ANONY_PK_PATH)
            )
            .arg(Arg::with_name("verification-key-path")
                .short("v")
                .long("verification-key-path")
                .help("Path of the generated verification key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(ANONY_VK_PATH)
            )
        )
}

//
// Wallet Sub Commands
//

const WALLET_COMMAND: &'static str = "wallet";

fn wallet_arg_id_match<'a>(matches: &ArgMatches<'a>) -> u32 {
    let id_str = matches.value_of("asset-id")
        .expect("Asset id paramter is required; qed");

    let id: u32 = id_str.parse()
        .expect("should be parsed to u32 number; qed");

    id
}

fn subcommand_wallet<R: Rng>(mut term: term::Term, root_dir: PathBuf, matches: &ArgMatches, rng: &mut R) {
    match matches.subcommand() {
        ("init", Some(_)) => {
            // Create new wallet
            new_wallet(&mut term, root_dir, rng)
                .expect("Invalid operations of creating new wallet.");
        },
        ("list", Some(_)) => {
            // show accounts list
            show_list(&mut term, root_dir)
                .expect("Invalid operations of listing accounts.");
        },
        ("add-account", Some(_)) => {
            new_keyfile(&mut term, root_dir, rng)
                .expect("Invalid operations of creating new account.");
        },
        ("change-account", Some(sub_matches)) => {
            let account_name = sub_matches.value_of("account-name")
                .expect("Account name is required; qed");

            change_default_account(root_dir, account_name)
                .expect("Change default account failed.");
        },
        ("recovery", Some(_)) => {
            recover(&mut term, root_dir, rng)
                .expect("Invalid mnemonic to recover keystore.");
        },
        ("balance", Some(sub_matches)) => {
            println!("Getting encrypted balance from zerochain");
            let api = Api::init(tx_arg_url_match(&sub_matches));

            let dec_key = load_dec_key(&mut term, root_dir)
                .expect("loading decrption key failed.");

            let balance_query = getter::BalanceQuery::get_encrypted_balance(&dec_key, api)
                .expect("Falid to get balance data.");

            println!("Decrypted balance: {}", balance_query.decrypted_balance);
            println!("Encrypted balance: {}", balance_query.encrypted_balance_str);
            println!("Encrypted pending transfer: {}", balance_query.pending_transfer_str);
        },
        ("asset-balance", Some(sub_matches)) => {
            println!("Getting encrypted asset from zerochain");
            let api = Api::init(tx_arg_url_match(&sub_matches));
            let dec_key = load_dec_key(&mut term, root_dir)
                .expect("loading decrption key failed.");
            let asset_id = wallet_arg_id_match(&sub_matches);

            let balance_query = getter::BalanceQuery::get_encrypted_asset(asset_id, &dec_key, api)
                .expect("Falid to get balance data.");;

            println!("Decrypted balance: {}", balance_query.decrypted_balance);
            println!("Encrypted balance: {}", balance_query.encrypted_balance_str);
            println!("Encrypted pending transfer: {}", balance_query.pending_transfer_str);
        },
        ("wallet-test", Some(_)) => {
            println!("Initialize key components...");
            println!("Accounts of alice and bob are fixed");

            let alice_seed = seed_to_array(ALICESEED);
            let bob_seed = seed_to_array(BOBSEED);

            let print_keys_alice = PrintKeys::generate_from_seed(alice_seed);
            let print_keys_bob = PrintKeys::generate_from_seed(bob_seed);
            let print_keys_charlie = PrintKeys::generate();

            println!(
                "
                \nSeed
                Alice: 0x{}
                Bob: 0x{}
                Charlie: 0x{}
                \nDecryption Key
                Alice: 0x{}
                Bob: 0x{}
                Charlie: 0x{}
                \nEncryption Key
                Alice: 0x{}
                Bob: 0x{}
                Charlie: 0x{}
                ",
                hex::encode(&alice_seed[..]),
                hex::encode(&print_keys_bob.seed[..]),
                hex::encode(&print_keys_charlie.seed[..]),
                hex::encode(&print_keys_alice.decryption_key[..]),
                hex::encode(&print_keys_bob.decryption_key[..]),
                hex::encode(&print_keys_charlie.decryption_key[..]),
                hex::encode(&print_keys_alice.encryption_key[..]),
                hex::encode(&print_keys_bob.encryption_key[..]),
                hex::encode(&print_keys_charlie.encryption_key[..]),
            );
        },
        _ => {
            term.error(matches.usage()).unwrap();
            ::std::process::exit(1)
        }
    };
}

fn wallet_commands_definition<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name(WALLET_COMMAND)
        .about("wallet operations")
        .subcommand(SubCommand::with_name("wallet-test")
            .about("Initialize key components")
        )
        .subcommand(SubCommand::with_name("init")
            .about("Initialize your wallet")
        )
        .subcommand(SubCommand::with_name("list")
            .about("Show accounts list.")
        )
        .subcommand(SubCommand::with_name("add-account")
            .about("Add a new account")
        )
        .subcommand(SubCommand::with_name("change-account")
            .about("Change default account")
            .arg(Arg::with_name("account-name")
                .short("n")
                .long("name")
                .help("A new account name that you have in your keystore.")
                .takes_value(true)
                .required(true)
            )
        )
        .subcommand(SubCommand::with_name("recovery")
            .about("Recover keystore from mnemonic.")
        )
        .subcommand(SubCommand::with_name("balance")
            .about("Get current balance stored in encrypted balances module")
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
        )
        .subcommand(SubCommand::with_name("asset-balance")
            .about("Get current asset stored in encrypted asset module")
            .arg(Arg::with_name("asset-id")
                .short("i")
                .long("id")
                .help("Asset id")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
        )
}

//
// Transaction Sub Commands
//

const TX_COMMAND: &'static str = "tx";

fn tx_arg_recipient_address_match<'a>(matches: &ArgMatches<'a>) -> [u8; 32] {
    let recipient_address = matches.value_of("recipient-address")
        .expect("Recipient's address is required; qed");

    let recipient_enc_key = EncryptionKeyBytes::from_ss58check(recipient_address)
        .expect("The string should be a properly encoded SS58Check address.");

    recipient_enc_key.0
}

fn tx_arg_amount_match<'a>(matches: &ArgMatches<'a>) -> u32 {
    let amount_str = matches.value_of("amount")
        .expect("Amount parameter is required; qed");

    let amount: u32 = amount_str.parse()
        .expect("should be parsed to u32 number; qed");

    amount
}

fn tx_arg_url_match<'a>(matches: &ArgMatches<'a>) -> Url {
    match matches.value_of("url") {
        Some(u) => Url::Custom(u.to_string()),
        None => Url::Local,
    }
}

fn subcommand_tx<R: Rng>(mut term: term::Term, root_dir: PathBuf, matches: &ArgMatches, rng: &mut R) {
    let res = match matches.subcommand() {
        ("send", Some(sub_matches)) => {
            let recipient_enc_key = tx_arg_recipient_address_match(&sub_matches);
            let amount = tx_arg_amount_match(&sub_matches);
            let url = tx_arg_url_match(&sub_matches);

            confidential_transfer_tx(&mut term, root_dir, &recipient_enc_key[..], amount, url, rng)
        },
        ("asset-issue", Some(sub_matches)) => {
            let amount = tx_arg_amount_match(&sub_matches);
            let url = tx_arg_url_match(&sub_matches);

            asset_issue_tx(&mut term, root_dir, amount, url, rng)
        },
        ("asset-send", Some(sub_matches)) => {
            let recipient_enc_key = tx_arg_recipient_address_match(&sub_matches);
            let amount = tx_arg_amount_match(&sub_matches);
            let url = tx_arg_url_match(&sub_matches);
            let asset_id = wallet_arg_id_match(&sub_matches);

            asset_transfer_tx(&mut term, root_dir, &recipient_enc_key[..], amount, asset_id, url, rng)
        },
        ("asset-burn", Some(sub_matches)) => {
            let url = tx_arg_url_match(&sub_matches);
            let asset_id = wallet_arg_id_match(&sub_matches);
            asset_burn_tx(&mut term, root_dir, asset_id, url, rng)
        },
        ("anonymous-send",  Some(sub_matches)) => {
            let recipient_enc_key = tx_arg_recipient_address_match(&sub_matches);
            let amount = tx_arg_amount_match(&sub_matches);
            let url = tx_arg_url_match(&sub_matches);

            anonymous_transfer_tx(&mut term, root_dir, &recipient_enc_key[..], amount, url, rng)
        },
        _ => {
            term.error(matches.usage()).unwrap();
            ::std::process::exit(1)
        }
    };

    res.unwrap_or_else(|e| term.fail_with(e))
}

fn tx_commands_definition<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name(TX_COMMAND)
        .about("transaction operations")
        .subcommand(SubCommand::with_name("confidential-send")
            .about("Submit a transaction to zerochain nodes in order to call confidential_transfer function in encrypted-balances module.")
            .arg(Arg::with_name("amount")
                .short("a")
                .long("amount")
                .help("The coin amount for the confidential transfer.")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("recipient-address")
                .short("to")
                .long("recipient-address")
                .help("Recipient's SS58-encoded address")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
        )
        .subcommand(SubCommand::with_name("asset-issue")
            .about("Submit a transaction to zerochain nodes in order to call issue function in encrypted-assets module.")
            .arg(Arg::with_name("amount")
                .short("a")
                .long("amount")
                .help("The issued coin amount")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
        )
        .subcommand(SubCommand::with_name("asset-send")
            .about("Submit a transaction to zerochain nodes in order to call confidential_transfer function in encrypted-assets module.")
            .arg(Arg::with_name("amount")
                .short("a")
                .long("amount")
                .help("The coin amount for the confidential transfer.")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("recipient-address")
                .short("to")
                .long("recipient-address")
                .help("Recipient's SS58-encoded address")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("asset-id")
                .short("i")
                .long("id")
                .help("Asset id")
                .takes_value(true)
                .required(false)
            )
        )
        .subcommand(SubCommand::with_name("asset-burn")
            .about("Submit a transaction to zerochain in order to call destroy function in encrypted-assets module.")
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("asset-id")
                .short("i")
                .long("id")
                .help("Asset id")
                .takes_value(true)
                .required(false)
            )
        )
        .subcommand(SubCommand::with_name("anonymous-send")
            .about("Submit a transaction to zerochain nodes in order to call anonymous_transfer function in encrypted-balances module.")
            .arg(Arg::with_name("amount")
                .short("a")
                .long("amount")
                .help("The coin amount for the anonymous transfer.")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("recipient-address")
                .short("to")
                .long("recipient-address")
                .help("Recipient's SS58-encoded address")
                .takes_value(true)
                .required(false)
            )
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
        )
}

//
// Debug Sub Commands
//

const DEBUG_COMMAND: &'static str = "debug";

fn debug_arg_seed_match<'a>(matches: &ArgMatches<'a>) -> Vec<u8> {
    hex::decode(matches.value_of("sender-seed")
        .expect("Seed parameter is required; qed"))
        .expect("should be decoded to hex.")
}

fn subcommand_debug<R: Rng>(mut term: term::Term, matches: &ArgMatches, rng: &mut R) {
    match matches.subcommand() {
        ("key-init", Some(_)) => {
            let lang = Language::English;
            // create a new randomly generated mnemonic phrase
            let mnemonic = Mnemonic::new(MnemonicType::Words12, lang);
            PrintKeys::print_from_phrase(mnemonic.phrase(), None, lang);
        },
        ("send", Some(sub_matches)) => {
            let seed = debug_arg_seed_match(&sub_matches);
            let recipient_enc_key = tx_arg_recipient_address_match(&sub_matches);
            let amount = tx_arg_amount_match(&sub_matches);
            let url = tx_arg_url_match(&sub_matches);

            transfer_tx_for_debug(&seed[..], &recipient_enc_key[..], amount, url, rng).unwrap();
        },
        ("anonymous-send", Some(sub_matches)) => {
            let seed = debug_arg_seed_match(&sub_matches);
            let recipient_enc_key = tx_arg_recipient_address_match(&sub_matches);
            let amount = tx_arg_amount_match(&sub_matches);
            let url = tx_arg_url_match(&sub_matches);

            anonymous_transfer_tx_for_debug(&seed[..], &recipient_enc_key[..], amount, url, rng).unwrap();
        },
        ("print-tx", Some(sub_matches)) => {
            println!("Generate transaction...");

            let sender_seed = hex::decode(sub_matches.value_of("sender-privatekey").unwrap()).unwrap();
            let recipient_seed  = hex::decode(sub_matches.value_of("recipient-privatekey").unwrap()).unwrap();

            let sender_address = getter::address(&sender_seed[..]).unwrap();
            let recipient_address = getter::address(&recipient_seed[..]).unwrap();

            println!("Private Key(Sender): 0x{}\nAddress(Sender): 0x{}\n",
                HexDisplay::from(&sender_seed),
                HexDisplay::from(&sender_address),
            );

            println!("Private Key(Recipient): 0x{}\nAddress(Recipient): 0x{}\n",
                HexDisplay::from(&recipient_seed),
                HexDisplay::from(&recipient_address),
            );

            let pk_path = sub_matches.value_of("proving-key-path").unwrap();
            let vk_path = sub_matches.value_of("verification-key-path").unwrap();

            let amount_str = sub_matches.value_of("amount").unwrap();
            let amount: u32 = amount_str.parse().unwrap();
            let fee = 1 as u32;

            let balance_str = sub_matches.value_of("balance").unwrap();
            let balance: u32 = balance_str.parse().unwrap();

            println!("Transaction >>");

            let address_recipient = EncryptionKey::<Bls12>::from_seed(&recipient_seed[..], &PARAMS).unwrap();

            let ciphertext_balance_a = sub_matches.value_of("encrypted-balance").unwrap();
            let ciphertext_balance_v = hex::decode(ciphertext_balance_a).unwrap();
            let ciphertext_balance = vec![elgamal::Ciphertext::read(&mut &ciphertext_balance_v[..], &*PARAMS).unwrap()];

            let remaining_balance = balance - amount - fee;

            use scrypto::jubjub::edwards;
            let g_epoch_vec = hex::decode("0953f47325251a2f479c25527df6d977925bebafde84423b20ae6c903411665a").unwrap();
            let g_epoch = edwards::Point::read(&g_epoch_vec[..], &*PARAMS).unwrap().as_prime_order(&*PARAMS).unwrap();

            let tx = KeyContext::read_from_path(pk_path, vk_path)
                .unwrap()
                .gen_proof(
                    amount,
                    fee,
                    remaining_balance,
                    &SpendingKey::<Bls12>::from_seed(&sender_seed[..]),
                    MultiEncKeys::<Bls12, Confidential>::new(address_recipient.clone()),
                    &ciphertext_balance,
                    g_epoch,
                    rng,
                    &*PARAMS
                ).expect("fails to generate the tx");

            println!(
                "
                \nzkProof(Alice): 0x{}
                \naddress_sender(Alice): 0x{}
                \naddress_recipient(Alice): 0x{}
                \nvalue_sender(Alice): 0x{}
                \nvalue_recipient(Alice): 0x{}
                \nrvk(Alice): 0x{}
                \nrsk(Alice): 0x{}
                \nEncrypted fee by sender: 0x{}
                \nright_randomness: 0x{}
                \nNonce:  0x{}
                ",
                HexDisplay::from(&&tx.proof[..] as &dyn AsBytesRef),
                HexDisplay::from(&tx.enc_key_sender as &dyn AsBytesRef),
                HexDisplay::from(&tx.enc_key_recipient as &dyn AsBytesRef),
                HexDisplay::from(&tx.left_amount_sender as &dyn AsBytesRef),
                HexDisplay::from(&tx.left_amount_recipient as &dyn AsBytesRef),
                HexDisplay::from(&tx.rvk as &dyn AsBytesRef),
                HexDisplay::from(&tx.rsk as &dyn AsBytesRef),
                HexDisplay::from(&tx.left_fee as &dyn AsBytesRef),
                HexDisplay::from(&tx.right_randomness as &dyn AsBytesRef),
                HexDisplay::from(&tx.nonce as &dyn AsBytesRef)
            );
        },
        ("balance", Some(sub_matches)) => {
            println!("Getting encrypted balance from zerochain");

            let api = Api::init(tx_arg_url_match(&sub_matches));
            let decr_key_vec = hex::decode(sub_matches.value_of("decryption-key")
                .expect("Decryption key parameter is required; qed"))
                .expect("should be decoded to hex.");

            let dec_key = DecryptionKey::read(&mut &decr_key_vec[..])
                .expect("Reading decryption key faild.");

            let balance_query = getter::BalanceQuery::get_encrypted_balance(&dec_key, api)
                .expect("Falid to get balance data.");

            println!("Decrypted balance: {}", balance_query.decrypted_balance);
            println!("Encrypted balance: {}", balance_query.encrypted_balance_str);
            println!("Encrypted pending transfer: {}", balance_query.pending_transfer_str);
        },
        _ => {
            term.error(matches.usage()).unwrap();
            ::std::process::exit(1)
        }
    };
}

fn debug_commands_definition<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name(DEBUG_COMMAND)
        .about("debug operations")
        .subcommand(SubCommand::with_name("key-init")
            .about("Print a keypair")
        )
        .subcommand(SubCommand::with_name("send")
            .about("(Debug) Submit extrinsic to the substrate nodes")
            .arg(Arg::with_name("amount")
                .short("a")
                .long("amount")
                .help("The coin amount for the confidential transfer. (default: 10)")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_AMOUNT)
            )
            .arg(Arg::with_name("sender-seed")
                .short("s")
                .long("sender-seed")
                .help("Sender's seed. (default: Alice)")
                .takes_value(true)
                .required(false)
                .default_value(ALICESEED)
            )
            .arg(Arg::with_name("recipient-address")
                .short("t")
                .long("recipient-address")
                .help("Recipient's encryption key. (default: Bob)")
                .takes_value(true)
                .required(false)
                .default_value(BOBACCOUNTID)
            )
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
        )
        .subcommand(SubCommand::with_name("anonymous-send")
            .about("(Debug) Submit extrinsic to the substrate nodes")
            .arg(Arg::with_name("amount")
                .short("a")
                .long("amount")
                .help("The coin amount for the confidential transfer. (default: 10)")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_AMOUNT)
            )
            .arg(Arg::with_name("sender-seed")
                .short("s")
                .long("sender-seed")
                .help("Sender's seed. (default: Alice)")
                .takes_value(true)
                .required(false)
                .default_value(ALICESEED)
            )
            .arg(Arg::with_name("recipient-address")
                .short("t")
                .long("recipient-address")
                .help("Recipient's encryption key. (default: Bob)")
                .takes_value(true)
                .required(false)
                .default_value(BOBACCOUNTID)
            )
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
        )
        .subcommand(SubCommand::with_name("print-tx")
            .about("Show transaction components for sending it from a browser")
            .arg(Arg::with_name("proving-key-path")
                .short("p")
                .long("proving-key-path")
                .help("Path of the proving key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(CONF_PK_PATH)
            )
            .arg(Arg::with_name("verification-key-path")
                .short("v")
                .long("verification-key-path")
                .help("Path of the generated verification key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(CONF_VK_PATH)
            )
            .arg(Arg::with_name("amount")
                .short("a")
                .long("amount")
                .help("The coin amount for the confidential transfer. (default: 10)")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_AMOUNT)
            )
            .arg(Arg::with_name("balance")
                .short("b")
                .long("balance")
                .help("The coin balance for the confidential transfer.")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_BALANCE)
            )
            .arg(Arg::with_name("sender-privatekey")
                .short("s")
                .long("sender-privatekey")
                .help("Sender's private key. (default: Alice)")
                .takes_value(true)
                .required(false)
                .default_value(ALICESEED)
            )
            .arg(Arg::with_name("recipient-privatekey")
                .short("r")
                .long("recipient-privatekey")
                .help("Recipient's private key. (default: Bob)")
                .takes_value(true)
                .required(false)
                .default_value(BOBSEED)
            )
            .arg(Arg::with_name("encrypted-balance")
                .short("e")
                .long("encrypted-balance")
                .help("Encrypted balance by sender stored in on-chain")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_ENCRYPTED_BALANCE)
            )
        )
        .subcommand(SubCommand::with_name("balance")
            .about("Get current balance stored in ConfTransfer module")
            .arg(Arg::with_name("decryption-key")
                .short("d")
                .long("decryption-key")
                .help("Your decription key")
                .takes_value(true)
                .required(true)
                .default_value(ALICEDECRYPTIONKEY)
            )
            .arg(Arg::with_name("url")
                .short("u")
                .long("url")
                .help("Endpoint to connect zerochain nodes")
                .takes_value(true)
                .required(false)
            )
        )
}
