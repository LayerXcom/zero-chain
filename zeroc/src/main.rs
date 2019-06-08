use clap::{Arg, App, SubCommand, AppSettings};
use rand::OsRng;
use proofs::{
    primitives::{EncryptionKey, bytes_to_uniform_fs, ProofGenerationKey},
    elgamal,
    };
use primitives::{hexdisplay::{HexDisplay, AsBytesRef}, blake2_256};
use pairing::{bls12_381::Bls12, Field, PrimeField, PrimeFieldRepr};
use zpairing::{bls12_381::Bls12 as zBls12, PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr};
use scrypto::jubjub::{JubjubBls12, fs, FixedGenerators};
use zjubjub::{
    curve::{JubjubBls12 as zJubjubBls12, fs::Fs as zFs, FixedGenerators as zFixedGenerators},
    redjubjub::PrivateKey as zPrivateKey
    };
use std::fs::File;
use std::path::Path;
use std::string::String;
use std::io::{BufWriter, Write, BufReader, Read};
use wasm_utils::transaction::Transaction;
use bellman::groth16::{Parameters, PreparedVerifyingKey};
use polkadot_rs::{Api, Url};
use zprimitives::{Proof, Ciphertext as zCiphertext, PkdAddress, SigVerificationKey, RedjubjubSignature};
use runtime_primitives::generic::Era;
use parity_codec::{Compact, Encode};
use zero_chain_runtime::{UncheckedExtrinsic, Call, ConfTransferCall};

mod setup;
use setup::setup;
mod utils;
use utils::*;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref PARAMS: JubjubBls12 = { JubjubBls12::new() };
    pub static ref ZPARAMS: zJubjubBls12 = { zJubjubBls12::new() };
}

fn get_address(seed: &[u8]) -> Vec<u8> {
    let address = EncryptionKey::<Bls12>::from_seed(seed, &PARAMS);

    let mut address_bytes = vec![];
    address.write(&mut address_bytes).unwrap();
    address_bytes
}

fn main() {
    cli().unwrap_or_else(|e| {
        println!("{}", e);
        std::process::exit(1);
    });
}

fn cli() -> Result<(), String> {
    const VERIFICATION_KEY_PATH: &str = "cli/verification.params";
    const PROVING_KEY_PATH: &str = "cli/proving.params";
    const DEFAULT_AMOUNT: &str = "10";
    const DEFAULT_BALANCE: &str = "100";
    const DEFAULT_FEE: &str = "1";
    const ALICESEED: &str = "416c696365202020202020202020202020202020202020202020202020202020";
    const BOBSEED: &str = "426f622020202020202020202020202020202020202020202020202020202020";
    const BOBACCOUNTID: &str = "45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389";
    const ALICEDECRYPTIONKEY: &str = "b0451b0bfab2830a75216779e010e0bfd2e6d0b4e4b1270dfcdfd0d538509e02";
    const DEFAULT_ENCRYPTED_BALANCE: &str = "6f4962da776a391c3b03f3e14e8156d2545f39a3ebbed675ea28859252cb006fac776c796563fcd44cc49cfaea8bb796952c266e47779d94574c10ad01754b11";
    const URL: &str = "";

    let matches = App::new("zeroc")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version("0.1.0")
        .author("Osuke Sudo")
        .about("Privacy oriented blockchain framework")
        .subcommand(SubCommand::with_name("setup")
            .about("Performs a trusted setup for a given constraint system")
            .arg(Arg::with_name("proving-key-path")
                .short("p")
                .long("proving-key-path")
                .help("Path of the generated proving key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(PROVING_KEY_PATH)
            )
            .arg(Arg::with_name("verification-key-path")
                .short("v")
                .long("verification-key-path")
                .help("Path of the generated verification key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(VERIFICATION_KEY_PATH)
            )
        )
        .subcommand(SubCommand::with_name("init")
            .about("Initialize key components")
        )
        .subcommand(SubCommand::with_name("generate-tx")
            .about("Execute zk proving and output tx components")
            .arg(Arg::with_name("proving-key-path")
                .short("p")
                .long("proving-key-path")
                .help("Path of the proving key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(PROVING_KEY_PATH)
            )
            .arg(Arg::with_name("verification-key-path")
                .short("v")
                .long("verification-key-path")
                .help("Path of the generated verification key file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .default_value(VERIFICATION_KEY_PATH)
            )
            .arg(Arg::with_name("amount")
                .short("a")
                .long("amount")
                .help("The coin amount for the confidential transfer. (default: 10)")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_AMOUNT)
            )
            .arg(Arg::with_name("fee")
                .short("f")
                .long("fee")
                .help("The fee for the confidential transfer. (default: 1)")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_FEE)
            )
            .arg(Arg::with_name("balance")
                .short("b")
                .long("balance")
                .help("The coin balance for the confidential transfer. (default: 100)")
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
            .arg(Arg::with_name("is-submitting")
                .short("i")
                .long("is-submitting")
                .help("Whether the extrinsic is submitted or just print extrinsic")
                .takes_value(true)
                .required(false)
                .default_value("true")
            )
        )
        .subcommand(SubCommand::with_name("send-tx")
            .about("Submit extrinsic to the substrate nodes")
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
            .arg(Arg::with_name("recipient-encryption-key")
                .short("r")
                .long("recipient-encryption-key")
                .help("Recipient's encryption key. (default: Bob)")
                .takes_value(true)
                .required(false)
                .default_value(BOBACCOUNTID)
            )
            .arg(Arg::with_name("fee")
                .short("f")
                .long("fee")
                .help("The fee for the confidential transfer. (default: 1)")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_FEE)
            )
            // .arg(Arg::with_name("url")
            //     .short("u")
            //     .long("url")
            //     .help("Endpoint to connect substrate nodes")
            //     .takes_value(true)
            //     .required(false)
            //     .default_value(URL)
            // )
        )
        .subcommand(SubCommand::with_name("get-balance")
            .about("Get current balance stored in ConfTransfer module")
            .arg(Arg::with_name("decryption-key")
                .short("d")
                .long("decryption-key")
                .help("Your decription key")
                .takes_value(true)
                .required(true)
                .default_value(ALICEDECRYPTIONKEY)
            )
        )
        .subcommand(SubCommand::with_name("decrypt")
            .about("Decrypt the elgamal encryption")
            .arg(Arg::with_name("encrypted-value")
                .short("e")
                .long("encrypted-value")
                .help("Encrypted transfer amount or balance (w/o 0x prefix)")
                .takes_value(true)
                .required(true)
            )
            .arg(Arg::with_name("private-key")
                .short("p")
                .long("private-key")
                .help("The private key for decryption")
                .takes_value(true)
                .required(true)
            )
        )
        .get_matches();

    match matches.subcommand() {
        ("setup", Some(sub_matches)) => {
            println!("Performing setup...");

            let pk_path = Path::new(sub_matches.value_of("proving-key-path").unwrap());
            let vk_path = Path::new(sub_matches.value_of("verification-key-path").unwrap());

            let pk_file = File::create(&pk_path)
                .map_err(|why| format!("couldn't create {}: {}", pk_path.display(), why))?;
            let vk_file = File::create(&vk_path)
                .map_err(|why| format!("couldn't create {}: {}", vk_path.display(), why))?;

            let mut bw_pk = BufWriter::new(pk_file);
            let mut bw_vk = BufWriter::new(vk_file);

            let (proving_key, prepared_vk) = setup();
            let mut v_pk = vec![];
            let mut v_vk = vec![];

            proving_key.write(&mut &mut v_pk).unwrap();
            prepared_vk.write(&mut &mut v_vk).unwrap();

            bw_pk.write(&v_pk[..])
                .map_err(|_| "Unable to write proving key data to file.".to_string())?;

            bw_vk.write(&v_vk[..])
                .map_err(|_| "Unable to write verification key data to file.".to_string())?;

            bw_pk.flush()
                .map_err(|_| "Unable to flush proving key buffer.".to_string())?;

            bw_vk.flush()
                .map_err(|_| "Unable to flush verification key buffer.".to_string())?;

            println!("Success! Output >> 'proving.params' and 'verification.params'");
        },
        ("init", Some(_)) => {
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
        ("generate-tx", Some(sub_matches)) => {
            println!("Generate transaction...");

            let sender_seed = hex::decode(sub_matches.value_of("sender-privatekey").unwrap()).unwrap();
            let recipient_seed  = hex::decode(sub_matches.value_of("recipient-privatekey").unwrap()).unwrap();

            let sender_address = get_address(&sender_seed[..]);
            let recipient_address = get_address(&recipient_seed[..]);

            println!("Private Key(Sender): 0x{}\nAddress(Sender): 0x{}\n",
                HexDisplay::from(&sender_seed),
                HexDisplay::from(&sender_address),
            );

            println!("Private Key(Recipient): 0x{}\nAddress(Recipient): 0x{}\n",
                HexDisplay::from(&recipient_seed),
                HexDisplay::from(&recipient_address),
            );

            let pk_path = Path::new(sub_matches.value_of("proving-key-path").unwrap());
            let vk_path = Path::new(sub_matches.value_of("verification-key-path").unwrap());

            let pk_file = File::open(&pk_path)
                .map_err(|why| format!("couldn't open {}: {}", pk_path.display(), why))?;
            let vk_file = File::open(&vk_path)
                .map_err(|why| format!("couldn't open {}: {}", vk_path.display(), why))?;

            let mut reader_pk = BufReader::new(pk_file);
            let mut reader_vk = BufReader::new(vk_file);

            let mut buf_pk = vec![];
            reader_pk.read_to_end(&mut buf_pk)
                .map_err(|why| format!("couldn't read {}: {}", pk_path.display(), why))?;

            let mut buf_vk = vec![];
            reader_vk.read_to_end(&mut buf_vk)
                .map_err(|why| format!("couldn't read {}: {}", vk_path.display(), why))?;


            let amount_str = sub_matches.value_of("amount").unwrap();
            let amount: u32 = amount_str.parse().unwrap();
            let fee_str = sub_matches.value_of("fee").unwrap();
            let fee: u32 = fee_str.parse().unwrap();

            let balance_str = sub_matches.value_of("balance").unwrap();
            let balance: u32 = balance_str.parse().unwrap();

            println!("Transaction >>");

            let rng = &mut OsRng::new().expect("should be able to construct RNG");

            // let alpha = fs::Fs::rand(rng);
            let alpha = fs::Fs::zero(); // TODO

            let proving_key = Parameters::<Bls12>::read(&mut &buf_pk[..], true).unwrap();
            let prepared_vk = PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..]).unwrap();

            let origin_key = bytes_to_uniform_fs::<Bls12>(&sender_seed[..]);

            let address_recipient = EncryptionKey::<Bls12>::from_seed(&recipient_seed[..], &PARAMS);

            let ciphertext_balance_a = sub_matches.value_of("encrypted-balance").unwrap();
            let ciphertext_balance_v = hex::decode(ciphertext_balance_a).unwrap();
            let ciphertext_balance = elgamal::Ciphertext::read(&mut &ciphertext_balance_v[..], &PARAMS as &JubjubBls12).unwrap();

            let remaining_balance = balance - amount - fee;

            let tx = Transaction::gen_tx(
                            amount,
                            remaining_balance,
                            alpha,
                            &proving_key,
                            &prepared_vk,
                            &address_recipient,
                            &origin_key,
                            ciphertext_balance,
                            rng,
                            fee
                    ).expect("fails to generate the tx");

            // println!(
            //     "
            //     \nEncrypted fee by sender: 0x{}
            //     \nzkProof: 0x{}
            //     \nEncrypted amount by sender: 0x{}
            //     \nEncrypted amount by recipient: 0x{}
            //     ",
            //     HexDisplay::from(&tx.enc_fee as &AsBytesRef),
            //     HexDisplay::from(&&tx.proof[..] as &AsBytesRef),
            //     HexDisplay::from(&tx.enc_val_sender as &AsBytesRef),
            //     HexDisplay::from(&tx.enc_val_recipient as &AsBytesRef),
            // );
            println!(
                "
                \nzkProof(Alice): 0x{}
                \naddress_sender(Alice): 0x{}
                \naddress_recipient(Alice): 0x{}
                \nvalue_sender(Alice): 0x{}
                \nvalue_recipient(Alice): 0x{}
                \nbalance_sender(Alice): 0x{}
                \nrvk(Alice): 0x{}
                \nrsk(Alice): 0x{}
                \nEncrypted fee by sender: 0x{}
                ",
                HexDisplay::from(&&tx.proof[..] as &AsBytesRef),
                HexDisplay::from(&tx.address_sender as &AsBytesRef),
                HexDisplay::from(&tx.address_recipient as &AsBytesRef),
                HexDisplay::from(&tx.enc_val_sender as &AsBytesRef),
                HexDisplay::from(&tx.enc_val_recipient as &AsBytesRef),
                HexDisplay::from(&tx.enc_bal_sender as &AsBytesRef),
                HexDisplay::from(&tx.rvk as &AsBytesRef),
                HexDisplay::from(&tx.rsk as &AsBytesRef),
                HexDisplay::from(&tx.enc_fee as &AsBytesRef),
            );

            if let Some(value) = sub_matches.value_of("is-submitting") {
                match value.parse() {
                    Ok(true) => {
                    let api = Api::init(Url::Local);
                    let rng = &mut OsRng::new().expect("should be able to construct RNG");
                    let p_g = zFixedGenerators::Diversifier; // 1

                    let mut rsk_repr = zFs::default().into_repr();
                    rsk_repr.read_le(&mut &tx.rsk[..]).unwrap();
                    let rsk = zFs::from_repr(rsk_repr).unwrap();

                    let sig_sk = zPrivateKey::<zBls12>(rsk);
                    let sig_vk = SigVerificationKey::from_slice(&tx.rvk[..]);

                    let calls = Call::ConfTransfer(ConfTransferCall::confidential_transfer(
                        Proof::from_slice(&tx.proof[..]),
                        PkdAddress::from_slice(&tx.address_sender[..]),
                        PkdAddress::from_slice(&tx.address_recipient[..]),
                        zCiphertext::from_slice(&tx.enc_val_sender[..]),
                        zCiphertext::from_slice(&tx.enc_val_recipient[..]),
                        sig_vk,
                        zCiphertext::from_slice(&tx.enc_fee[..]),
                    ));

                    let era = Era::Immortal;
                    let index = api.get_nonce(&sig_vk).expect("Nonce must be got.");
                    let checkpoint = api.get_genesis_blockhash().unwrap();
                    let raw_payload = (Compact(index), calls, era, checkpoint);

                    let sig = raw_payload.using_encoded(|payload| {
                        let msg = blake2_256(payload);
                        let sig = sig_sk.sign(&msg[..], rng, p_g, &ZPARAMS as &zJubjubBls12);

                        let sig_vk = sig_vk.into_verification_key().unwrap();
                        assert!(sig_vk.verify(&msg, &sig, p_g, &ZPARAMS as &zJubjubBls12));

                        sig
                    });

                    let sig_repr = RedjubjubSignature::from_signature(&sig);
                    let uxt = UncheckedExtrinsic::new_signed(index, raw_payload.1, sig_vk.into(), sig_repr, era);
                    let _tx_hash = api.submit_extrinsic(&uxt).unwrap();
                },
                _ => {},
                }
            }

        },
        ("send-tx", Some(sub_matches)) => {
            // let url_str = sub_matches.value_of("url").unwrap();
            // let mut url = Url::Local;
            // if url_str.len() != 0 {
            //     url = Url::Custom(url_str);
            // }
            println!("Computing zk proof...");
            let api = Api::init(Url::Local);

            let rng = &mut OsRng::new().expect("should be able to construct RNG");
            // let alpha = fs::Fs::rand(rng);
            let alpha = fs::Fs::zero(); // TODO

            let pk_path = Path::new(PROVING_KEY_PATH);
            let vk_path = Path::new(VERIFICATION_KEY_PATH);

            let pk_file = File::open(&pk_path)
                .map_err(|why| format!("couldn't open {}: {}", pk_path.display(), why))?;
            let vk_file = File::open(&vk_path)
                .map_err(|why| format!("couldn't open {}: {}", vk_path.display(), why))?;

            let mut reader_pk = BufReader::new(pk_file);
            let mut reader_vk = BufReader::new(vk_file);

            let mut buf_pk = vec![];
            reader_pk.read_to_end(&mut buf_pk)
                .map_err(|why| format!("couldn't read {}: {}", pk_path.display(), why))?;

            let mut buf_vk = vec![];
            reader_vk.read_to_end(&mut buf_vk)
                .map_err(|why| format!("couldn't read {}: {}", vk_path.display(), why))?;

            let proving_key = Parameters::<Bls12>::read(&mut &buf_pk[..], true).unwrap();
            let prepared_vk = PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..]).unwrap();

            let seed = hex::decode(sub_matches.value_of("sender-seed").unwrap()).unwrap();
            let amount_str = sub_matches.value_of("amount").unwrap();
            let amount: u32 = amount_str.parse().unwrap();
            let fee_str = sub_matches.value_of("fee").unwrap();
            let fee: u32 = fee_str.parse().unwrap();

            let origin_key = bytes_to_uniform_fs::<Bls12>(&seed[..]);
            let decryption_key = ProofGenerationKey::<Bls12>::from_seed(&seed[..], &PARAMS).bdk();

            let mut decrypted_key = [0u8; 32];
            decryption_key.into_repr().write_le(&mut &mut decrypted_key[..]).unwrap();

            let recipient_encryption_key = hex::decode(sub_matches.value_of("recipient-encryption-key").unwrap()).unwrap();

            let (decrypted_balance, encrypted_balance_vec, _) = get_balance_from_decryption_key(&decrypted_key[..] ,api.clone());
            let remaining_balance = decrypted_balance - amount - fee;

            let recipient_account_id = EncryptionKey::<Bls12>::read(&mut &recipient_encryption_key[..], &PARAMS).unwrap();
            let encrypted_balance = elgamal::Ciphertext::read(&mut &encrypted_balance_vec[..], &PARAMS as &JubjubBls12).unwrap();

            println!("Computing zk proof...");
            let tx = Transaction::gen_tx(
                            amount,
                            remaining_balance,
                            alpha,
                            &proving_key,
                            &prepared_vk,
                            &recipient_account_id,
                            &origin_key,
                            encrypted_balance,
                            rng,
                            fee
                    ).expect("fails to generate the tx");


            {
                println!("Start sending extrinsic to substrate node");

                let p_g = zFixedGenerators::Diversifier; // 1

                let mut rsk_repr = zFs::default().into_repr();
                rsk_repr.read_le(&mut &tx.rsk[..]).unwrap();
                let rsk = zFs::from_repr(rsk_repr).unwrap();

                let sig_sk = zPrivateKey::<zBls12>(rsk);
                let sig_vk = SigVerificationKey::from_slice(&tx.rvk[..]);

                let calls = Call::ConfTransfer(ConfTransferCall::confidential_transfer(
                    Proof::from_slice(&tx.proof[..]),
                    PkdAddress::from_slice(&tx.address_sender[..]),
                    PkdAddress::from_slice(&tx.address_recipient[..]),
                    zCiphertext::from_slice(&tx.enc_val_sender[..]),
                    zCiphertext::from_slice(&tx.enc_val_recipient[..]),
                    sig_vk,
                    zCiphertext::from_slice(&tx.enc_fee[..]),
                ));

                let era = Era::Immortal;
                let index = api.get_nonce(&sig_vk).expect("Nonce must be got.");
                let checkpoint = api.get_genesis_blockhash().unwrap();
                let raw_payload = (Compact(index), calls, era, checkpoint);

                let sig = raw_payload.using_encoded(|payload| {
                    let msg = blake2_256(payload);
                    let sig = sig_sk.sign(&msg[..], rng, p_g, &ZPARAMS as &zJubjubBls12);

                    let sig_vk = sig_vk.into_verification_key().unwrap();
                    assert!(sig_vk.verify(&msg, &sig, p_g, &ZPARAMS as &zJubjubBls12));

                    sig
                });

                let sig_repr = RedjubjubSignature::from_signature(&sig);
                let uxt = UncheckedExtrinsic::new_signed(index, raw_payload.1, sig_vk.into(), sig_repr, era);
                let _tx_hash = api.submit_extrinsic(&uxt).unwrap();

                println!("Remaining balance is {}", remaining_balance);
            }

        },
        ("get-balance", Some(sub_matches)) => {
            println!("Getting encrypted balance from substrate node");
            let api = Api::init(Url::Local);
            let decryption_key_vec = hex::decode(sub_matches.value_of("decryption-key").unwrap()).unwrap();

            let (decrypted_balance, _, encrypted_balance_str) = get_balance_from_decryption_key(&decryption_key_vec[..], api);

            println!("Decrypted balance is {}", decrypted_balance);
            println!("Encrypted balance is {}", encrypted_balance_str);


        },
        ("decrypt", Some(sub_matches)) => {
            println!("Decrypting the data...");
            let p_g = FixedGenerators::NoteCommitmentRandomness; // 1

            let enc = sub_matches.value_of("encrypted-value").unwrap();
            let enc_vec = hex::decode(enc).unwrap();
            let enc_c = elgamal::Ciphertext::<Bls12>::read(&mut &enc_vec[..], &PARAMS).expect("Invalid data");

            let pk = sub_matches.value_of("private-key").unwrap();
            let pk_vec = hex::decode(pk).unwrap();

            let mut pk_repr = fs::Fs::default().into_repr();
            pk_repr.read_le(&mut &pk_vec[..]).unwrap();

            let dec = enc_c.decrypt(fs::Fs::from_repr(pk_repr).unwrap(), p_g, &PARAMS).unwrap();
            println!("Decrypted value is {}", dec);
        },
        _ => unreachable!()
    }
    Ok(())
}