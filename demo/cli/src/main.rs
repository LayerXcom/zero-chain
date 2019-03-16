use clap::{Arg, App, SubCommand, AppSettings};
use rand::{OsRng, Rng, Rand};
use proofs::{
    primitives::{ExpandedSpendingKey, ViewingKey},     
    elgamal::{Ciphertext, elgamal_extend},
    };
use substrate_primitives::hexdisplay::{HexDisplay, AsBytesRef};
use pairing::{bls12_381::Bls12, Field};
use scrypto::jubjub::{JubjubBls12, fs, ToUniform, JubjubParams, FixedGenerators};      
use std::fs::File;
use std::path::Path;
use std::string::String;
use std::io::{BufWriter, Write, BufReader, Read};
use wasm_utils::transaction::Transaction;
use bellman::groth16::{Parameters, PreparedVerifyingKey};

mod setup;
use setup::setup;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref params: JubjubBls12 = { JubjubBls12::new() };
}

fn get_address(seed: &[u8; 32]) -> Vec<u8> { 
    let expsk = ExpandedSpendingKey::<Bls12>::from_spending_key(seed);     
    let viewing_key = ViewingKey::<Bls12>::from_expanded_spending_key(&expsk, &params);        
    let address = viewing_key.into_payment_address(&params);

    let mut address_bytes = vec![];
    address.write(&mut address_bytes).unwrap();
    address_bytes
}

fn print_random_accounts(seed: &[u8; 32], num: i32) {    
    for i in 0..num {
        let address_bytes = get_address(seed);

        println!("Secret Key{}: 0x{}\n Address{}: 0x{}\n", 
            i,
            HexDisplay::from(seed),
            i,
            HexDisplay::from(&address_bytes),
        );
    }
}

fn print_alice_tx(sender_seed: &[u8], recipient_seed: &[u8], mut proving_key_b: &[u8], mut prepared_vk_b : &[u8]) {    
    let rng = &mut OsRng::new().expect("should be able to construct RNG");
    let p_g = FixedGenerators::NoteCommitmentRandomness; // 1

    let value = 10 as u32;
    let remaining_balance = 90 as u32;
    let balance = 100 as u32;
    // let alpha = fs::Fs::rand(rng); 
    let alpha = fs::Fs::zero();
    
    let proving_key =  Parameters::<Bls12>::read(&mut proving_key_b, true).unwrap();
    let prepared_vk = PreparedVerifyingKey::<Bls12>::read(&mut prepared_vk_b).unwrap();
    
    let ex_sk_s = ExpandedSpendingKey::<Bls12>::from_spending_key(&sender_seed[..]);
    let ex_sk_r = ExpandedSpendingKey::<Bls12>::from_spending_key(&recipient_seed[..]);
    
    let viewing_key_s = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk_s, &params);
    let viewing_key_r = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk_r, &params);

    let address_recipient = viewing_key_r.into_payment_address(&params);
    
    let ivk = viewing_key_s.ivk();    
    
    let r_fs = fs::Fs::rand(rng);

    let public_key = params.generator(p_g).mul(ivk, &params).into();
    let ciphertext_balance = Ciphertext::encrypt(balance, r_fs, &public_key, p_g, &params);        

    let tx = Transaction::gen_tx(
                    value, 
                    remaining_balance, 
                    alpha,
                    &proving_key,
                    &prepared_vk,
                    &address_recipient,
                    sender_seed,
                    ciphertext_balance,                    
                    rng
            ).expect("fails to generate the tx");

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
        ",        
        HexDisplay::from(&&tx.proof[..] as &AsBytesRef),    
        HexDisplay::from(&tx.address_sender as &AsBytesRef),    
        HexDisplay::from(&tx.address_recipient as &AsBytesRef),        
        HexDisplay::from(&tx.enc_val_sender as &AsBytesRef),
        HexDisplay::from(&tx.enc_val_recipient as &AsBytesRef),
        HexDisplay::from(&tx.enc_bal_sender as &AsBytesRef),     
        HexDisplay::from(&tx.rk as &AsBytesRef),
        HexDisplay::from(&tx.rsk as &AsBytesRef),
    );
}
    
fn main() {   
    cli().unwrap_or_else(|e| {
        println!("{}", e);
        std::process::exit(1);
    });

}

fn cli() -> Result<(), String> {
    const VERIFICATION_KEY_PATH: &str = "verification.params";
    const PROVING_KEY_PATH: &str = "proving.params";

    let matches = App::new("Zerochain")
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
        ("generate-tx", Some(sub_matches)) => {
            println!("Generate transaction...");

            let mut seed = [0u8; 32];
            if let Ok(mut e) = OsRng::new() {
                e.fill_bytes(&mut seed[..]);
            }    

            let alice_seed = b"Alice                           ";
            let bob_seed = b"Bob                             ";
            let alice_address = get_address(alice_seed);

            println!("Secret Key(Alice): 0x{}\nAddress(Alice): 0x{}\n",        
                HexDisplay::from(alice_seed),        
                HexDisplay::from(&alice_address),
            );

            print_random_accounts(&seed, 2);                        

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
            
            print_alice_tx(alice_seed, bob_seed, &buf_pk[..], &buf_vk[..]);

        },
        _ => unreachable!()
    }
    Ok(())
}
