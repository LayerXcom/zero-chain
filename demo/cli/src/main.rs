use clap::{Arg, App, SubCommand, AppSettings};
use rand::{OsRng, Rng, Rand};
use proofs::{
    primitives::{ExpandedSpendingKey, ViewingKey},     
    elgamal::{Ciphertext, elgamal_extend},
    };
use substrate_primitives::hexdisplay::{HexDisplay, AsBytesRef};
use pairing::{bls12_381::Bls12, Field, PrimeField, PrimeFieldRepr};
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

fn get_address(seed: &[u8]) -> Vec<u8> { 
    let expsk = ExpandedSpendingKey::<Bls12>::from_spending_key(seed);     
    let viewing_key = ViewingKey::<Bls12>::from_expanded_spending_key(&expsk, &params);        
    let address = viewing_key.into_payment_address(&params);

    let mut address_bytes = vec![];
    address.write(&mut address_bytes).unwrap();
    address_bytes
}

// fn print_random_accounts(seed: &[u8], num: i32) {    
//     for i in 0..num {
//         let address_bytes = get_address(seed);

//         println!("Secret Key{}: 0x{}\n Address{}: 0x{}\n", 
//             i,
//             HexDisplay::from(seed),
//             i,
//             HexDisplay::from(&address_bytes),
//         );
//     }
// }

fn print_alice_tx(
    sender_seed: &[u8], 
    recipient_seed: &[u8], 
    mut proving_key_b: &[u8], 
    mut prepared_vk_b : &[u8], 
    value: u32, 
    balance: u32,
) 
{    
    let rng = &mut OsRng::new().expect("should be able to construct RNG");
    let p_g = FixedGenerators::NoteCommitmentRandomness; // 1        
    
    // let alpha = fs::Fs::rand(rng); 
    let alpha = fs::Fs::zero();
        
    let proving_key =  Parameters::<Bls12>::read(&mut proving_key_b, true).unwrap();    
    let prepared_vk = PreparedVerifyingKey::<Bls12>::read(&mut prepared_vk_b).unwrap(); 
        
    let ex_sk_s = ExpandedSpendingKey::<Bls12>::from_spending_key(sender_seed);
    let ex_sk_r = ExpandedSpendingKey::<Bls12>::from_spending_key(&recipient_seed[..]);

    let viewing_key_s = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk_s, &params);       
    let viewing_key_r = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk_r, &params);

    let address_recipient = viewing_key_r.into_payment_address(&params);        
    
    let ivk = viewing_key_s.ivk();
    let public_key = params.generator(p_g).mul(ivk, &params).into();

    let ciphertext_balance = Ciphertext::encrypt(balance, fs::Fs::one(), &public_key, p_g, &params);   

    let remaining_balance = balance - value;       

    let tx = Transaction::gen_tx(
                    value, 
                    remaining_balance, 
                    alpha,
                    &proving_key,
                    &prepared_vk,
                    &address_recipient,
                    &ex_sk_s,
                    ciphertext_balance,                    
                    rng
            ).expect("fails to generate the tx");

    println!(
        "
        \nzkProof: 0x{}                
        \nEncrypted value by sender: 0x{}
        \nEncrypted value by recipient: 0x{}
        \nnEncrypted balance bysender: 0x{}         
        ",        
        HexDisplay::from(&&tx.proof[..] as &AsBytesRef),           
        HexDisplay::from(&tx.enc_val_sender as &AsBytesRef),
        HexDisplay::from(&tx.enc_val_recipient as &AsBytesRef),
        HexDisplay::from(&tx.enc_bal_sender as &AsBytesRef),
    );
    // println!(
    //     "
    //     \nzkProof(Alice): 0x{}
    //     \naddress_sender(Alice): 0x{}
    //     \naddress_recipient(Alice): 0x{}
    //     \nvalue_sender(Alice): 0x{}
    //     \nvalue_recipient(Alice): 0x{}
    //     \nbalance_sender(Alice): 0x{}
    //     \nrvk(Alice): 0x{}           
    //     \nrsk(Alice): 0x{}           
    //     ",        
    //     HexDisplay::from(&&tx.proof[..] as &AsBytesRef),    
    //     HexDisplay::from(&tx.address_sender as &AsBytesRef),    
    //     HexDisplay::from(&tx.address_recipient as &AsBytesRef),        
    //     HexDisplay::from(&tx.enc_val_sender as &AsBytesRef),
    //     HexDisplay::from(&tx.enc_val_recipient as &AsBytesRef),
    //     HexDisplay::from(&tx.enc_bal_sender as &AsBytesRef),     
    //     HexDisplay::from(&tx.rk as &AsBytesRef),
    //     HexDisplay::from(&tx.rsk as &AsBytesRef),
    // );
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
    const DEFAULT_AMOUNT: &str = "10";
    const DEFAULT_BALANCE: &str = "100";
    const ALICESEED: &str = "416c696365202020202020202020202020202020202020202020202020202020";
    const BOBSEED: &str = "426f622020202020202020202020202020202020202020202020202020202020";

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
        ("generate-tx", Some(sub_matches)) => {
            println!("Generate transaction...");

            let sender_seed = hex::decode(sub_matches.value_of("sender-privatekey").unwrap()).unwrap();
            let recipient_seed  = hex::decode(sub_matches.value_of("recipient-privatekey").unwrap()).unwrap();                    

            let rng = &mut OsRng::new().expect("should be able to construct RNG");
            let seed: [u8; 32] = rng.gen();            
            
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

            // print_random_accounts(&seed, 1);                        

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

            let balance_str = sub_matches.value_of("balance").unwrap();
            let balance: u32 = balance_str.parse().unwrap();

            println!("Transaction >>");
            print_alice_tx(&sender_seed[..], &recipient_seed[..], &buf_pk[..], &buf_vk[..], amount, balance);

        },
        ("decrypt", Some(sub_matches)) => {
            println!("Decrypting the data...");
            let p_g = FixedGenerators::NoteCommitmentRandomness; // 1  

            let enc = sub_matches.value_of("encrypted-value").unwrap();
            let enc_vec = hex::decode(enc).unwrap();
            let enc_c = Ciphertext::<Bls12>::read(&mut &enc_vec[..], &params).expect("Invalid data");

            let pk = sub_matches.value_of("private-key").unwrap();
            let pk_vec = hex::decode(pk).unwrap();

            let mut pk_repr = fs::Fs::default().into_repr();    
            pk_repr.read_le(&mut &pk_vec[..]).unwrap(); 

            let dec = enc_c.decrypt(fs::Fs::from_repr(pk_repr).unwrap(), p_g, &params).unwrap();
            println!("Decrypted value is {}", dec);
        },
        _ => unreachable!()
    }
    Ok(())
}
