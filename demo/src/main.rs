#[macro_use]
extern crate structopt;
use structopt::StructOpt;
use rand::{OsRng, Rng, Rand};
use proofs::{
    primitives::{ExpandedSpendingKey, ViewingKey}, 
    setup::setup,
    elgamal::{Ciphertext, elgamal_extend},
    };
use substrate_primitives::hexdisplay::{HexDisplay, AsBytesRef};
use pairing::{bls12_381::Bls12, PrimeField};
use scrypto::jubjub::{JubjubBls12, fs, ToUniform, JubjubParams, FixedGenerators};      

pub mod transaction;
use transaction::Transaction;

extern crate parity_codec as codec;
#[macro_use]
extern crate parity_codec_derive as codec_derive;
#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}

#[derive(StructOpt, Debug)]
#[structopt(name = "handle")]
struct Opt {
    #[structopt(short = "b", long = "balance")]
    balance: Vec<String>,
}

fn get_address(seed: &[u8; 32]) -> Vec<u8> { 
    let expsk = ExpandedSpendingKey::<Bls12>::from_spending_key(seed);     
    let viewing_key = ViewingKey::<Bls12>::from_expanded_spending_key(&expsk, &JUBJUB);        
    let address = viewing_key.into_payment_address(&JUBJUB);

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

fn print_alice_tx(sender_seed: &[u8], recipient_seed: &[u8]) {
    let params = &JubjubBls12::new();
    let mut rng = OsRng::new().expect("should be able to construct RNG");
    let p_g = FixedGenerators::NullifierPosition; // 2

    let value = 10 as u32;
    let remaining_balance = 90 as u32;
    let balance = 100 as u32;
    let alpha = fs::Fs::rand(&mut rng); 

    let (proving_key, prepared_vk) = setup();        
    
    let ex_sk_r = ExpandedSpendingKey::<Bls12>::from_spending_key(&recipient_seed[..]);
    
    let viewing_key_r = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk_r, params);
    let address_recipient = viewing_key_r.into_payment_address(params);
    
    let sk_fs = fs::Fs::to_uniform(elgamal_extend(&sender_seed).as_bytes()).into_repr();
    let mut randomness = [0u8; 32];

    rng.fill_bytes(&mut randomness[..]);
    let r_fs = fs::Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

    let public_key = params.generator(p_g).mul(sk_fs, params).into();
    let ciphertext_balance = Ciphertext::encrypt(balance, r_fs, &public_key, p_g, params);        

    let tx = Transaction::gen_tx(
                    value, 
                    remaining_balance, 
                    alpha,
                    &proving_key,
                    &prepared_vk,
                    &address_recipient,
                    sender_seed,
                    ciphertext_balance
            ).expect("fails to generate the tx");

    println!(
        "
        \nzkProof(Alice): 0x{}
        \naddress_sender(Alice): 0x{}
        \naddress_recipient(Alice): 0x{}
        \nvalue_sender(Alice): 0x{}
        \nvalue_recipient(Alice): 0x{}
        \nbalance_sender(Alice): 0x{}
        \nrk(Alice): 0x{}           
        ",        
        HexDisplay::from(&tx.proof as &AsBytesRef),    
        HexDisplay::from(&tx.address_sender as &AsBytesRef),    
        HexDisplay::from(&tx.address_recipient as &AsBytesRef),        
        HexDisplay::from(&tx.enc_val_sender as &AsBytesRef),
        HexDisplay::from(&tx.enc_val_recipient as &AsBytesRef),
        HexDisplay::from(&tx.enc_bal_sender as &AsBytesRef),     
        HexDisplay::from(&tx.rk as &AsBytesRef),
    );
}

fn main() {
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
    print_alice_tx(alice_seed, bob_seed);
}
