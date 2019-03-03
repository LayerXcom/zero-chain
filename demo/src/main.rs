// use structopt::Structopt;
use rand::{OsRng, Rand, Rng};
use proofs::primitives::{ExpandedSpendingKey, ViewingKey};
use substrate_primitives::hexdisplay::HexDisplay;
use pairing::bls12_381::Bls12;
use scrypto::jubjub::JubjubBls12;

pub mod transaction;

extern crate parity_codec as codec;
#[macro_use]
extern crate parity_codec_derive as codec_derive;
#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
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

fn main() {
    let mut seed = [0u8; 32];
    OsRng::new().unwrap().fill_bytes(&mut seed[..]);

    let alice_seed = b"Alice                           ";
    let alice_address = get_address(alice_seed);

    println!("Secret Key(Alice): 0x{}\n Address(Alice): 0x{}\n",        
        HexDisplay::from(alice_seed),        
        HexDisplay::from(&alice_address),
    );

    print_random_accounts(&seed, 2);
}
