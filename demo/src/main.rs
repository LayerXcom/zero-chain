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

fn print_account(seed: &[u8; 32]) {    
    for i in 0..3 {
        let expsk = ExpandedSpendingKey::<Bls12>::from_spending_key(seed);
        let mut expsk_bytes = vec![];
        expsk.write(&mut expsk_bytes).unwrap();

        let params = JubjubBls12::new();

        let viewing_key = ViewingKey::<Bls12>::from_expanded_spending_key(&expsk, &params);        
        let address = viewing_key.into_payment_address(&params);

        let mut address_bytes = vec![];
        address.write(&mut address_bytes).unwrap();

        println!("Spending key{}: 0x{}\n Address{}: 0x{}\n", 
            i,
            HexDisplay::from(&expsk_bytes),
            i,
            HexDisplay::from(&address_bytes),
        );
    }
}

fn main() {
    let mut seed = [0u8; 32];
    OsRng::new().unwrap().fill_bytes(&mut seed[..]);
    print_account(&seed);
}
