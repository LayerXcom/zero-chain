#[macro_use]
extern crate lazy_static;

// use structopt::Structopt;
use rand::{rngs::OsRng, RngCore};
use zero_chain_proofs::primitives::{ExpandedSpendingKey, ViewingKey, Diversifier};
use substrate_primitives::hexdisplay::HexDisplay;
use pairing::bls12_381::Bls12;
use sapling_crypto::jubjub::JubjubBls12;

lazy_static! {
    static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}

fn print_account(seed: &[u8; 32]) {    
    for i in 0..3 {
        let expsk = ExpandedSpendingKey::<Bls12>::from_spending_key(seed);
        let mut expsk_bytes = vec![];
        expsk.write(&mut expsk_bytes).unwrap();

        let viewing_key = ViewingKey::<Bls12>::from_expanded_spending_key(&expsk, &JUBJUB);
        let diversifier = Diversifier::new::<Bls12>(&JUBJUB).unwrap();
        let address = viewing_key.into_payment_address(diversifier, &JUBJUB).unwrap();

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
