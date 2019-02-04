
// use structopt::Structopt;
use rand::{rngs::OsRng, RngCore};
use zero_chain_proofs::primitives::{ExpandedSpendingKey};
use substrate_primitives::hexdisplay::HexDisplay;
use pairing::bls12_381::Bls12;

fn print_account(seed: &[u8; 32]) {    
    for i in 0..3 {
        let expsk = ExpandedSpendingKey::<Bls12>::from_spending_key(seed);
        let mut expsk_bytes = vec![];
        expsk.write(&mut expsk_bytes).unwrap();

        println!("Spending key{}: 0x{}\n", 
            i,
            HexDisplay::from(&expsk_bytes)
        );
    }
}

fn main() {
    let mut seed = [0u8; 32];
    OsRng::new().unwrap().fill_bytes(&mut seed[..]);
    print_account(&seed);
}
