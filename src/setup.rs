use pairing::bls12_381::Bls12;

use bellman::groth16::{    
    generate_random_parameters,
    prepare_verifying_key,        
};

use scrypto::jubjub::{JubjubBls12};
use rand::{OsRng, Rand};
use proofs::circuit_transfer::Transfer;

use std::fs::File;
use std::io::{Write, BufWriter};

pub fn setup() {
    let rng = &mut OsRng::new().expect("should be able to construct RNG");

    let params = JubjubBls12::new();

    // Create parameters for the confidential transfer circuit
    let params = {
        let c = Transfer::<Bls12> {
            params: &params,
            value: None,
            remaining_balance: None,
            randomness: None,
            alpha: None,
            proof_generation_key: None,
            ivk: None,
            pk_d_recipient: None,
            encrypted_balance: None,
        };

        generate_random_parameters(c, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);
    let mut v = vec![];
    pvk.write(&mut &mut v).unwrap();    
    // println!("pvk: {:?}", v);
    println!("pvk: {:?}", v.len());

    // let mut file = BufWriter::new(File::create("pvk.txt")?);
    // file.write_all(&v)?;
    // file.flush()?;
    // Ok(())    
}

// #[test]
// fn test_setup() {    
//     setup();
// }
