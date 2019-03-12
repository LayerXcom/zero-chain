use pairing::bls12_381::Bls12;
use bellman::groth16::{    
    generate_random_parameters,
    prepare_verifying_key,
    Parameters,
    PreparedVerifyingKey,
};
use rand::OsRng;
use proofs::circuit_transfer::Transfer;
use crate::params;

pub fn setup() -> (Parameters<Bls12>, PreparedVerifyingKey<Bls12>) {
    let rng = &mut OsRng::new().expect("should be able to construct RNG");

    // Create parameters for the confidential transfer circuit
    let proving_key = {
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

    let prepared_vk = prepare_verifying_key(&proving_key.vk);
    let mut v = vec![];
    prepared_vk.write(&mut &mut v).unwrap();        
    println!("pvk: {:?}", v.len());

    (proving_key, prepared_vk)
}
