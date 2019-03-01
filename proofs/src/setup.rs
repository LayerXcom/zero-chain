use pairing::bls12_381::Bls12;

use bellman::{
    Circuit,
    ConstraintSystem,
    SynthesisError,
};

use bellman::groth16::{
    Proof,
    generate_random_parameters,
    prepare_verifying_key,
    create_random_proof,
    verify_proof,
};

use scrypto::jubjub::{JubjubBls12};

use rand::{OsRng, Rand};

use crate::circuit_transfer::Transfer;

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
    // let pvk_v = pvk.write();
    // println!("pvk_len{:?}", pvk_v.len());
}

#[test]
fn test_setup() {    
    setup()
}