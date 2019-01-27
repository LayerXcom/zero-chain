

use bellman::groth16::{
    create_random_proof, verify_proof, Parameters, PreparedVerifyingKey, Proof,
    prepare_verifying_key, generate_random_parameters,
};
use byteorder::{LittleEndian, ReadBytesExt};
use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    Field, PrimeField, PrimeFieldRepr, Engine,
};
use rand::{thread_rng, Rng, ChaChaRng};
use scrypto::{
    circuit::{
        multipack,
        sapling::{Output, Spend, TREE_DEPTH},
    },
    jubjub::{edwards, fs::Fs, FixedGenerators, JubjubBls12, Unknown},
    primitives::{Diversifier, Note, PaymentAddress, ProofGenerationKey, ValueCommitment},
    redjubjub::{PrivateKey, PublicKey, Signature},
};
use circuit_transfer::Transfer;


pub struct ProvingContext {
    bsk: Fs,
    bvk: edwards::Point<Bls12, Unknown>,
}

impl ProvingContext {
    pub fn new() -> Self {
        ProvingContext {
            bsk: Fs::zero(),
            bvk: edwards::Point::zero(),
        }
    }

    pub fn gen_proof(
        &mut self, 
        transfer_value: u64, 
        transfer_rcm: Fs,
        balance_value: u64,
        balance_rcm: Fs,
        ar: Fs,
        esk: Fs, 
        proving_key: &Parameters<Bls12>, 
        verifying_key: &PreparedVerifyingKey<Bls12>,
        proof_generation_key: ProofGenerationKey<Bls21>,
        params: &JubjubBls12,        
    ) -> Result<
        (
            Proof<Bls12>,
            edwards::Point<Bls12, Unknown>, // value commitment       
        ),
        (),    
    >{
        let mut rng = OsRng::new().expect("should be able to construct RNG");        


        let instance = Transfer {
            params: params,     
            transfer_value_commitment: Option<ValueCommitment<E>>,
            balance_value_commitment: Option<ValueCommitment<E>>,            
            ar: Option<E::Fs>,
            proof_generation_key: Option<ProofGenerationKey<E>>, 
            esk: Option<E::Fs>,
            prover_payment_address: Option<PaymentAddress<E>>,
            recipient_payment_address: Option<PaymentAddress<E>>,
        }

        // Crate proof
        let proof = create_random_proof(instance, proving_key, &mut rng)
            .expect("proving should not fail");
    }


}
