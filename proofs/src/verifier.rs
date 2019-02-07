use bellman::groth16::{
    create_random_proof, 
    verify_proof, 
    Parameters, 
    PreparedVerifyingKey, 
    Proof,
    prepare_verifying_key, 
    generate_random_parameters,
};
use pairing::{
    bls12_381::{
        Bls12, 
        Fr, 
        FrRepr
    },
    Field, 
    PrimeField, 
    PrimeFieldRepr, 
    Engine,
};
use rand::{OsRng, Rand};
use scrypto::{    
    jubjub::{
        edwards, 
        fs::Fs, 
        FixedGenerators, 
        JubjubBls12, 
        Unknown, 
        PrimeOrder
    },    
    redjubjub::{
        PrivateKey, 
        PublicKey, 
        Signature as RedjubjubSignature,
    },
};
use circuit_transfer::Transfer;
use primitives::{
    Diversifier, 
    PaymentAddress, 
    ProofGenerationKey, 
    ValueCommitment
};

fn is_small_order<Order>(p: &edwards::Point<Bls12, Order>, params: &JubjubBls12) -> bool {
    p.double(params).double(params).double(params) == edwards::Point::zero()
}

pub fn check_proof (    
    zkproof: Proof<Bls12>,
    cv_transfer: edwards::Point<Bls12, Unknown>,
    cv_balance: edwards::Point<Bls12, Unknown>,
    epk: edwards::Point<Bls12, Unknown>,
    rk: PublickKey<Bls12>,
    verifying_key: &PreparedVerifyingKey<Bls12>,
    sighash_value: &[u8; 32],
    auth_sig: RedjubjubSignature,
    params: &JubjubBls12,
) -> bool {
    if is_small_order(&cv, params) {
        return false;
    }
    if is_small_order(&rk.0, params) {
        return false;
    }

}
}
