use bellman::groth16::{   
    PreparedVerifyingKey, 
    verify_proof, 
    Proof,      
};
use pairing::{
    bls12_381::{
        Bls12, 
        Fr,         
    },
    Field,    
};
use scrypto::{    
    jubjub::{
        edwards,         
        FixedGenerators, 
        JubjubBls12, 
        Unknown, 
        PrimeOrder
    },    
    redjubjub::{        
        PublicKey, 
        Signature as RedjubjubSignature,
    },
};

fn is_small_order<Order>(p: &edwards::Point<Bls12, Order>, params: &JubjubBls12) -> bool {
    p.double(params).double(params).double(params) == edwards::Point::zero()
}

pub fn check_proof (    
    zkproof: Proof<Bls12>,
    cv_transfer: edwards::Point<Bls12, PrimeOrder>,
    cv_balance: edwards::Point<Bls12, PrimeOrder>,
    epk: edwards::Point<Bls12, PrimeOrder>,
    rk: PublicKey<Bls12>,
    verifying_key: &PreparedVerifyingKey<Bls12>,
    sighash_value: &[u8; 32],
    auth_sig: RedjubjubSignature,
    params: &JubjubBls12,
) -> bool {
    // Check the points are not small order
    if is_small_order(&cv_transfer, params) {
        return false;
    }
    if is_small_order(&cv_balance, params) {
        return false;
    }
    if is_small_order(&rk.0, params) {
        return false;
    }

    // Compute the signature's message for rk/auth_sig
    let mut data_to_be_signed = [0u8; 64];
    rk.0.write(&mut data_to_be_signed[0..32])
        .expect("message buffer should be 32 bytes");
    (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash_value[..]);

    // Verify the auth_sig
    if !rk.verify(
        &data_to_be_signed,
        &auth_sig,
        FixedGenerators::SpendingKeyGenerator,
        params,
    ) {
        return false;
    }

    // Construct public input for circuit
    let mut public_input = [Fr::zero(); 8];
    {
        let (x, y) = (&cv_balance).into_xy();
        public_input[0] = x;
        public_input[1] = y;
    }
    {
        let (x, y) = (&cv_transfer).into_xy();
        public_input[2] = x;
        public_input[3] = y;
    }
    {
        let (x, y) = epk.into_xy();
        public_input[4] = x;
        public_input[5] = y;
    }
    {
        let (x, y) = rk.0.into_xy();
        public_input[6] = x;
        public_input[7] = y;
    }

    // Verify the proof
    match verify_proof(verifying_key, &zkproof, &public_input[..]) {
        // No error, and proof verification successful
        Ok(true) => true,
        _ => false,                
    }

}
