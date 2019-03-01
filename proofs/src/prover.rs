use bellman::groth16::{
    create_random_proof, 
    verify_proof, 
    Parameters, 
    PreparedVerifyingKey, 
    Proof,        
};
use pairing::{
    bls12_381::{
        Bls12,               
    },
    Field,    
};
use rand::{OsRng, Rand};
use scrypto::{    
    jubjub::{
        JubjubEngine,
        JubjubParams,
        edwards,         
        FixedGenerators, 
        JubjubBls12, 
        Unknown, 
        PrimeOrder
    },    
    redjubjub::{        
        PublicKey,        
    },
};
use crate::circuit_transfer::Transfer;
use crate::primitives::{    
    PaymentAddress, 
    ProofGenerationKey,     
};
use crate::elgamal::Ciphertext;

pub struct TransferProof<E: JubjubEngine> {
    pub proof: Proof<E>,
    pub rk: PublicKey<E>, // re-randomization sig-verifying key    
    pub address_sender: PaymentAddress<E>,    
    pub address_recipient: PaymentAddress<E>,
    pub cipher_val_s: Ciphertext<E>,
    pub cipher_val_r: Ciphertext<E>,
}

impl<E: JubjubEngine> TransferProof<E> {    
    pub fn gen_proof(        
        value: u32,         
        remaining_balance: u32,        
        alpha: E::Fs,        
        proving_key: &Parameters<E>, 
        verifying_key: &PreparedVerifyingKey<E>,
        proof_generation_key: ProofGenerationKey<E>,
        address_recipient: PaymentAddress<E>,   
        ciphertext_balance: Ciphertext<E>,  
        params: &E::Params,        
    ) -> Result<Self, ()>
    {
        // TODO: Change OsRng for wasm
        let mut rng = OsRng::new().expect("should be able to construct RNG");        

        let randomness = E::Fs::rand(&mut rng);        
        
        let viewing_key = proof_generation_key.into_viewing_key(params);
        let ivk = viewing_key.ivk();

        let address_sender = viewing_key.into_payment_address(params);

        let rk = PublicKey(proof_generation_key.ak.clone().into())
            .randomize(
                alpha,
                FixedGenerators::SpendingKeyGenerator,
                params,
        );                       

        let instance = Transfer {
            params: params,
            value: Some(value),
            remaining_balance: Some(remaining_balance),
            randomness: Some(randomness.clone()),
            alpha: Some(alpha.clone()),
            proof_generation_key: Some(proof_generation_key.clone()),
            ivk: Some(ivk.clone()),
            pk_d_recipient: Some(address_recipient.0.clone()),
            encrypted_balance: Some(ciphertext_balance.clone())            
        };

        // Crate proof
        let proof = create_random_proof(instance, proving_key, &mut rng)
            .expect("proving should not fail");
        
        let mut public_input = [E::Fr::zero(); 16];

        let cipher_val_s = Ciphertext::encrypt(
            value, 
            randomness, 
            &address_sender.0, 
            FixedGenerators::NullifierPosition,
            params
        );

        let cipher_val_r = Ciphertext::encrypt(
            value, 
            randomness, 
            &address_recipient.0, 
            FixedGenerators::NullifierPosition,
            params
        );

        {
            let (x, y) = address_sender.0.into_xy();
            public_input[0] = x;
            public_input[1] = y;
        }
        {
            let (x, y) = address_recipient.0.into_xy();
            public_input[2] = x;
            public_input[3] = y;
        }
        {
            let (x, y) = cipher_val_s.left.into_xy();
            public_input[4] = x;
            public_input[5] = y;
        }
        {
            let (x, y) = cipher_val_r.left.into_xy();
            public_input[6] = x;
            public_input[7] = y;
        }
        {
            let (x, y) = cipher_val_s.right.into_xy();
            public_input[8] = x;
            public_input[9] = y;
        }
        {
            let (x, y) = ciphertext_balance.left.into_xy();
            public_input[10] = x;
            public_input[11] = y;            
        }
        {
            let (x, y) = ciphertext_balance.right.into_xy();
            public_input[12] = x;
            public_input[13] = y;
        }
        {
            let (x, y) = rk.0.into_xy();
            public_input[14] = x;
            public_input[15] = y;
        }                             

        match verify_proof(verifying_key, &proof, &public_input[..]) {
            Ok(true) => {},
            _ => {
                return Err(());
            }
        }

        let transfer_proof = TransferProof {
            proof: proof,        
            rk: rk,             
            address_sender: address_sender,  
            address_recipient: address_recipient,          
            cipher_val_s: cipher_val_s,
            cipher_val_r: cipher_val_r,
        };

        Ok(transfer_proof)
    }    
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_proof() {
        
    }
}
