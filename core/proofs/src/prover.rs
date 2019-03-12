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
use rand::{OsRng, Rand, Rng};
use scrypto::{    
    jubjub::{
        JubjubEngine,               
        FixedGenerators, 
        JubjubBls12,           
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
    pub fn gen_proof<R: Rng>(        
        value: u32,         
        remaining_balance: u32,        
        alpha: E::Fs,        
        proving_key: &Parameters<E>, 
        // prepared_vk: &PreparedVerifyingKey<E>,
        proof_generation_key: ProofGenerationKey<E>,
        address_recipient: PaymentAddress<E>,   
        ciphertext_balance: Ciphertext<E>,
        rng: &mut R,  
        params: &E::Params,        
    ) -> Self
    {
        // TODO: Change OsRng for wasm
        // let mut rng = OsRng::new().expect("should be able to construct RNG");

        let randomness = E::Fs::rand(rng);   
        
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
        let proof = create_random_proof(instance, proving_key, rng)
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

        // verify_proof(prepared_vk, &proof, &public_input[..])
        //     .expect("verifying should not fail");

        let transfer_proof = TransferProof {
            proof: proof,        
            rk: rk,             
            address_sender: address_sender,  
            address_recipient: address_recipient,          
            cipher_val_s: cipher_val_s,
            cipher_val_r: cipher_val_r,            
        };

        transfer_proof
    }    
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng, Rng};
    use crate::primitives::{ExpandedSpendingKey, ViewingKey};
    use scrypto::jubjub::{fs, ToUniform, JubjubParams};
    use crate::elgamal::elgamal_extend;
    use pairing::PrimeField;
    use std::path::{Path, PathBuf};
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};

    #[test]
    fn test_gen_proof() {        
        let params = &JubjubBls12::new();
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::NullifierPosition;

        let value = 10 as u32;
        let remaining_balance = 30 as u32;
        let balance = 40 as u32;
        let alpha = fs::Fs::rand(&mut rng);         

        let pk_path = Path::new("../../demo/cli/proving.key");        
        let vk_path = Path::new("../../demo/cli/verification.key");        

        let pk_file = File::open(&pk_path).unwrap();
        let vk_file = File::open(&vk_path).unwrap();

        let mut pk_reader = BufReader::new(pk_file);
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_pk = vec![];
        pk_reader.read_to_end(&mut buf_pk).unwrap();

        let proving_key = Parameters::<Bls12>::read(&mut &buf_pk[..], true).unwrap();

        let mut sender_seed = [0u8; 32];
        let mut recipient_seed = [0u8; 32];
        rng.fill_bytes(&mut sender_seed[..]);
        rng.fill_bytes(&mut recipient_seed[..]);

        let ex_sk_s = ExpandedSpendingKey::<Bls12>::from_spending_key(&sender_seed[..]);
        let ex_sk_r = ExpandedSpendingKey::<Bls12>::from_spending_key(&recipient_seed[..]);

        let proof_generation_key = ex_sk_s.into_proof_generation_key(params);
        let viewing_key_r = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk_r, params);
        let address_recipient = viewing_key_r.into_payment_address(params);
        
        let sk_fs = fs::Fs::to_uniform(elgamal_extend(&sender_seed).as_bytes()).into_repr();
        let mut randomness = [0u8; 32];

        rng.fill_bytes(&mut randomness[..]);
        let r_fs = fs::Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let public_key = params.generator(p_g).mul(sk_fs, params).into();
        let ciphertext_balance = Ciphertext::encrypt(balance, r_fs, &public_key, p_g, params);

        // let (_, prepared_vk) = setup::setup();        

        let _proofs = TransferProof::gen_proof(
            value, 
            remaining_balance, 
            alpha, 
            &proving_key, 
            // &prepared_vk, 
            proof_generation_key, 
            address_recipient, 
            ciphertext_balance, 
            &mut rng,
            params
        );
    }

    #[test]
    fn test_read_proving_key() {
        let pk_path = Path::new("../../demo/cli/proving.key");        

        let pk_file = File::open(&pk_path).unwrap();        

        let mut pk_reader = BufReader::new(pk_file);        
        println!("{:?}", pk_reader);
        let mut buf = vec![];

        pk_reader.read_to_end(&mut buf).unwrap();
        println!("{:?}", buf.len());
        
        let proving_key = Parameters::<Bls12>::read(&mut &buf[..], true).unwrap();
    }
}
