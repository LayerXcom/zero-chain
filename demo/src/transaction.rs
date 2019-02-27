use bellman::groth16::{
    create_random_proof, verify_proof, Parameters, PreparedVerifyingKey, Proof,
    prepare_verifying_key, generate_random_parameters,
};
use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    Field, PrimeField, PrimeFieldRepr,
};
use scrypto::{    
    jubjub::{edwards, fs::Fs, FixedGenerators, JubjubBls12, Unknown, PrimeOrder, JubjubEngine},    
    redjubjub::{PrivateKey, PublicKey, Signature as RedjubjubSignature},
};
use proofs::{
	primitives::{Diversifier, PaymentAddress, ProofGenerationKey},
	prover::TransferProof,
};
use blake2_rfc::blake2b::Blake2b;
use zcrypto::{constants, elgamal};
use rand::{OsRng, Rand, Rng};

use zprimitives::{
	account_id::AccountId,
	ciphertext::Ciphertext,
	proof::Proof,
	public_key::PublicKey,
	signature::Signature,
};

#[derive(Eq, PartialEq, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct Transaction {
    pub sig: Signature,                   // 64 bytes
    pub sighash_value: Vec<u8>,           // 32 bytes [u8; 32]
    pub vk: SigVerificationKey,           // 32 bytes
    pub proof: Proof,                     // 192 bytes
    pub address_sender: AccountId,        // 43 bytes
    pub address_recipient: AccountId,     // 43 bytes
    pub enc_val_recipient: Ciphertext,    // 64 bytes
	pub enc_val_sender: Ciphertext,       // 64 bytes
	pub enc_bal_sender: Ciphertext,       // 64 bytes
}

// impl<E: JubjubEngine> Transaction {
//     pub fn gen_tx(
//         value: u32,
//         balance: u32,
//         alpha: &E::Fs,
//         proving_key: &Parameters<E>
// 		verifyibng_key: &Parameters<E>
// 		proof_generation_key: &ProofGenerationKey<E>,
// 		address_recipient: &PaymentAddress<E>,		
// 		sk: E::Fs
// 		params: &E::Params
//     ) -> Result<Self, &'static str>
// 	{
// 		let rng = &mut OsRng::new().expect("OsRng::new() error.");

// 		let proof_output = TransferProof::gen_proof(
// 			value as u64,
// 			balance as u64,        
// 			alpha,			
// 			proving_key, 
// 			verifying_key,
// 			proof_generation_key,
// 			payment_addr_recipient.clone(),
// 			address_sender.diversifier,
// 			params,  
// 		)?;
		
// 		let rsk = PrivateKey(sk).randomize(alpha);

// 		// FIXME
// 		let msg = b"Foo bar";

// 		let mut h = Blake2b::with_params(32, &[], &[], constants::SIGHASH_PERSONALIZATION);		
// 		h.update(msg);
// 		let sighash_value = h.finalize().as_ref().to_vec();
		
// 		let p_g = FixedGenerators::SpendingKeyGenerator;
// 		let sig = rsk.sign(msg, rng, p_g, params);
		
// 		let ciphertext = Ciphertext::encrypt(value, )

// 		let tx = Transaction {
// 			sig: from_signature(sig),                   
// 			sighash_value: sighash_value,          
// 			vk: from_public_key(proof_output.rk),  
// 			proof: from_proof(proof_output.proof),                     
// 			address_sender: from_payment_address(proof_output.address_sender),        
// 			address_recipient: from_payment_address(address_recipient),     
// 			ciphertext_sender: Ciphertext,    			
// 		};

// 		Ok(tx)
// 	}
// }
