use bellman::groth16::{Parameters, Proof, PreparedVerifyingKey};
use bellman_verifier::Proof as zProof;

use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    Field, PrimeField, PrimeFieldRepr,
};

use scrypto::{    
    jubjub::{FixedGenerators, PrimeOrder, JubjubEngine},    
    redjubjub::{PrivateKey, PublicKey, Signature},
};
use zjubjub::{
	curve::JubjubBls12,
	redjubjub::{PrivateKey as zPrivateKey, PublicKey as zPublicKey, Signature as zSignature},
};

use proofs::{
    self,
	primitives::{PaymentAddress, ProofGenerationKey},
	prover::TransferProof,
	elgamal::Ciphertext,   
};

use blake2_rfc::blake2b::Blake2b;
use zcrypto::{constants, elgamal::Ciphertext as zCiphertext};
use rand::{OsRng, Rand, Rng};
use std::marker::PhantomData;

use zprimitives::{
		ciphertext::Ciphertext as pCiphertext,
		account_id::AccountId as pAccountId,
		proof::Proof as pProof,
		public_key::{SigVerificationKey as pSigVerificationKey},
		signature::Signature as pSignature,
		keys::PaymentAddress as zPaymentAddress,
	};

#[derive(Eq, PartialEq, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct Transaction<E: JubjubEngine> {
    pub sig: pSignature,                   // 64 bytes
    pub sighash_value: Vec<u8>,            // 32 bytes [u8; 32]
    pub vk: pSigVerificationKey,           // 32 bytes
    pub proof: pProof,                     // 192 bytes
    pub address_sender: pAccountId,        // 43 bytes
    pub address_recipient: pAccountId,     // 43 bytes
    pub enc_val_recipient: pCiphertext,    // 64 bytes
	pub enc_val_sender: pCiphertext,       // 64 bytes
	pub enc_bal_sender: pCiphertext,       // 64 bytes
	phantom: PhantomData<E>
}

impl<E: JubjubEngine> Transaction<E> {
    pub fn gen_tx(
        value: u32,
        remaining_balance: u32,
        alpha: E::Fs,
        proving_key: &Parameters<E>,
		verifying_key: &PreparedVerifyingKey<E>,
		proof_generation_key: ProofGenerationKey<E>,
		address_recipient: &PaymentAddress<E>,		
		sk: E::Fs,
        ciphertext_balance: proofs::elgamal::Ciphertext<E>,
		params: &E::Params,
    ) -> Result<Self, &'static str>
	{
		let rng = &mut OsRng::new().expect("OsRng::new() error.");

		let proof_output = TransferProof::gen_proof(
			value,
			remaining_balance,        
			alpha,			
			proving_key, 
			verifying_key,
			proof_generation_key,
			address_recipient.clone(),			
            ciphertext_balance.clone(),
			params,
		).unwrap();

		let jbujub_bls12 = JubjubBls12::new();
		
		// Generate the re-randomized sign key
		let rsk: PrivateKey<E> = PrivateKey(sk).randomize(alpha);

		// FIXME
		let msg = b"Foo bar";		

		let mut h = Blake2b::with_params(32, &[], &[], constants::SIGHASH_PERSONALIZATION);		
		h.update(msg);
		let sighash_value = h.finalize().as_ref().to_vec();
		
		let p_g = FixedGenerators::SpendingKeyGenerator;
		let sig = rsk.sign(msg, rng, p_g, params);

		let mut sig_bytes = [0u8; 32];
		sig.write(&mut sig_bytes[..]).unwrap();
		// Read Signature as a no_std type
		let zsig = zSignature::read(&sig_bytes[..]).unwrap();
		
		let mut rk_bytes = [0u8; 32];
		proof_output.rk.write(&mut rk_bytes[..]).unwrap();
		// Read Publickey as a no_std type
		let zrk = zPublicKey::read(&mut &rk_bytes[..], &jbujub_bls12).unwrap();

		let mut proof_bytes = [0u8; 192];
		proof_output.proof.write(&mut proof_bytes[..]).unwrap();
		// Read Proof as a no_std type
		let zproof = zProof::read(&proof_bytes[..]).unwrap();

		let mut z_addr_sb = [0u8; 32];
		proof_output.address_sender.write(&mut z_addr_sb[..]).unwrap();
		// Read the sender address as a no_std type
		let zaddress_sender = zPaymentAddress::read(&mut &z_addr_sb[..], &jbujub_bls12).unwrap();

		let mut z_addr_rb = [0u8; 32];
		proof_output.address_recipient.write(&mut z_addr_rb[..]).unwrap();
		// Read the recipient address as a no_std type
		let zaddress_recipient = zPaymentAddress::read(&mut &z_addr_rb[..], &jbujub_bls12).unwrap();

		let mut env_val_rb = [0u8; 64];
		proof_output.cipher_val_r.write(&mut env_val_rb[..]).unwrap();
		// Read the sending value encrypted by the recipient key as a no_std type
		let zenc_val_recipient = zCiphertext::read(&mut &env_val_rb[..], &jbujub_bls12).unwrap();

		let mut env_val_sb = [0u8; 64];
		proof_output.cipher_val_s.write(&mut env_val_sb[..]).unwrap();
		// Read the sending value encrypted by the sender key as a no_std type
		let zenc_val_sender = zCiphertext::read(&mut &env_val_sb[..], &jbujub_bls12).unwrap();

		let mut env_bal_sb = [0u8; 64];
		ciphertext_balance.write(&mut env_bal_sb[..]).unwrap();
		// Read the sender's balance encrypted by the sender key as a no_std type
		let zenc_bal_sender = zCiphertext::read(&mut &env_bal_sb[..], &jbujub_bls12).unwrap();
		
		let tx = Transaction {
			sig: pSignature::from_signature(&zsig),                   
			sighash_value: sighash_value,          
			vk: pSigVerificationKey::from_verification_key(&zrk),  
			proof: pProof::from_proof(&zproof),                     
			address_sender: pAccountId::from_payment_address(&zaddress_sender),        
			address_recipient: pAccountId::from_payment_address(&zaddress_recipient),     
			enc_val_recipient: pCiphertext::from_ciphertext(&zenc_val_recipient),
			enc_val_sender: pCiphertext::from_ciphertext(&zenc_val_sender),
			enc_bal_sender: pCiphertext::from_ciphertext(&zenc_bal_sender),
			phantom: PhantomData::<E>
		};

		Ok(tx)
	}
}

