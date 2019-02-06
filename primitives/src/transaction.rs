use bellman::groth16::{
    create_random_proof, verify_proof, Parameters, PreparedVerifyingKey, Proof,
    prepare_verifying_key, generate_random_parameters,
};
use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    Field, PrimeField, PrimeFieldRepr, Engine,
};
use scrypto::{    
    jubjub::{edwards, fs::Fs, FixedGenerators, JubjubBls12, Unknown, PrimeOrder},    
    redjubjub::{PrivateKey, PublicKey, Signature},
};
use proofs::{
	primitives::{Diversifier, PaymentAddress, ProofGenerationKey, ValueCommitment},
	prover::TransferProof,
};
use super::cm_encryption::{Ciphertext, Commitments};
use rand::{OsRng, Rand, Rng};

#[derive(Clone, Encode, Decode, Default)]
pub struct Transaction {
    // Length of the rest of the extrinsic, // 1-5 bytes
 	// Version information, // 1 byte
 	pub nonce: u32,
 	pub sig: Signature, // 64 bytes
 	pub sig_verifying_key: PublicKey<Bls12>, // rk 32bytes
 	pub proof: Proof<Bls12>, // 192 bytes
 	pub balance_commitment: ValueCommitment<Bls12>, // 32 bytes
 	pub transfer_commitment: ValueCommitment<Bls12>, // 32bytes
 	pub epk: edwards::Point<Bls12, PrimeOrder>, // 32 bytes
 	pub payment_address_s: PaymentAddress<Bls12>, // 11 + 32 bytes
 	pub payment_address_r: PaymentAddress<Bls12>, // 11 + 32 bytes
 	pub ciphertext_recipient: Ciphertext<Bls12>, // 16 + 64 bytes?
	pub ciphertext_sender: Ciphertext<Bls12>, // 16 + 64 bytes?
}

impl Transaction {
	pub fn gen_tx(
		transfer_value: u64,         
        balance_value: u64, 				
        ar: Fs,
        esk: Fs, 
        proving_key: &Parameters<Bls12>, 
        verifying_key: &PreparedVerifyingKey<Bls12>,
        proof_generation_key: ProofGenerationKey<Bls12>,
        payment_addr_recipient: PaymentAddress<Bls12>,
        diversifier: Diversifier,
        params: &JubjubBls12,  
			
	) -> Result<Self, ()>
	{
		let rng = &mut OsRng::new().expect("OsRng::new() error.");

		let proof_output = TransferProof::gen_proof(
			transfer_value,
			balance_value,        
			ar,
			esk, 
			proving_key, 
			verifying_key,
			proof_generation_key,
			payment_addr_recipient.clone(),
			diversifier,
			params,  
		)?;
		
		let sk = PrivateKey::<Bls12>(rng.gen());
		let sig_private_key = sk.randomize(ar);
		
		// FIXME
		let msg = b"Foo bar";
		
		let p_g = FixedGenerators::SpendingKeyGenerator;
		let sig = sig_private_key.sign(msg, rng, p_g, params);
		let payment_addr_sender = proof_output.payment_address_sender;

		let transfer_cm = proof_output.transfer_value_commitment;	

		let transfer_cm_recipient = Commitments (
			transfer_cm.clone()
		);		

		let transfer_cm_sender = Commitments (
			transfer_cm.clone().change_sign()
		);		

		let ciphertext_recipient = transfer_cm_recipient.encrypt_cm_to_recipient(
			&payment_addr_recipient.pk_d,
			&payment_addr_recipient.diversifier,
			params
		);

		let ciphertext_sender = transfer_cm_sender.encrypt_cm_to_recipient(
			&payment_addr_sender.pk_d,
			&payment_addr_sender.diversifier,
			params
		);

		// FIXME
		let nonce = 1;

		let tx = Transaction {
			nonce: nonce,
			sig: sig,
			sig_verifying_key: proof_output.rk,
			proof: proof_output.proof,
			balance_commitment: proof_output.balance_value_commitment,
			transfer_commitment: transfer_cm,
			epk: proof_output.epk,
			payment_address_s: payment_addr_sender,
			payment_address_r: payment_addr_recipient,
			ciphertext_recipient: ciphertext_recipient,
			ciphertext_sender: ciphertext_sender,
		};

		Ok(tx)
	}

	// pub fn sig_hash(
	// 	&self,

	// ) -> Vec<u8> {

	// }
}