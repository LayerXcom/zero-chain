use bellman::groth16::Parameters;
use bellman_verifier::Proof as zProof;
use pairing::bls12_381::Bls12;
use zpairing::io;
use scrypto::{
	jubjub::{JubjubBls12, fs},
	redjubjub::PrivateKey,
	};
use zjubjub::{
	curve::JubjubBls12 as zJubjubBls12,
	redjubjub::PublicKey as zPublicKey,
};

use proofs::{
    self,
	primitives::{		
		PaymentAddress, 		
		ExpandedSpendingKey,		
		},
	prover::TransferProof,	   
};

use zcrypto::elgamal::Ciphertext as zCiphertext;
use rand::Rng;

// use zprimitives::{
// 		ciphertext::Ciphertext as pCiphertext,
// 		pkd_address::PkdAddress,
// 		proof::Proof as pProof,
// 		sig_vk::{SigVerificationKey as pSigVerificationKey},		
// 	};
use keys::PaymentAddress as zPaymentAddress;

// #[derive(Eq, PartialEq, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct Transaction{
    // pub sig: pRedjubjubSignature,          // 64 bytes    
    pub rk: [u8; 32],                     // 32 bytes
    pub proof: [u8; 192],                // 192 bytes
    pub address_sender: [u8; 32],        // 32 bytes
    pub address_recipient: [u8; 32],     // 32 bytes
    pub enc_val_recipient: [u8; 64],    // 64 bytes
	pub enc_val_sender: [u8; 64],       // 64 bytes
	pub enc_bal_sender: [u8; 64],       // 64 bytes	
	pub rsk: [u8; 32],                  // 32 bytes
}

impl Transaction {
    pub fn gen_tx<R: Rng>(
        value: u32,
        remaining_balance: u32,
        alpha: fs::Fs,
        proving_key: &Parameters<Bls12>,
		// prepared_vk: &PreparedVerifyingKey<Bls12>,		
		address_recipient: &PaymentAddress<Bls12>,		
		sk: &[u8],
        ciphertext_balance: proofs::elgamal::Ciphertext<Bls12>,		
		rng: &mut R,
    ) -> Result<Self, io::Error>
	{		
		// The pramaters from std environment
		let params = JubjubBls12::new();
		// The pramaters from no_std environment
		// let zparams = zJubjubBls12::new();

		let expsk = ExpandedSpendingKey::<Bls12>::from_spending_key(sk);
		let proof_generation_key = expsk.into_proof_generation_key(&params);

		// Generate the zk proof
		let proof_output = TransferProof::gen_proof(
			value,
			remaining_balance,        
			alpha,			
			proving_key, 
			// prepared_vk,
			proof_generation_key,
			address_recipient.clone(),			
            ciphertext_balance.clone(),
			rng,
			&params,
		);
		
		// let sk = fs::Fs::to_uniform(primitives::prf_extend_wo_t(sk).as_bytes());

		// Generate the re-randomized sign key
		let rsk = PrivateKey::<Bls12>(expsk.ask).randomize(alpha);
		let mut rsk_bytes = [0u8; 32];
		rsk.write(&mut rsk_bytes[..]).map_err(|_| io::Error::InvalidData)?;
		
		let mut rk_bytes = [0u8; 32];
		proof_output.rk.write(&mut rk_bytes[..]).map_err(|_| io::Error::InvalidData)?;
		// Read Publickey as a no_std type
		// let zrk = zPublicKey::read(&mut &rk_bytes[..], &zparams)?;
		// let rk = pSigVerificationKey::from_verification_key(&zrk);

		let mut proof_bytes = [0u8; 192];
		proof_output.proof.write(&mut proof_bytes[..]).map_err(|_| io::Error::InvalidData)?;
		// Read Proof as a no_std type
		// let zproof = zProof::read(&proof_bytes[..])?;	
		// let proof = pProof::from_proof(&zproof);

		let mut z_addr_sb = [0u8; 32];
		proof_output.address_sender.write(&mut z_addr_sb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the sender address as a no_std type
		// let zaddress_sender = zPaymentAddress::read(&mut &z_addr_sb[..], &zparams)?;
		// let address_sender = PkdAddress::from_payment_address(&zaddress_sender);

		let mut z_addr_rb = [0u8; 32];
		proof_output.address_recipient.write(&mut z_addr_rb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the recipient address as a no_std type
		// let zaddress_recipient = zPaymentAddress::read(&mut &z_addr_rb[..], &zparams)?;
		// let address_recipient = PkdAddress::from_payment_address(&zaddress_recipient);

		let mut env_val_rb = [0u8; 64];
		proof_output.cipher_val_r.write(&mut env_val_rb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the sending value encrypted by the recipient key as a no_std type
		// let zenc_val_recipient = zCiphertext::read(&mut &env_val_rb[..], &zparams)?;
		// let enc_val_recipient = pCiphertext::from_ciphertext(&zenc_val_recipient);

		let mut env_val_sb = [0u8; 64];
		proof_output.cipher_val_s.write(&mut env_val_sb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the sending value encrypted by the sender key as a no_std type
		// let zenc_val_sender = zCiphertext::read(&mut &env_val_sb[..], &zparams)?;
		// let mut enc_val_sender = [0u8; 64];
		// zenc_val_sender.write(&mut )
		// pCiphertext::from_ciphertext(&zenc_val_sender);

		let mut env_bal_sb = [0u8; 64];
		ciphertext_balance.write(&mut env_bal_sb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the sender's balance encrypted by the sender key as a no_std type
		// let zenc_bal_sender = zCiphertext::read(&mut &env_bal_sb[..], &zparams)?;
		// let enc_bal_sender = pCiphertext::from_ciphertext(&zenc_bal_sender);				

	
		// let mut msg = vec![];

		// BigEndian::write_u64(&mut msg[..], nonce);
		// // The index of confidential transfer module is fixed at 0x00
		// msg.push(0);
		// msg.push(0);

		// // The index of confidential_transfer function in the module is fixed at 0x00
		// msg.push(0);
		// msg.push(0);

		// // The arugments
		// msg.append(&mut proof.0);		
		// msg.append(&mut address_sender.as_bytes().to_vec());
		// msg.append(&mut address_recipient.as_bytes().to_vec());		
		// msg.append(&mut enc_val_sender.as_bytes().to_vec());
		// msg.append(&mut enc_val_recipient.as_bytes().to_vec());
		// msg.append(&mut enc_bal_sender.as_bytes().to_vec());
		// msg.append(&mut rk.as_bytes().to_vec());  // TODO: Temporally added to use rk explicitly.


		// // let mut h = Blake2b::with_params(32, &[], &[], constants::SIGHASH_PERSONALIZATION);		
		// // h.update(&msg);
		// // let sighash_value = h.finalize().as_ref().to_vec();
				
		// let p_g = FixedGenerators::SpendingKeyGenerator;
		// let sig = rsk.sign(&msg, rng, p_g, &params);	

		// let mut sig_bytes = [0u8; 64];
		// sig.write(&mut sig_bytes[..]).map_err(|_| io::Error::InvalidData)?;		
		// // Read Signature as a no_std type		
		// let zsig = zSignature::read(&sig_bytes[..])?;	
		// let sig = pRedjubjubSignature::from_signature(&zsig);

		let tx = Transaction {		
			proof: proof_bytes,		           			 
			rk: rk_bytes,  			      
			address_sender: z_addr_sb,        
			address_recipient: z_addr_rb,
			enc_val_recipient: env_val_rb,
			enc_val_sender: env_val_sb,
			enc_bal_sender: env_bal_sb,
			rsk: rsk_bytes,					
		};

		Ok(tx)
	}
}

