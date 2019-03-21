use bellman::groth16::{Parameters, PreparedVerifyingKey};
use pairing::bls12_381::Bls12;
use zpairing::io;
use scrypto::{
	jubjub::{JubjubBls12, fs},
	redjubjub::PrivateKey,
	};
use proofs::{
    self,
	primitives::{		
		PaymentAddress, 		
		ExpandedSpendingKey,		
		},
	prover::TransferProof,	   
};
use rand::Rng;

pub struct Transaction{    
    pub rk: [u8; 32],                    // 32 bytes
    pub proof: [u8; 192],                // 192 bytes
    pub address_sender: [u8; 32],        // 32 bytes
    pub address_recipient: [u8; 32],     // 32 bytes
    pub enc_val_recipient: [u8; 64],     // 64 bytes
	pub enc_val_sender: [u8; 64],        // 64 bytes
	pub enc_bal_sender: [u8; 64],        // 64 bytes	
	pub rsk: [u8; 32],                   // 32 bytes
}

impl Transaction {
    pub fn gen_tx<R: Rng>(
        value: u32,
        remaining_balance: u32,
        alpha: fs::Fs,
        proving_key: &Parameters<Bls12>,
		prepared_vk: &PreparedVerifyingKey<Bls12>,		
		address_recipient: &PaymentAddress<Bls12>,		
		ex_sk_sender: &ExpandedSpendingKey<Bls12>,
        ciphertext_balance: proofs::elgamal::Ciphertext<Bls12>,		
		rng: &mut R,
    ) -> Result<Self, io::Error>
	{		
		// The pramaters from std environment
		let params = JubjubBls12::new();
		
		let proof_generation_key = ex_sk_sender.into_proof_generation_key(&params);

		// Generate the zk proof
		let proof_output = TransferProof::gen_proof(
			value,
			remaining_balance,        
			alpha,			
			proving_key, 
			prepared_vk,
			proof_generation_key,
			address_recipient.clone(),			
            ciphertext_balance.clone(),
			rng,
			&params,
		).unwrap();		

		// Generate the re-randomized sign key
		let rsk = PrivateKey::<Bls12>(ex_sk_sender.ask).randomize(alpha);
		let mut rsk_bytes = [0u8; 32];
		rsk.write(&mut rsk_bytes[..]).map_err(|_| io::Error::InvalidData)?;
		
		let mut rk_bytes = [0u8; 32];
		proof_output.rk.write(&mut rk_bytes[..]).map_err(|_| io::Error::InvalidData)?;

		let mut proof_bytes = [0u8; 192];
		proof_output.proof.write(&mut proof_bytes[..]).map_err(|_| io::Error::InvalidData)?;

		let mut b_address_sender = [0u8; 32];
		proof_output.address_sender.write(&mut b_address_sender[..]).map_err(|_| io::Error::InvalidData)?;

		let mut b_address_recipient = [0u8; 32];
		proof_output.address_recipient.write(&mut b_address_recipient[..]).map_err(|_| io::Error::InvalidData)?;

		let mut enc_val_recipient = [0u8; 64];
		proof_output.cipher_val_r.write(&mut enc_val_recipient[..]).map_err(|_| io::Error::InvalidData)?;

		let mut enc_val_sender = [0u8; 64];
		proof_output.cipher_val_s.write(&mut enc_val_sender[..]).map_err(|_| io::Error::InvalidData)?;

		let mut enc_bal_sender = [0u8; 64];
		proof_output.cipher_balance.write(&mut enc_bal_sender[..]).map_err(|_| io::Error::InvalidData)?;					

		let tx = Transaction {		
			proof: proof_bytes,		           			 
			rk: rk_bytes,  			      
			address_sender: b_address_sender,        
			address_recipient: b_address_recipient,
			enc_val_recipient: enc_val_recipient,
			enc_val_sender: enc_val_sender,
			enc_bal_sender: enc_bal_sender,
			rsk: rsk_bytes,					
		};

		Ok(tx)
	}
}
