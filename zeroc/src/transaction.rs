use crate::PARAMS;
use bellman::groth16::{Parameters, PreparedVerifyingKey};
use pairing::bls12_381::Bls12;
use zpairing::io;
use scrypto::{
	jubjub::{JubjubBls12, fs},
	redjubjub::PrivateKey,
	};
use proofs::{
    self,
	keys::{
		EncryptionKey,
		ProofGenerationKey,
		SpendingKey,
		},
	prover::TransferProof,
};
use rand::Rng;

/// Transaction components which is needed to create a signed `UncheckedExtrinsic`.
pub struct Transaction{
    pub proof: [u8; 192],                // 192 bytes
    pub address_sender: [u8; 32],        // 32 bytes
    pub address_recipient: [u8; 32],     // 32 bytes
    pub enc_amount_recipient: [u8; 64],  // 64 bytes
	pub enc_amount_sender: [u8; 64],     // 64 bytes
	pub enc_fee: [u8; 64],			     // 64 bytes
	pub rsk: [u8; 32],                   // 32 bytes
	pub rvk: [u8; 32],                   // 32 bytes
}

impl Transaction {
    pub fn gen_tx<R: Rng>(
        value: u32,
        remaining_balance: u32,
        alpha: fs::Fs,
        proving_key: &Parameters<Bls12>,
		prepared_vk: &PreparedVerifyingKey<Bls12>,
		address_recipient: &EncryptionKey<Bls12>,
		seed: &[u8],
        ciphertext_balance: proofs::elgamal::Ciphertext<Bls12>,
		rng: &mut R,
		fee: u32,
    ) -> Result<Self, io::Error>
	{
		let spending_key = SpendingKey::from_seed(seed);
		let proof_generation_key = ProofGenerationKey::from_spending_key(
			&spending_key,
			&*PARAMS
		);

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
			&PARAMS,
			fee
		).expect("Should not be faild to generate a proof.");

		// Generate the re-randomized sign key
		let rsk = spending_key.into_rsk(alpha, &PARAMS);
		let mut rsk_bytes = [0u8; 32];
		rsk.write(&mut rsk_bytes[..]).map_err(|_| io::Error::InvalidData)?;

		let mut rvk_bytes = [0u8; 32];
		proof_output.rvk.write(&mut rvk_bytes[..]).map_err(|_| io::Error::InvalidData)?;

		let mut proof_bytes = [0u8; 192];
		proof_output.proof.write(&mut proof_bytes[..]).map_err(|_| io::Error::InvalidData)?;

		let mut b_address_sender = [0u8; 32];
		proof_output.address_sender.write(&mut b_address_sender[..]).map_err(|_| io::Error::InvalidData)?;

		let mut b_address_recipient = [0u8; 32];
		proof_output.address_recipient.write(&mut b_address_recipient[..]).map_err(|_| io::Error::InvalidData)?;

		let mut enc_amount_recipient = [0u8; 64];
		proof_output.cipher_val_r.write(&mut enc_amount_recipient[..]).map_err(|_| io::Error::InvalidData)?;

		let mut enc_amount_sender = [0u8; 64];
		proof_output.cipher_val_s.write(&mut enc_amount_sender[..]).map_err(|_| io::Error::InvalidData)?;

		let mut enc_fee_sender = [0u8; 64];
		proof_output.cipher_fee_s.write(&mut enc_fee_sender[..]).map_err(|_| io::Error::InvalidData)?;

		let tx = Transaction {
			proof: proof_bytes,
			rvk: rvk_bytes,
			address_sender: b_address_sender,
			address_recipient: b_address_recipient,
			enc_amount_recipient,
			enc_amount_sender,
			rsk: rsk_bytes,
			enc_fee: enc_fee_sender,
		};

		Ok(tx)
	}
}
