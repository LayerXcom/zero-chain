use crate::{
	PARAMS,
	EncryptionKey,
	ProofGenerationKey,
	SpendingKey,
	prover::{ConfidentialProof, MultiEncKeys},
	elgamal,
};
use bellman::groth16::{Parameters, PreparedVerifyingKey};
use pairing::bls12_381::Bls12;
use pairing::Field;
use zpairing::io;
use scrypto::jubjub::{fs, edwards, PrimeOrder};
use rand::{Rng, Rand};

/// Transaction components which is needed to create a signed `UncheckedExtrinsic`.
pub struct Transaction{
    pub proof: [u8; 192],                // 192 bytes
    pub enc_key_sender: [u8; 32],        // 32 bytes
    pub enc_key_recipient: [u8; 32],     // 32 bytes
    pub enc_amount_recipient: [u8; 64],  // 64 bytes
	pub enc_amount_sender: [u8; 64],     // 64 bytes
	pub enc_fee: [u8; 64],			     // 64 bytes
	pub rsk: [u8; 32],                   // 32 bytes
	pub rvk: [u8; 32],                   // 32 bytes
	pub enc_balance: [u8; 64],           // 32 bytes
	pub nonce: [u8; 32],
}

impl Transaction {
    pub fn gen_tx<R: Rng>(
        value: u32,
        remaining_balance: u32,
        proving_key: &Parameters<Bls12>,
		prepared_vk: &PreparedVerifyingKey<Bls12>,
		enc_keys: &MultiEncKeys<Bls12>,
		spending_key: &SpendingKey<Bls12>,
        ciphertext_balance: &elgamal::Ciphertext<Bls12>,
		g_epoch: &edwards::Point<Bls12, PrimeOrder>,
		rng: &mut R,
		fee: u32,
    ) -> Result<Self, io::Error>
	{
		let alpha = fs::Fs::rand(rng);

		let proof_generation_key = ProofGenerationKey::from_spending_key(
			&spending_key,
			&*PARAMS
		);

		// Generate the zk proof
		let proof_output = ConfidentialProof::gen_proof(
			value,
			remaining_balance,
			fee,
			alpha,
			proving_key,
			prepared_vk,
			&proof_generation_key,
			enc_keys,
            ciphertext_balance,
			g_epoch,
			rng,
			&PARAMS,
		).expect("Should not be faild to generate a proof.");

		// TODO: Creating bridge_convert traits between std and no_std.

		// Generate the re-randomized sign key
		let mut rsk_bytes = [0u8; 32];
		spending_key
			.into_rsk(alpha)
			.write(&mut rsk_bytes[..])
			.map_err(|_| io::Error::InvalidData)?;

		let mut rvk_bytes = [0u8; 32];
		proof_output
			.rvk
			.write(&mut rvk_bytes[..])
			.map_err(|_| io::Error::InvalidData)?;

		let mut proof_bytes = [0u8; 192];
		proof_output
			.proof
			.write(&mut proof_bytes[..])
			.map_err(|_| io::Error::InvalidData)?;

		let mut enc_key_sender = [0u8; 32];
		proof_output
			.enc_key_sender
			.write(&mut enc_key_sender[..])
			.map_err(|_| io::Error::InvalidData)?;

		let mut enc_key_recipient = [0u8; 32];
		proof_output
			.enc_keys.recipient
			.write(&mut enc_key_recipient[..])
			.map_err(|_| io::Error::InvalidData)?;

		let mut enc_amount_recipient = [0u8; 64];
		proof_output
			.multi_ciphertexts.recipient
			.write(&mut enc_amount_recipient[..])
			.map_err(|_| io::Error::InvalidData)?;

		let mut enc_amount_sender = [0u8; 64];
		proof_output
			.multi_ciphertexts.sender
			.write(&mut enc_amount_sender[..])
			.map_err(|_| io::Error::InvalidData)?;

		let mut enc_fee = [0u8; 64];
		proof_output
			.multi_ciphertexts.fee
			.write(&mut enc_fee[..])
			.map_err(|_| io::Error::InvalidData)?;

		let mut enc_balance = [0u8; 64];
		proof_output.cipher_balance
			.write(&mut enc_balance[..])
			.map_err(|_| io::Error::InvalidData)?;

		let mut nonce = [0u8; 32];
		proof_output
			.nonce
			.write(&mut nonce[..])
			.map_err(|_| io::Error::InvalidData)?;

		let tx = Transaction {
			proof: proof_bytes,
			rvk: rvk_bytes,
			enc_key_sender,
			enc_key_recipient,
			enc_amount_recipient,
			enc_amount_sender,
			rsk: rsk_bytes,
			enc_fee,
			enc_balance,
			nonce,
		};

		Ok(tx)
	}
}
