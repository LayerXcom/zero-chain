use bellman::groth16::{
    create_random_proof,
    verify_proof,
    Parameters,
    PreparedVerifyingKey,
    Proof,
};
use pairing::Field;
use rand::{Rand, Rng};
use scrypto::{
    jubjub::{
        JubjubEngine,
        FixedGenerators,
    },
    redjubjub::{
        PublicKey,
    },
};
use crate::circuit_transfer::Transfer;
use crate::primitives::{
    EncryptionKey,
    ProofGenerationKey,
};
use crate::elgamal::Ciphertext;

pub struct TransferProof<E: JubjubEngine> {
    pub proof: Proof<E>,
    pub rvk: PublicKey<E>, // re-randomization sig-verifying key
    pub address_sender: EncryptionKey<E>,
    pub address_recipient: EncryptionKey<E>,
    pub cipher_val_s: Ciphertext<E>,
    pub cipher_val_r: Ciphertext<E>,
    pub cipher_balance: Ciphertext<E>,
    pub cipher_fee_s: Ciphertext<E>
}

impl<E: JubjubEngine> TransferProof<E> {
    pub fn gen_proof<R: Rng>(
        value: u32,
        remaining_balance: u32,
        alpha: E::Fs,
        proving_key: &Parameters<E>,
        prepared_vk: &PreparedVerifyingKey<E>,
        proof_generation_key: ProofGenerationKey<E>,
        address_recipient: EncryptionKey<E>,
        ciphertext_balance: Ciphertext<E>,
        rng: &mut R,
        params: &E::Params,
        fee: u32,
    ) -> Result<Self, &'static str>
    {
        let randomness = E::Fs::rand(rng);

        let bdk = proof_generation_key.bdk();
        let ek_sender = proof_generation_key.into_encryption_key(params);

        let rvk = PublicKey(proof_generation_key.0.clone().into())
            .randomize(
                alpha,
                FixedGenerators::NoteCommitmentRandomness,
                params,
        );

        let instance = Transfer {
            params: params,
            value: Some(value),
            remaining_balance: Some(remaining_balance),
            randomness: Some(randomness.clone()),
            alpha: Some(alpha.clone()),
            proof_generation_key: Some(proof_generation_key.clone()),
            decryption_key: Some(bdk.clone()),
            pk_d_recipient: Some(address_recipient.0.clone()),
            encrypted_balance: Some(ciphertext_balance.clone()),
            fee: Some(fee),
        };

        // Crate proof
        let proof = create_random_proof(instance, proving_key, rng)
            .expect("proving should not fail");

        let mut public_input = [E::Fr::zero(); 16];

        let cipher_val_s = Ciphertext::encrypt(
            value,
            randomness,
            &ek_sender.0,
            FixedGenerators::NoteCommitmentRandomness,
            params
        );

        let cipher_val_r = Ciphertext::encrypt(
            value,
            randomness,
            &address_recipient.0,
            FixedGenerators::NoteCommitmentRandomness,
            params
        );

        let cipher_fee_s = Ciphertext::encrypt(
            fee,
            randomness,
            &ek_sender.0,
            FixedGenerators::NoteCommitmentRandomness,
            params
        );

        {
            let (x, y) = ek_sender.0.into_xy();
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
            let (x, y) = rvk.0.into_xy();
            public_input[14] = x;
            public_input[15] = y;
        }

        if let Err(_) = verify_proof(prepared_vk, &proof, &public_input[..]) {
            return Err("Invalid zk proof")
        }

        let transfer_proof = TransferProof {
            proof: proof,
            rvk: rvk,
            address_sender: ek_sender,
            address_recipient: address_recipient,
            cipher_val_s: cipher_val_s,
            cipher_val_r: cipher_val_r,
            cipher_balance: ciphertext_balance,
            cipher_fee_s: cipher_fee_s,
        };

        Ok(transfer_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng, Rng};
    use crate::primitives::{ProofGenerationKey, EncryptionKey};
    use scrypto::jubjub::{fs, ToUniform, JubjubParams, JubjubBls12};
    use crate::elgamal::elgamal_extend;
    use pairing::{PrimeField, bls12_381::Bls12};
    use std::path::Path;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use hex_literal::{hex, hex_impl};

    fn get_pk_and_vk() -> (Parameters<Bls12>, PreparedVerifyingKey<Bls12>) {
        let pk_path = Path::new("../../demo/cli/proving.params");
        let vk_path = Path::new("../../demo/cli/verification.params");

        let pk_file = File::open(&pk_path).unwrap();
        let vk_file = File::open(&vk_path).unwrap();

        let mut pk_reader = BufReader::new(pk_file);
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_pk = vec![];
        pk_reader.read_to_end(&mut buf_pk).unwrap();

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        let proving_key = Parameters::<Bls12>::read(&mut &buf_pk[..], true).unwrap();
        let prepared_vk = PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..]).unwrap();

        (proving_key, prepared_vk)
    }

    #[test]
    fn test_gen_proof() {
        let params = &JubjubBls12::new();
        let mut rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::NoteCommitmentRandomness;

        let value = 10 as u32;
        let remaining_balance = 30 as u32;
        let fee = 1 as u32;
        let balance = 100 as u32;
        let alpha = fs::Fs::rand(rng);

        let sender_ok = fs::Fs::rand(rng);
        let recipient_ok = fs::Fs::rand(rng);

        let proof_generation_key = ProofGenerationKey::<Bls12>::from_origin_key(&sender_ok, params);

        let pgk_sender = ProofGenerationKey::<Bls12>::from_origin_key(&sender_ok, params);
        let ek_recipient = EncryptionKey::<Bls12>::from_origin_key(&recipient_ok, params);
        let bdk = pgk_sender.bdk();

        let r_fs = fs::Fs::rand(rng);
        let public_key = params.generator(p_g).mul(bdk, params).into();
        let ciphertext_balance = Ciphertext::encrypt(balance, r_fs, &public_key, p_g, params);

        let (proving_key, prepared_vk) = get_pk_and_vk();

        let proofs = TransferProof::gen_proof(
            value,
            remaining_balance,
            alpha,
            &proving_key,
            &prepared_vk,
            proof_generation_key,
            ek_recipient,
            ciphertext_balance,
            &mut rng,
            params,
            fee,
        );

        assert!(proofs.is_ok());
    }

    #[test]
    fn test_read_proving_key() {
        let pk_path = Path::new("../../demo/cli/proving.params");

        let pk_file = File::open(&pk_path).unwrap();

        let mut pk_reader = BufReader::new(pk_file);
        println!("{:?}", pk_reader);
        let mut buf = vec![];

        pk_reader.read_to_end(&mut buf).unwrap();
        println!("{:?}", buf.len());

        let _proving_key = Parameters::<Bls12>::read(&mut &buf[..], true).unwrap();
    }
}
