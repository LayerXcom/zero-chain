//! This module contains a circuit implementation for anonymous transfer.

use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit,
};
use scrypto::jubjub::{
    JubjubEngine,
    FixedGenerators,
};
use crate::{ProofGenerationKey, EncryptionKey, DecryptionKey};
use scrypto::circuit::{
    boolean::{self, Boolean, AllocatedBit},
    ecc::{self, EdwardsPoint},
    num::AllocatedNum,
};
use scrypto::jubjub::{edwards, PrimeOrder};
use crate::{elgamal::Ciphertext, Assignment, Nonce};
use super::range_check::u32_into_bit_vec_le;
use super::anonimity_set::*;
use super::utils::*;

pub struct AnonymousTransfer<'a, E: JubjubEngine> {
    params: &'a E::Params,
    amount: Option<u32>,
    remaining_balance: Option<u32>,
    s_index: Option<usize>,
    t_index: Option<usize>,
    randomness: Option<&'a E::Fs>,
    alpha: Option<&'a E::Fs>,
    proof_generation_key: Option<&'a ProofGenerationKey<E>>,
    dec_key: Option<&'a DecryptionKey<E>>,
    enc_key_recipient: Option<&'a EncryptionKey<E>>,
    enc_key_decoys: &'a [Option<EncryptionKey<E>>],
    enc_balance_sendder: Option<&'a Ciphertext<E>>,
    enc_balance_recipient: Option<&'a Ciphertext<E>>,
    enc_balances_decoys: &'a [Option<Ciphertext<E>>],
    g_epoch: Option<&'a edwards::Point<E, PrimeOrder>>,
}

impl<'a, E: JubjubEngine> Circuit<E> for AnonymousTransfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let params = self.params;

        // Ensure the amount is u32.
        let amount_bits = u32_into_bit_vec_le(
            cs.namespace(|| "range proof of amount"),
            self.amount
        )?;

        // Multiply the amount to the base point same as FixedGenerators::ElGamal.
        let amount_g = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the amount in the exponent")),
            FixedGenerators::NoteCommitmentRandomness,
            &amount_bits,
            params
        )?;

        let neg_amount_g = negate_point(
            cs.namespace(|| "negate amount_g"),
            &amount_g,
            params
        )?;

        // Ensure the remaining balance is u32.
        let remaining_balance_bits = u32_into_bit_vec_le(
            cs.namespace(|| "range proof of remaining_balance"),
            self.remaining_balance
        )?;

        let zero_p = EdwardsPoint::<E>::witness::<PrimeOrder, _>(
            cs.namespace(|| "initialize acc."),
            Some(edwards::Point::zero()),
            params,
        )?;

        let s_bins = Binary::new(
            cs.namespace(|| "new s binary"),
            ST::S,
            self.s_index
        )?;

        let t_bins = Binary::new(
            cs.namespace(|| "new t binary"),
            ST::T,
            self.t_index
        )?;

        // dec_key in circuit
        let dec_key_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("dec_key")),
            self.dec_key.map(|e| e.0)
        )?;

        let mut enc_key_set = EncKeySet::new(ANONIMITY_SIZE);

        enc_key_set
            .push_enckeys(
                cs.namespace(|| "push enckeys"),
                &dec_key_bits,
                self.enc_key_recipient,
                self.enc_key_decoys,
                self.s_index,
                self.t_index,
                params
            )?;

        let expected_enc_key_sender = s_bins.edwards_add_fold(
            cs.namespace(|| "add folded enc keys"),
            &enc_key_set.0,
            zero_p.clone(),
            params
        )?;

        if let Some(i) = self.s_index {
            eq_edwards_points(
                cs.namespace(|| "equal enc_key_sender"),
                &expected_enc_key_sender,
                &enc_key_set.0[i]
            )?;
        }

        let enc_keys_mul_random = enc_key_set.gen_enc_keys_mul_random(
            cs.namespace(|| "generate enc keys multipled by randomness"),
            self.randomness,
            params
        )?;

        let enc_keys_mul_random_add_fold = s_bins.edwards_add_fold(
            cs.namespace(|| "add folded enc keys mul random"),
            &enc_keys_mul_random.0,
            zero_p.clone(),
            params
        )?;

        let expected_ciphertext_left_s_i = enc_keys_mul_random_add_fold.add(
            cs.namespace(|| "compute ciphertext left s_i"),
            &amount_g,
            params
        )?;

        let ciphertext_left_set= enc_keys_mul_random.gen_left_ciphertexts(
            cs.namespace(|| "compute left ciphertexts of s_i"),
            &amount_g,
            &neg_amount_g,
            self.s_index,
            self.t_index,
            zero_p.clone(),
            params
        )?;

        let ciphertext_left_s_i = s_bins.edwards_add_fold(
            cs.namespace(|| "add folded left ciphertext based in s_i"),
            &ciphertext_left_set.0,
            zero_p.clone(),
            params
        )?;

        eq_edwards_points(
            cs.namespace(|| "left ciphertext equals"),
            &expected_ciphertext_left_s_i,
            &ciphertext_left_s_i
        )?;

        let nor_st_bins = s_bins.nor(cs.namespace(|| "s_i nor t_i"), &t_bins)?;



        // Generate the randomness for elgamal encryption into the circuit
        let randomness_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "randomness_bits"),
            self.randomness.map(|e| *e)
        )?;

        // Multiply the randomness to the base point same as FixedGenerators::ElGamal.
        let right_ciphertext = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the right elgamal component")),
            FixedGenerators::NoteCommitmentRandomness,
            &randomness_bits,
            params
        )?;

        right_ciphertext
            .inputize(cs.namespace(|| "inputize right ciphertext."))?;


        rvk_inputize(
            cs.namespace(|| "inputize rvk"),
            self.proof_generation_key,
            self.alpha,
            params
        )?;

        g_epoch_nonce_inputize(
            cs.namespace(|| "inputize g_epoch and nonce"),
            self.g_epoch,
            &dec_key_bits,
            params
        )?;


        Ok(())
    }
}






#[cfg(test)]
mod tests {
    use super::*;
    use pairing::{bls12_381::{Bls12, Fr}, Field};
    use rand::{SeedableRng, Rng, XorShiftRng, Rand};
    use crate::EncryptionKey;
    use crate::circuit::TestConstraintSystem;
    use scrypto::jubjub::{JubjubBls12, fs::Fs, JubjubParams};

    fn neg_encrypt(
        amount: u32,
        randomness: &Fs,
        enc_key: &EncryptionKey<Bls12>,
        p_g: FixedGenerators,
        params: &JubjubBls12
    ) -> Ciphertext<Bls12> {
        let right = params.generator(p_g).mul(*randomness, params);
        let mut v_point = params.generator(p_g).mul(amount as u64, params);
        v_point.negate();
        let r_point = enc_key.0.mul(*randomness, params);
        let left = v_point.add(&r_point, params);

        Ciphertext {
            left,
            right,
        }
    }

    fn test_based_amount(amount: u32) {
        // constants
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::NoteCommitmentRandomness;
        let current_balance = 100;
        let remaining_balance = current_balance - amount;

        // randomness
        let seed_sender: [u8; 32] = rng.gen();
        let seed_recipient: [u8; 32] = rng.gen();
        let alpha = Fs::rand(rng);
        let randomness_balance = Fs::rand(rng);
        let randomness_amount = Fs::rand(rng);
        let randomness_balanace_sender = Fs::rand(rng);
        let randomness_balanace_recipient = Fs::rand(rng);
        let remaining_balance_recipient: u32 = rng.gen();
        let s_index: usize = rng.gen_range(0, ANONIMITY_SIZE+1);
        let mut t_index: usize;
        loop {
            t_index = rng.gen_range(0, ANONIMITY_SIZE+1);
            if t_index != s_index {
                break;
            }
        }
        let seed_decoys_iter = rng.gen_iter::<[u8; 32]>().take(DECOY_SIZE);
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let randomness_amounts_iter = rng.gen_iter::<Fs>().take(DECOY_SIZE);
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let randomness_balances_iter = rng.gen_iter::<Fs>().take(DECOY_SIZE);
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let remaining_balance_iter = rng.gen_iter::<u32>().take(DECOY_SIZE);
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // keys
        let proof_gen_key = ProofGenerationKey::<Bls12>::from_seed(&seed_sender[..], params);
        let dec_key = proof_gen_key.into_decryption_key().unwrap();
        let enc_key_sender = EncryptionKey::from_decryption_key(&dec_key, params);
        let enc_key_recipient = EncryptionKey::<Bls12>::from_seed(&seed_recipient, params).unwrap();
        let enc_keys_decoy = seed_decoys_iter.map(|e| EncryptionKey::from_seed(&e, params).ok()).collect::<Vec<Option<EncryptionKey<Bls12>>>>();
        let enc_key_sender_xy = enc_key_sender.0.into_xy();
        let enc_key_recipient_xy = enc_key_recipient.0.into_xy();

        // ciphertexts
        let ciphertext_amount_sender = Ciphertext::encrypt(amount, &randomness_amount, &enc_key_sender, p_g, params);
        let ciphertext_amount_recipient = neg_encrypt(amount, &randomness_amount, &enc_key_recipient, p_g, params);
        let ciphertexts_amount_decoy = enc_keys_decoy.iter().zip(randomness_amounts_iter).map(|(e, r)| Ciphertext::encrypt(0, &r, e.as_ref().unwrap(), p_g, params));
        let ciphertext_balance_sender = Ciphertext::encrypt(remaining_balance, &randomness_balanace_sender, &enc_key_sender, p_g, params);
        let ciphertext_balance_recipient = Ciphertext::encrypt(remaining_balance_recipient, &randomness_balanace_recipient, &enc_key_recipient, p_g, params);
        let cipherrtexts_balances = enc_keys_decoy.iter().zip(remaining_balance_iter).zip(randomness_balances_iter).map(|((e, a), r)| Some(Ciphertext::encrypt(a, &r, e.as_ref().unwrap(), p_g, params)));

        let rvk = proof_gen_key.into_rvk(alpha, params).0.into_xy();
        let g_epoch = edwards::Point::<Bls12, _>::rand(rng, params).mul_by_cofactor(params);
        let g_epoch_xy = g_epoch.into_xy();
        let nonce = g_epoch.mul(dec_key.0, params).into_xy();

        let mut cs = TestConstraintSystem::<Bls12>::new();
        let instance = AnonymousTransfer {
            params,
            amount: Some(amount),
            remaining_balance: Some(remaining_balance),
            s_index: Some(s_index),
            t_index: Some(t_index),
            randomness: Some(&randomness_amount),
            alpha: Some(&alpha),
            proof_generation_key: Some(&proof_gen_key),
            dec_key: Some(&dec_key),
            enc_key_recipient: Some(&enc_key_recipient),
            enc_key_decoys: &enc_keys_decoy,
            enc_balance_sendder: Some(&ciphertext_balance_sender),
            enc_balance_recipient: Some(&ciphertext_balance_recipient),
            enc_balances_decoys: &cipherrtexts_balances.collect::<Vec<Option<Ciphertext<Bls12>>>>(),
            g_epoch: Some(&g_epoch),
        };

        instance.synthesize(&mut cs).unwrap();
        assert!(cs.is_satisfied());
        println!("num: {:?}", cs.num_constraints());
        println!("hash: {:?}", cs.hash());
    }

    #[test]
    fn test_circuit_anonymous_transfer_valid() {
        test_based_amount(10);
    }
}
