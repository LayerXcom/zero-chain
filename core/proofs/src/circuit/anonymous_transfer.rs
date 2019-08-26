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

pub const ANONIMITY_SIZE: usize = 11;

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
    encrypted_balance: Option<&'a Ciphertext<E>>,
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
            &RecipientOp::None,
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
            &RecipientOp::None,
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
            self.s_index,
            self.t_index,
            zero_p.clone(),
            params
        )?;

        let ciphertext_left_s_i = s_bins.edwards_add_fold(
            cs.namespace(|| "add folded left ciphertext based in s_i"),
            &ciphertext_left_set.0,
            &RecipientOp::None,
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

}
