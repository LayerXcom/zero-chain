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

pub const ANONIMITY_SIZE: usize = 11;

pub struct AnonymousTransfer<'a, E: JubjubEngine> {
    params: &'a E::Params,
    amount: Option<u32>,
    remaining_balance: Option<u32>,
    s_idnex: Option<usize>,
    t_index: Option<usize>,
    randomness: Option<&'a E::Fs>,
    alpha: Option<&'a E::Fs>,
    proof_generation_key: Option<&'a ProofGenerationKey<E>>,
    dec_key_sender: Option<&'a DecryptionKey<E>>,
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

        // Ensure the remaining balance is u32.
        let remaining_balance_bits = u32_into_bit_vec_le(
            cs.namespace(|| "range proof of remaining_balance"),
            self.remaining_balance
        )?;

        




        let mut enc_key_set = EncKeySet::new(ANONIMITY_SIZE);

        enc_key_set
            .push_sender(
                cs.namespace(|| "push sender to enckey set"),
                self.dec_key_sender,
                params
            )?;

        enc_key_set
            .push_recipient(
                cs.namespace(|| "push recipient to enckey set"),
                self.enc_key_recipient,
                params
            )?;

        enc_key_set
            .push_decoys(
                cs.namespace(|| "push decoys to enckey set"),
                self.enc_key_decoys,
                params
            )?;

        let shuffled_enc_keys = enc_key_set
            .shuffle(self.randomness);

        shuffled_enc_keys
            .inputize(cs.namespace(|| "inputize shuffled enc keys."))?;


        let mut left_ciphertexts = LeftCiphertextSet::new(ANONIMITY_SIZE);

        // Generate the randomness for elgamal encryption into the circuit
        let randomness_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "randomness_bits"),
            self.randomness.map(|e| *e)
        )?;

        left_ciphertexts.from_enc_keys(
            cs.namespace(|| "create left ciphertext set"),
            shuffled_enc_keys,
            &amount_bits,
            &randomness_bits,
            params
            )?;

        left_ciphertexts
            .inputize(cs.namespace(|| "inputize shuffled left ciphertext set."))?;

        // Multiply the randomness to the base point same as FixedGenerators::ElGamal.
        let right_ciphertext = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the right elgamal component")),
            FixedGenerators::NoteCommitmentRandomness,
            &randomness_bits,
            params
        )?;

        right_ciphertext
            .inputize(cs.namespace(|| "inputize right ciphertext."))?;




        Ok(())
    }
}






#[cfg(test)]
mod tests {
    use super::*;

}
