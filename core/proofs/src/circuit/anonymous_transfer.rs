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
    boolean::{self, Boolean},
    ecc::{self, EdwardsPoint},
    num::AllocatedNum,
};
use scrypto::jubjub::{edwards, PrimeOrder};
use crate::{elgamal::Ciphertext, Assignment, Nonce};
use super::range_check::u32_into_bit_vec_le;


// Non-decoy-index is defined over 00 to 99 to represent which enc_keys are not decoys.
// First digit is for sender's index in the list of encryption keys and
// second one is for recipient's.
// The range is enough for representing non-decoys-index because
// the entire set of encryption keys are limited with 10.
pub struct AnonymousTransfer<'a, E: JubjubEngine> {
    params: &'a E::Params,
    amount: Option<u32>,
    remaining_balance: Option<u32>,
    randomness: Option<&'a E::Fs>,
    alpha: Option<&'a E::Fs>,
    proof_generation_key: Option<&'a ProofGenerationKey<E>>,
    dec_key_sender: Option<&'a DecryptionKey<E>>,
    enc_key_recipient: Option<EncryptionKey<E>>,
    enc_key_decoys: Option<Vec<EncryptionKey<E>>>,
    encrypted_balance: Option<&'a Ciphertext<E>>,
    fee: Option<u32>,
    g_epoch: Option<&'a edwards::Point<E, PrimeOrder>>,
    // non_decoy_index: Option<u32>,
}

impl<'a, E: JubjubEngine> Circuit<E> for AnonymousTransfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let params = self.params;



        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

}
