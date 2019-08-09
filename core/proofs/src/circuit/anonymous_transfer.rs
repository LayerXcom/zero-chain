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
use crate::keys::{ProofGenerationKey, EncryptionKey, DecryptionKey};
use scrypto::circuit::{
    boolean::{self, Boolean},
    ecc::{self, EdwardsPoint},
    num::AllocatedNum,
};
use crate::{elgamal::Ciphertext, Assignment};

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
