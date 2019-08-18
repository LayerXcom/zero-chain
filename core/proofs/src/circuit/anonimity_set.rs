use bellman::{SynthesisError, ConstraintSystem};
use pairing::{Engine, PrimeField};
use scrypto::circuit::{
    boolean::{self, Boolean},
    ecc::{self, EdwardsPoint},
    num::AllocatedNum,
};
use scrypto::jubjub::{JubjubEngine, FixedGenerators};
use crate::{ProofGenerationKey, EncryptionKey, DecryptionKey};

pub struct EncKeySet<E: JubjubEngine>(Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> EncKeySet<E> {
    pub fn new() -> Self {
        unimplemented!();
    }

    pub fn push_sender<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        dec_key: Option<&DecryptionKey<E>>,
        params: &E::Params,
    ) -> Result<EdwardsPoint<E>, SynthesisError> {
        // dec_key_sender in circuit
        let dec_key_sender_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("dec_key_sender")),
            dec_key.map(|e| e.0)
        )?;

        // Ensure the validity of enc_key_sender
        let enc_key_sender_alloc = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute enc_key_sender")),
            FixedGenerators::NoteCommitmentRandomness,
            &dec_key_sender_bits,
            params
        )?;

        self.0.push(enc_key_sender_alloc.clone());

        Ok(enc_key_sender_alloc)
    }

    pub fn push_recipient<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        enc_key: Option<&EncryptionKey<E>>,
        params: &E::Params,
    ) -> Result<EdwardsPoint<E>, SynthesisError> {
        // Ensures recipient enc_key is on the curve
        let recipient_enc_key_bits = ecc::EdwardsPoint::witness(
            cs.namespace(|| "recipient enc_key witness"),
            enc_key.as_ref().map(|e| e.0.clone()),
            params
        )?;

        // Check the recipient enc_key is not small order
        recipient_enc_key_bits.assert_not_small_order(
            cs.namespace(|| "val_gl not small order"),
            params
        )?;

        self.0.push(recipient_enc_key_bits.clone());

        Ok(recipient_enc_key_bits)
    }

    pub fn push_decoys<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        enc_keys: Vec<EdwardsPoint<E>>,
        params: &E::Params
    ) -> Self {
        unimplemented!();
    }

    pub fn shuffle<P: PrimeField>(&self, randomnes: P) -> ShuffledEncKeySet<E> {
        unimplemented!();
    }
}

pub struct ShuffledEncKeySet<E: JubjubEngine>(Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> ShuffledEncKeySet<E> {
    pub fn inputize(&self) {
        unimplemented!();
    }
}

pub struct LeftCiphertextSet<E: Engine>(Vec<EdwardsPoint<E>>);


