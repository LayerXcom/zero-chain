use bellman::{SynthesisError, ConstraintSystem};
use pairing::{Engine, PrimeField};
use scrypto::circuit::{
    boolean::{self, Boolean, AllocatedBit},
    ecc::{self, EdwardsPoint},
    num::AllocatedNum,
};
use scrypto::jubjub::{JubjubEngine, FixedGenerators, edwards, PrimeOrder};
use crate::{ProofGenerationKey, EncryptionKey, DecryptionKey};
use std::fmt;

pub const ANONIMITY_SIZE: usize = 11;

pub enum ST {
    S,
    T,
}

impl fmt::Display for ST {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ST::S => write!(f, "s"),
            ST::T => write!(f, "t"),
        }
    }
}

#[derive(Clone)]
pub struct Binary(Vec<Boolean>);

impl Binary {
    pub fn new<E, CS>(
        mut cs: CS,
        st: ST,
        index: Option<usize>
    ) -> Result<Self, SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        let mut binaries = [false; ANONIMITY_SIZE];
        if let Some(i) = index {
            binaries[i] = true;
        }

        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);
        for (i, b) in binaries.into_iter().enumerate() {
            acc[i] = Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("{} binary {}", st, i)),
                    Some(*b))?
                );
        }

        Ok(Binary(acc))
    }

    pub fn or<E, CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        assert_eq!(self.len(), other.len());

        unimplemented!();
    }

    pub fn xor<E, CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        assert_eq!(self.len(), other.len());

        unimplemented!();
    }

    pub fn edwards_add_fold<E, CS>(
        &self,
        mut cs: CS,
        points: &[EdwardsPoint<E>],
        params: &E::Params,
    ) -> Result<EdwardsPoint<E>, SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        assert_eq!(self.len(), points.len());

        let mut acc = EdwardsPoint::<E>::witness::<PrimeOrder, _>(
            cs.namespace(|| "initialize acc."),
            Some(edwards::Point::zero()),
            params,
        )?;
        for (i, (b, p)) in self.0.iter().zip(points.iter()).enumerate() {
            let selected_point = p.conditionally_select(
                cs.namespace(|| format!("conditionally select p_{} depending on b", i)),
                b
            )?;

            let tmp = acc.add(
                cs.namespace(|| format!("add conditionally selected p_{}", i)),
                &selected_point,
                params,
            )?;

            acc = tmp
        }

        Ok(acc)
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}


pub struct EncKeySet<E: JubjubEngine>(Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> EncKeySet<E> {
    pub fn new(capacity: usize) -> Self {
        EncKeySet(Vec::with_capacity(capacity))
    }

    pub fn push_sender<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        dec_key: Option<&DecryptionKey<E>>,
        params: &E::Params,
    ) -> Result<(), SynthesisError> {
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

        Ok(())
    }

    pub fn push_recipient<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        enc_key: Option<&EncryptionKey<E>>,
        params: &E::Params,
    ) -> Result<(), SynthesisError> {
        // Ensures recipient enc_key is on the curve
        let enc_key_recipient_bits = ecc::EdwardsPoint::witness(
            cs.namespace(|| "recipient enc_key witness"),
            enc_key.as_ref().map(|e| e.0.clone()),
            params
        )?;

        // Check the recipient enc_key is not small order
        enc_key_recipient_bits.assert_not_small_order(
            cs.namespace(|| "val_gl not small order"),
            params
        )?;

        self.0.push(enc_key_recipient_bits.clone());
        Ok(())
    }

    pub fn push_decoys<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        enc_keys: &[Option<EncryptionKey<E>>],
        params: &E::Params
    ) -> Result<(), SynthesisError> {
        for (i, e) in enc_keys.into_iter().enumerate() {
            let decoy_bits = ecc::EdwardsPoint::witness(
                cs.namespace(|| format!("decoy {} enc_key witness", i)),
                e.as_ref().map(|e| e.0.clone()),
                params
            )?;

            self.0.push(decoy_bits);
        }

        Ok(())
    }

    pub fn shuffle<P: PrimeField>(&self, randomnes: Option<&P>) -> ShuffledEncKeySet<E> {
        unimplemented!();
    }
}

pub struct ShuffledEncKeySet<E: JubjubEngine>(Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> ShuffledEncKeySet<E> {
    pub fn inputize<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS
    ) -> Result<(), SynthesisError> {
        for (i, e) in self.0.iter().enumerate() {
            e.inputize(cs.namespace(|| format!("inputize enc keys {}", i)))?;
        }

        Ok(())
    }
}

pub struct LeftCiphertextSet<E: JubjubEngine>(Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> LeftCiphertextSet<E> {
    pub fn new(capacity: usize) -> Self {
        LeftCiphertextSet(Vec::with_capacity(capacity))
    }

    pub fn from_enc_keys<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        enc_keys: ShuffledEncKeySet<E>,
        amount_bits: &[Boolean],
        randomness_bits: &[Boolean],
        params: &E::Params
    ) -> Result<(), SynthesisError> {

        // Multiply the amount to the base point same as FixedGenerators::ElGamal.
        let amount_g = ecc::fixed_base_multiplication(
            cs.namespace(|| "compute the amount in the exponent"),
            FixedGenerators::NoteCommitmentRandomness,
            amount_bits,
            params
        )?;

        for (i, e) in enc_keys.0.into_iter().enumerate() {
            let val_rlr = e.mul(
                cs.namespace(|| format!("compute {} amount cipher component", i)),
                randomness_bits,
                params
            )?;

            let c_left = amount_g.add(
                cs.namespace(|| format!("computation {} left ciphertext", i)),
                &val_rlr,
                params
            )?;

            self.0.push(c_left);
        }

        Ok(())
    }

    pub fn inputize<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS
    ) -> Result<(), SynthesisError> {
        for (i, e) in self.0.iter().enumerate() {
            e.inputize(cs.namespace(|| format!("inputize left ciphertexts {}", i)))?;
        }

        Ok(())
    }
}
