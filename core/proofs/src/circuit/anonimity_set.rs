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
pub const DECOY_SIZE: usize = ANONIMITY_SIZE - 2;

pub enum AnonimityIndexes {
    Sender(usize),
    Recipient(usize),
    Decoys([usize; DECOY_SIZE])
}

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
            let tmp = Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("{} binary {}", st, i)),
                Some(*b))?
            );
            acc.push(tmp);
        }

        Ok(Binary(acc))
    }

    // (1 - s_i)(1 - t_i)
    // iff s:0 * t:0 = 1
    // TODO:
    pub fn or<E, CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        assert_eq!(self.len(), other.len());

        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);
        for i in 0..self.len() {
            let tmp = Boolean::xor( // TODO:
                cs.namespace(|| format!("{} xor binary", i)),
                &self.0[i],
                &other.0[i]
            )?;
            acc.push(tmp);
        }

        Ok(Binary(acc))
    }

    // s_i + t_i
    // 1 + 0 = 1 -> sender
    // 0 + 1 = 1 -> recipient
    // 0 + 0 = 0
    // 1 + 1 = 0
    pub fn xor<E, CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        assert_eq!(self.len(), other.len());

        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);
        for i in 0..self.len() {
            let tmp = Boolean::xor(
                cs.namespace(|| format!("{} xor binary", i)),
                &self.0[i],
                &other.0[i]
            )?;
            acc.push(tmp);
        }

        Ok(Binary(acc))
    }

    pub fn edwards_add_fold<E, CS>(
        &self,
        mut cs: CS,
        points: &[EdwardsPoint<E>],
        recipient_op: &RecipientOp<E>,
        zero_p: EdwardsPoint<E>,
        params: &E::Params,
    ) -> Result<EdwardsPoint<E>, SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        assert_eq!(self.len(), points.len());
        let mut acc = zero_p;

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

pub enum RecipientOp<E: JubjubEngine> {
    Add(EdwardsPoint<E>),
    Remove(usize),
    None,
}

pub struct EncKeySet<E: JubjubEngine>(pub(crate) Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> EncKeySet<E> {
    pub fn new(capacity: usize) -> Self {
        EncKeySet(Vec::with_capacity(capacity))
    }

    pub fn push_enckeys<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        dec_key: Option<&DecryptionKey<E>>,
        enc_key_recipient: Option<&EncryptionKey<E>>,
        enc_keys_decoy: &[Option<EncryptionKey<E>>],
        s_index: Option<usize>,
        t_index: Option<usize>,
        params: &E::Params,
    ) -> Result<(), SynthesisError> {
        // dec_key_sender in circuit
        let dec_key_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("dec_key_sender")),
            dec_key.map(|e| e.0)
        )?;

        // Ensure the validity of enc_key_sender
        let enc_key_sender_bits = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute enc_key_sender")),
            FixedGenerators::NoteCommitmentRandomness,
            &dec_key_bits,
            params
        )?;

        // Ensures recipient enc_key is on the curve
        let enc_key_recipient_bits = ecc::EdwardsPoint::witness(
            cs.namespace(|| "recipient enc_key witness"),
            enc_key_recipient.as_ref().map(|e| e.0.clone()),
            params
        )?;

        // Check the recipient enc_key is not small order
        enc_key_recipient_bits.assert_not_small_order(
            cs.namespace(|| "val_gl not small order"),
            params
        )?;

        let mut decoy_iter = enc_keys_decoy.iter().enumerate().map(|(i, e)| {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| format!("decoy {} enc_key witness", i)),
                e.as_ref().map(|e| e.0.clone()),
                params
            ).unwrap()
        });

        // TODO: Rmove clone and unwrap
        for i in 0..ANONIMITY_SIZE {
            if Some(i) == s_index {
                self.0.push(enc_key_sender_bits.clone());
            } else if Some(i) == t_index {
                self.0.push(enc_key_recipient_bits.clone());
            } else {
                self.0.push(decoy_iter.next().unwrap())
            }
        }

        Ok(())
    }

    pub fn gen_enc_keys_mul_random<CS>(
        &self,
        mut cs: CS,
        randomness: Option<&E::Fs>,
        params: &E::Params
    ) -> Result<EncKeysMulRandom<E>, SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        // Generate the randomness for elgamal encryption into the circuit
        let randomness_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("randomness_bits")),
            randomness.map(|e| *e)
        )?;

        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);
        for i in 0..self.0.len() {
            // Generate the randomness * enc_keys in circuit
            let tmp = self.0[i].mul(
                cs.namespace(|| format!("randomness mul enc_key_{}", i)),
                &randomness_bits,
                params
            )?;
            acc.push(tmp);
        }

        Ok(EncKeysMulRandom(acc))
    }

    pub fn inputize<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        for (i, e) in self.0.iter().enumerate() {
            e.inputize(cs.namespace(|| format!("inputize enc keys {}", i)))?;
        }

        Ok(())
    }
}

pub struct EncKeysMulRandom<E: JubjubEngine>(pub(crate) Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> EncKeysMulRandom<E> {
    pub fn gen_left_ciphertexts<CS>(
        &self,
        mut cs: CS,
        amount_g: &EdwardsPoint<E>,
        s_index: Option<usize>,
        t_index: Option<usize>,
        zero_p: EdwardsPoint<E>,
        params: &E::Params,
    ) -> Result<LeftCiphertexts<E>, SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        assert_eq!(self.0.len(), ANONIMITY_SIZE);
        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);

        for i in 0..self.0.len() {
            if Some(i) == s_index {
                let tmp = amount_g.add(
                    cs.namespace(|| "sender's left ciphertext"),
                    &self.0[i],
                    params
                )?;
                acc.push(tmp);
            } else if Some(i) == t_index {
                let tmp = amount_g.add(
                    cs.namespace(|| "recipient's left ciphertext"),
                    &self.0[i],
                    params
                )?;
                acc.push(tmp);
            } else {
                let tmp = zero_p.add(
                    cs.namespace(|| format!("decoy_{} left ciphertext", i)),
                    &self.0[i],
                    params
                )?;
                acc.push(tmp);
            }
        }

        Ok(LeftCiphertexts(acc))
    }
}

pub struct LeftCiphertexts<E: JubjubEngine>(pub(crate) Vec<EdwardsPoint<E>>);


