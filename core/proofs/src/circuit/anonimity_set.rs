use bellman::{SynthesisError, ConstraintSystem};
use scrypto::circuit::{
    boolean::{self, Boolean, AllocatedBit},
    ecc::{self, EdwardsPoint},
};
use scrypto::jubjub::{JubjubEngine, FixedGenerators};
use crate::{EncryptionKey, elgamal};
use super::utils::{eq_edwards_points, negate_point};
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

    pub fn ensure_total_one<E, CS>(
        &self,
        mut cs: CS,
        true_index: Option<usize>
    ) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>
    {
        unimplemented!();
    }

    // (1 - s_i)(1 - t_i)
    // 1 + 0 -> 0
    // 0 + 1 -> 0
    // 0 + 0 -> 1 => non-sender, non-recipient
    // 1 + 1 -> 0
    // so, iff s:0 * t:0 = 1
    // Calculates `(NOT a) AND (NOT b)`
    pub fn nor<E, CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        assert_eq!(self.len(), other.len());

        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);
        for i in 0..self.len() {
            let tmp = Boolean::and(
                cs.namespace(|| format!("{} nor binary", i)),
                &self.0[i].not(),
                &other.0[i].not()
            )?;
            acc.push(tmp);
        }

        Ok(Binary(acc))
    }

    // s_i + t_i
    // 1 + 0 -> 1 => sender
    // 0 + 1 -> 1 => recipient
    // 0 + 0 -> 0
    // 1 + 1 -> 0
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

    pub fn conditionally_equals<E, CS>(
        &self,
        mut cs: CS,
        a_points: &[EdwardsPoint<E>],
        b_points: &[EdwardsPoint<E>]
    ) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        assert_eq!(self.len(), a_points.len());
        assert_eq!(self.len(), b_points.len());

        for (i, (a, b)) in a_points.iter().zip(b_points.iter()).enumerate() {
            let c_a = a.conditionally_select(
                cs.namespace(|| format!("conditionally select a_{}", i)),
                &self.0[i]
            )?;
            let c_b = b.conditionally_select(
                cs.namespace(|| format!("conditionally select b_{}", i)),
                &self.0[i]
            )?;

            eq_edwards_points(
                cs.namespace(|| format!("equal ca_{} and cb", i)),
                &c_a,
                &c_b
            )?;
        }

        Ok(())
    }

    pub fn edwards_add_fold<E, CS>(
        &self,
        mut cs: CS,
        points: &[EdwardsPoint<E>],
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

pub struct EncKeySet<E: JubjubEngine>(pub(crate) Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> EncKeySet<E> {
    pub fn new(capacity: usize) -> Self {
        EncKeySet(Vec::with_capacity(capacity))
    }

    pub fn push_enckeys<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        dec_key_bits: &[Boolean],
        enc_key_recipient: Option<&EncryptionKey<E>>,
        enc_keys_decoy: &[Option<EncryptionKey<E>>],
        s_index: Option<usize>,
        t_index: Option<usize>,
        params: &E::Params,
    ) -> Result<(), SynthesisError> {
        // Ensure the validity of enc_key_sender
        let enc_key_sender_bits = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute enc_key_sender")),
            FixedGenerators::NoteCommitmentRandomness,
            dec_key_bits,
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
        neg_amount_g: &EdwardsPoint<E>,
        s_index: Option<usize>,
        t_index: Option<usize>,
        zero_p: EdwardsPoint<E>,
        params: &E::Params,
    ) -> Result<LeftAmountCiphertexts<E>, SynthesisError>
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
                let tmp = neg_amount_g.add(
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

        Ok(LeftAmountCiphertexts(acc))
    }
}

pub struct LeftAmountCiphertexts<E: JubjubEngine>(pub(crate) Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> LeftAmountCiphertexts<E> {
    pub fn neg_each<CS>(&self, mut cs: CS, params: &E::Params) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        assert_eq!(self.0.len(), ANONIMITY_SIZE);

        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);
        for i in 0..self.0.len() {
            let tmp = negate_point(
                cs.namespace(|| format!("negate left amount ciphertexts {}", i)),
                &self.0[i],
                params
            )?;
            acc.push(tmp);
        }

        Ok(LeftAmountCiphertexts(acc))
    }

    pub fn inputize<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        for (i, e) in self.0.iter().enumerate() {
            e.inputize(cs.namespace(|| format!("inputize left ciphertexts {}", i)))?;
        }

        Ok(())
    }
}

pub struct LeftBalanceCiphertexts<E: JubjubEngine>(pub(crate) Vec<EdwardsPoint<E>>);
pub struct RightBalanceCiphertexts<E: JubjubEngine>(pub(crate) Vec<EdwardsPoint<E>>);

impl<E: JubjubEngine> LeftBalanceCiphertexts<E> {
    pub fn witness<Order, CS>(
        mut cs: CS,
        c: &[Option<elgamal::Ciphertext<E>>],
        params: &E::Params
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        assert_eq!(c.len(), ANONIMITY_SIZE);

        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);
        for i in 0..c.len() {
            let tmp = EdwardsPoint::witness(
                cs.namespace(|| format!("left ciphertext {} witness", i)),
                c[i].as_ref().map(|e| e.clone().left),
                params
            )?;
            acc.push(tmp);
        }

        Ok(LeftBalanceCiphertexts(acc))
    }

    pub fn add_each<CS>(
        &self,
        mut cs: CS,
        left_ac: &LeftAmountCiphertexts<E>,
        params: &E::Params
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        assert_eq!(self.0.len(), left_ac.0.len());

        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);
        for i in 0..self.0.len() {
            let tmp = self.0[i].add(
                cs.namespace(|| format!("add each left ciphertexts {}", i)),
                &left_ac.0[i],
                params
            )?;
            acc.push(tmp);
        }

        Ok(LeftBalanceCiphertexts(acc))
    }

    pub fn inputize<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        for (i, e) in self.0.iter().enumerate() {
            e.inputize(cs.namespace(|| format!("inputize left balance ciphertexts {}", i)))?;
        }

        Ok(())
    }
}

impl<E: JubjubEngine> RightBalanceCiphertexts<E> {
    pub fn witness<Order, CS>(
        mut cs: CS,
        c: &[Option<elgamal::Ciphertext<E>>],
        params: &E::Params
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        assert_eq!(c.len(), ANONIMITY_SIZE);

        let mut acc = Vec::with_capacity(ANONIMITY_SIZE);
        for i in 0..c.len() {
            let tmp = EdwardsPoint::witness(
                cs.namespace(|| format!("right ciphertext {} witness", i)),
                c[i].as_ref().map(|e| e.clone().right),
                params
            )?;
            acc.push(tmp);
        }

        Ok(RightBalanceCiphertexts(acc))
    }

    pub fn inputize<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<E>
    {
        for (i, e) in self.0.iter().enumerate() {
            e.inputize(cs.namespace(|| format!("inputize right balance ciphertexts {}", i)))?;
        }

        Ok(())
    }
}
