use bellman::{
    SynthesisError,
    ConstraintSystem,
    Variable,
    LinearCombination
};
use scrypto::circuit::boolean::{Boolean, AllocatedBit};
use scrypto::jubjub::JubjubEngine;
use pairing::{PrimeField, Field, BitIterator, PrimeFieldRepr};

pub fn u32_into_boolean_vec_le<E, CS>(
    mut cs: CS,
    amount: Option<u32>
) -> Result<Vec<Boolean>, SynthesisError>
    where E: JubjubEngine, CS: ConstraintSystem<E>
{
    let alloc_num = AllocRangedNum::alloc(
        cs.namespace(|| "allocated num to check range."),
        || {
            match amount {
                Some(a) => E::Fr::from_str(&a.to_string()),
                None => E::Fr::from_str("0")
            }.ok_or(SynthesisError::AssignmentMissing)
        }
    )?;

    alloc_num.into_bits_le_strict(cs.namespace(
        || "range check within u32"
    ))
}

pub struct AllocRangedNum<E: JubjubEngine> {
    value: Option<E::Fr>,
    variable: Variable,
}

impl<E: JubjubEngine> AllocRangedNum<E> {
    pub fn alloc<CS, F>(
        mut cs: CS,
        value: F,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
        F: FnOnce() -> Result<E::Fr, SynthesisError>
    {
        let mut new_value = None;
        let var = cs.alloc(|| "num", || {
            let tmp = value()?;

            new_value = Some(tmp);

            Ok(tmp)
        })?;

        Ok(AllocRangedNum {
            value: new_value,
            variable: var
        })
    }

    /// Deconstructs this allocated number into its
    /// boolean representation in little-endian bit
    /// order, requiring that the representation
    /// strictly exists "in the field" (i.e., a
    /// congruency is not allowed.)
    pub fn into_bits_le_strict<CS>(
        &self,
        mut cs: CS
    ) -> Result<Vec<Boolean>, SynthesisError>
        where CS: ConstraintSystem<E>
    {
        pub fn kary_and<E, CS>(
            mut cs: CS,
            v: &[AllocatedBit]
        ) -> Result<AllocatedBit, SynthesisError>
            where E: JubjubEngine,
                  CS: ConstraintSystem<E>
        {
            assert!(v.len() > 0);

            // Let's keep this simple for now and just AND them all
            // manually
            let mut cur = None;

            for (i, v) in v.iter().enumerate() {
                if cur.is_none() {
                    cur = Some(v.clone());
                } else {
                    cur = Some(AllocatedBit::and(
                        cs.namespace(|| format!("and {}", i)),
                        cur.as_ref().unwrap(),
                        v
                    )?);
                }
            }

            Ok(cur.expect("v.len() > 0"))
        }

        // We want to ensure that the bit representation of a is
        // less than or equal to r - 1.
        let mut a = self.value.map(|e| BitIterator::new(e.into_repr()));
        let mut b = E::Fr::char();
        b.sub_noborrow(&1.into());

        let mut result = vec![];

        // Runs of ones in r
        let mut last_run = None;
        let mut current_run = vec![];

        let mut found_one = false;
        let mut i = 0;
        for b in BitIterator::new(b) {
            let a_bit = a.as_mut().map(|e| e.next().unwrap());

            // Skip over unset bits at the beginning
            found_one |= b;
            if !found_one {
                // a_bit should also be false
                a_bit.map(|e| assert!(!e));
                continue;
            }

            if b {
                // This is part of a run of ones. Let's just
                // allocate the boolean with the expected value.
                let a_bit = AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    a_bit
                )?;
                // ... and add it to the current run of ones.
                current_run.push(a_bit.clone());
                result.push(a_bit);
            } else {
                if current_run.len() > 0 {
                    // This is the start of a run of zeros, but we need
                    // to k-ary AND against `last_run` first.

                    if last_run.is_some() {
                        current_run.push(last_run.clone().unwrap());
                    }
                    last_run = Some(kary_and(
                        cs.namespace(|| format!("run ending at {}", i)),
                        &current_run
                    )?);
                    current_run.truncate(0);
                }

                // If `last_run` is true, `a` must be false, or it would
                // not be in the field.
                //
                // If `last_run` is false, `a` can be true or false.

                let a_bit = AllocatedBit::alloc_conditionally(
                    cs.namespace(|| format!("bit {}", i)),
                    a_bit,
                    &last_run.as_ref().expect("char always starts with a one")
                )?;
                result.push(a_bit);
            }

            i += 1;
        }

        // char is prime, so we'll always end on
        // a run of zeros.
        assert_eq!(current_run.len(), 0);

        // Now, we have `result` in big-endian order.
        // However, now we have to unpack self!

        let mut lc = LinearCombination::zero();
        let mut coeff = E::Fr::one();

        for bit in result.iter().rev() {
            lc = lc + (coeff, bit.get_variable());

            coeff.double();
        }

        lc = lc - self.variable;

        cs.enforce(
            || "unpacking constraint",
            |lc| lc,
            |lc| lc,
            |_| lc
        );

        // Convert into booleans, and reverse for little-endian bit order
        Ok(result.into_iter().map(|b| Boolean::from(b)).rev().collect())
    }
}
