use bellman::{ConstraintSystem, LinearCombination, SynthesisError, Variable};
use pairing::{BitIterator, Field, PrimeField, PrimeFieldRepr};
use scrypto::circuit::boolean::{AllocatedBit, Boolean};
use scrypto::jubjub::JubjubEngine;

pub fn u32_into_bit_vec_le<E, CS>(
    mut cs: CS,
    amount: Option<u32>,
) -> Result<Vec<Boolean>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    let alloc_num =
        AllocRangedNum::alloc(cs.namespace(|| "allocated num to check range."), || {
            match amount {
                Some(a) => E::Fr::from_str(&a.to_string()),
                None => E::Fr::from_str("0"),
            }
            .ok_or(SynthesisError::AssignmentMissing)
        })?;

    alloc_num.into_bits_le_strict(cs.namespace(|| "range check within u32"))
}

struct AllocRangedNum<E: JubjubEngine> {
    value: Option<E::Fr>,
    variable: Variable,
}

impl<E: JubjubEngine> AllocRangedNum<E> {
    fn alloc<CS, F>(mut cs: CS, value: F) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<E>,
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
    {
        let mut new_value = None;
        let var = cs.alloc(
            || "num",
            || {
                let tmp = value()?;

                new_value = Some(tmp);

                Ok(tmp)
            },
        )?;

        Ok(AllocRangedNum {
            value: new_value,
            variable: var,
        })
    }

    /// Deconstructs this allocated number into its
    /// boolean representation in little-endian bit
    /// order, requiring that the representation
    /// strictly exists "in the field" (i.e., a
    /// congruency is not allowed.)
    fn into_bits_le_strict<CS>(&self, mut cs: CS) -> Result<Vec<Boolean>, SynthesisError>
    where
        CS: ConstraintSystem<E>,
    {
        pub fn kary_and<E, CS>(
            mut cs: CS,
            v: &[AllocatedBit],
        ) -> Result<AllocatedBit, SynthesisError>
        where
            E: JubjubEngine,
            CS: ConstraintSystem<E>,
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
                        v,
                    )?);
                }
            }

            Ok(cur.expect("v.len() > 0"))
        }

        // We want to ensure that the bit representation of a is
        // less than or equal to r - 1.
        let mut a = self.value.map(|e| BitIterator::new(e.into_repr()));
        let mut b = E::Fr::from_str(&std::u32::MAX.to_string())
            .map(|e| e.into_repr())
            .ok_or(SynthesisError::AssignmentMissing)?;
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
                let a_bit = AllocatedBit::alloc(cs.namespace(|| format!("bit {}", i)), a_bit)?;
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
                        &current_run,
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
                    &last_run
                        .as_ref()
                        .expect("u32::MAX always starts with a one"),
                )?;
                result.push(a_bit);
            }

            i += 1;
        }

        // u32::MAX is prime, so we'll always end on
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

        cs.enforce(|| "unpacking constraint", |lc| lc, |lc| lc, |_| lc);

        // Convert into booleans, and reverse for little-endian bit order
        Ok(result.into_iter().map(|b| Boolean::from(b)).rev().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::TestConstraintSystem;
    use pairing::bls12_381::{Bls12, Fr};

    fn valid_range_check(num_str: &str) -> bool {
        let num = Fr::from_str(num_str).unwrap();
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let alloc_num = AllocRangedNum::alloc(&mut cs, || Ok(num)).unwrap();
        alloc_num.into_bits_le_strict(&mut cs).unwrap();

        cs.is_satisfied()
    }

    fn should_panic_neg_range_check(num_str: &str) {
        let mut neg_num = Fr::from_str(num_str).unwrap();
        neg_num.negate();

        let mut cs = TestConstraintSystem::<Bls12>::new();
        let alloc_num = AllocRangedNum::alloc(&mut cs, || Ok(neg_num)).unwrap();
        alloc_num.into_bits_le_strict(&mut cs).unwrap();

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_range_check_valid() {
        assert!(valid_range_check("0"));
        assert!(valid_range_check("1"));
        assert!(valid_range_check("12"));
        assert!(valid_range_check("234"));
        assert!(valid_range_check("2353649"));

        let max_minus_one = std::u32::MAX - 1;
        assert!(valid_range_check(&max_minus_one.to_string()));
    }

    #[test]
    fn test_range_check_invalid() {
        let max = std::u32::MAX;
        assert!(!valid_range_check(&max.to_string()));
    }

    #[should_panic]
    #[test]
    fn test_panic_overflow() {
        let max = std::u32::MAX as u64;
        valid_range_check(&(max + 1).to_string());
    }

    #[should_panic]
    #[test]
    fn test_panic_neg_one() {
        should_panic_neg_range_check(&1.to_string());
    }

    #[should_panic]
    #[test]
    fn test_panic_neg_max() {
        let max = std::u32::MAX;
        should_panic_neg_range_check(&max.to_string());
    }

    #[should_panic]
    #[test]
    fn test_panic_neg_max_plus_one() {
        let max = std::u32::MAX as u64;
        should_panic_neg_range_check(&(max + 1).to_string());
    }
}
