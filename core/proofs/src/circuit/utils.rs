use bellman::{SynthesisError, ConstraintSystem};
use scrypto::circuit::{
    boolean::Boolean,
    ecc::EdwardsPoint,
};
use scrypto::jubjub::JubjubEngine;

/// This performs equal veficiation of two edward points.
pub fn eq_edwards_points<E, CS>(
    mut cs: CS,
    a: &EdwardsPoint<E>,
    b: &EdwardsPoint<E>,
) -> Result<(), SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    let a_repr = a.repr(cs.namespace(|| "a into representation."))?;
    let b_repr = b.repr(cs.namespace(|| "b into representation."))?;

    for (i, (a, b)) in a_repr.iter().zip(b_repr.iter()).enumerate() {
        Boolean::enforce_equal(
            cs.namespace(|| format!("a_repr equals b_repr {}", i)),
            &a,
            &b
        )?;
    }

    Ok(())
}
