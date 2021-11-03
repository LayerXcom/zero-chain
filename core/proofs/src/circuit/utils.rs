use crate::ProofGenerationKey;
use bellman::{ConstraintSystem, SynthesisError};
use scrypto::circuit::{
    boolean::{field_into_boolean_vec_le, Boolean},
    ecc::{fixed_base_multiplication, EdwardsPoint},
};
use scrypto::jubjub::{edwards, FixedGenerators, JubjubEngine, PrimeOrder};

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
    let (a_x, a_y) = (a.get_x(), a.get_y());
    let (b_x, b_y) = (b.get_x(), b.get_y());

    cs.enforce(
        || "equal x nums",
        |lc| lc + a_x.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + b_x.get_variable(),
    );

    cs.enforce(
        || "equal y nums",
        |lc| lc + a_y.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + b_y.get_variable(),
    );

    Ok(())
}

pub fn negate_point<E, CS>(
    mut cs: CS,
    point: &EdwardsPoint<E>,
    params: &E::Params,
) -> Result<EdwardsPoint<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    use crate::Assignment;
    use pairing::Field;
    use scrypto::circuit::num::AllocatedNum;

    let neg_x = AllocatedNum::alloc(cs.namespace(|| "negate x"), || {
        let x_value = point.get_x().get_value();
        let mut x = *x_value.get()?;
        x.negate();
        Ok(x)
    })?;

    EdwardsPoint::interpret(
        cs.namespace(|| "interpret negate point"),
        &neg_x,
        point.get_y(),
        params,
    )
}

/// Inputize re-randomized signature verification key.
pub fn rvk_inputize<E, CS>(
    mut cs: CS,
    proof_gen_key: Option<&ProofGenerationKey<E>>,
    alpha: Option<&E::Fs>,
    params: &E::Params,
) -> Result<(), SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // Ensure pgk on the curve.
    let pgk = EdwardsPoint::witness(
        cs.namespace(|| "pgk"),
        proof_gen_key.as_ref().map(|k| k.0.clone()),
        params,
    )?;

    // Ensure pgk is large order.
    pgk.assert_not_small_order(cs.namespace(|| "pgk not small order"), params)?;

    // Re-randomized parameter for pgk
    let alpha = field_into_boolean_vec_le(cs.namespace(|| "alpha"), alpha.map(|e| *e))?;

    // Make the alpha on the curve
    let alpha_g = fixed_base_multiplication(
        cs.namespace(|| "computation of randomiation for the signing key"),
        FixedGenerators::NoteCommitmentRandomness,
        &alpha,
        params,
    )?;

    // Ensure re-randomaized sig-verification key is computed by the addition of ak and alpha_g
    let rvk = pgk.add(cs.namespace(|| "computation of rvk"), &alpha_g, params)?;

    // Ensure rvk is large order.
    rvk.assert_not_small_order(cs.namespace(|| "rvk not small order"), params)?;

    rvk.inputize(cs.namespace(|| "rvk"))?;

    Ok(())
}

pub fn g_epoch_nonce_inputize<E, CS>(
    mut cs: CS,
    g_epoch: Option<&edwards::Point<E, PrimeOrder>>,
    dec_key_bits: &[Boolean],
    params: &E::Params,
) -> Result<(), SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // Ensure g_epoch is on the curve.
    let g_epoch = EdwardsPoint::witness(
        cs.namespace(|| "g_epoch"),
        g_epoch.map(|e| e.clone()),
        params,
    )?;

    // Ensure that nonce = dec_key * g_epoch
    let nonce = g_epoch.mul(
        cs.namespace(|| format!("g_epoch mul by dec_key")),
        dec_key_bits,
        params,
    )?;

    g_epoch.inputize(cs.namespace(|| "inputize g_epoch"))?;
    nonce.inputize(cs.namespace(|| "inputize nonce"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::TestConstraintSystem;
    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};
    use scrypto::circuit::num::AllocatedNum;
    use scrypto::jubjub::JubjubBls12;

    #[test]
    fn test_eq_points() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let p = edwards::Point::<Bls12, _>::rand(rng, params);
        let (x, y) = p.into_xy();
        let numx = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x)).unwrap();
        let numy = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y)).unwrap();
        let p1 = EdwardsPoint::interpret(&mut cs, &numx, &numy, &params).unwrap();
        let p2 = p1.clone();

        eq_edwards_points(cs.namespace(|| "eq_edwards_points"), &p1, &p2).unwrap();

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_negate_point() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut cs = TestConstraintSystem::<Bls12>::new();

        let p = edwards::Point::<Bls12, _>::rand(rng, params);
        let (expected_x, expected_y) = p.negate().into_xy();
        let (x, y) = p.into_xy();
        let numx = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x)).unwrap();
        let numy = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y)).unwrap();
        let p = EdwardsPoint::interpret(&mut cs, &numx, &numy, &params).unwrap();

        let neg_p = negate_point(cs.namespace(|| "negate point"), &p, params).unwrap();

        assert!(cs.is_satisfied());
        assert!(neg_p.get_x().get_value().unwrap() == expected_x);
        assert!(neg_p.get_y().get_value().unwrap() == expected_y);
    }
}
