use bellman::{SynthesisError, ConstraintSystem};
use scrypto::circuit::{
    boolean::{Boolean, field_into_boolean_vec_le},
    ecc::{EdwardsPoint, fixed_base_multiplication},
};
use scrypto::jubjub::{JubjubEngine, FixedGenerators, edwards, PrimeOrder};
use crate::ProofGenerationKey;

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
        |lc| lc + b_x.get_variable()
    );

    cs.enforce(
        || "equal y nums",
        |lc| lc + a_y.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + b_y.get_variable()
    );

    Ok(())
}

pub fn negate_point<E, CS>(
    mut cs: CS,
    point: &EdwardsPoint<E>,
    params: &E::Params
) -> Result<EdwardsPoint<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    use scrypto::circuit::num::AllocatedNum;
    use pairing::Field;
    use crate::Assignment;

    let neg_x = AllocatedNum::alloc(
        cs.namespace(|| "negate x"),
        || {
            let x_value = point.get_x().get_value();
            let mut x = *x_value.get()?;
            x.negate();
            Ok(x)
        }
    )?;

    EdwardsPoint::interpret(
        cs.namespace(|| "interpret negate point"),
        &neg_x,
        point.get_y(),
        params
    )
}

/// Inputize re-randomized signature verification key.
pub fn rvk_inputize<E, CS>(
    mut cs: CS,
    proof_gen_key: Option<&ProofGenerationKey<E>>,
    alpha: Option<&E::Fs>,
    params: &E::Params
) -> Result<(), SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // Ensure pgk on the curve.
    let pgk = EdwardsPoint::witness(
        cs.namespace(|| "pgk"),
        proof_gen_key.as_ref().map(|k| k.0.clone()),
        params
    )?;

    // Ensure pgk is large order.
    pgk.assert_not_small_order(
        cs.namespace(|| "pgk not small order"),
        params
    )?;

    // Re-randomized parameter for pgk
    let alpha = field_into_boolean_vec_le(
        cs.namespace(|| "alpha"),
        alpha.map(|e| *e)
    )?;

    // Make the alpha on the curve
    let alpha_g = fixed_base_multiplication(
        cs.namespace(|| "computation of randomiation for the signing key"),
        FixedGenerators::NoteCommitmentRandomness,
        &alpha,
        params
    )?;

    // Ensure re-randomaized sig-verification key is computed by the addition of ak and alpha_g
    let rvk = pgk.add(
        cs.namespace(|| "computation of rvk"),
        &alpha_g,
        params
    )?;

    // Ensure rvk is large order.
    rvk.assert_not_small_order(
        cs.namespace(|| "rvk not small order"),
        params
    )?;

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
        params
    )?;

    // Ensure that nonce = dec_key * g_epoch
    let nonce = g_epoch.mul(
        cs.namespace(|| format!("g_epoch mul by dec_key")),
        dec_key_bits,
        params
    )?;

    g_epoch.inputize(cs.namespace(|| "inputize g_epoch"))?;
    nonce.inputize(cs.namespace(|| "inputize nonce"))?;

    Ok(())
}
