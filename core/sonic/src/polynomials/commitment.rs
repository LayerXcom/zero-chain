use pairing::{Field, Engine, CurveAffine, CurveProjective, PrimeField};
use crate::srs::SRS;
use crate::utils::ChainExt;

/// Commit a polynomial `F`.
/// F \from g^{\alpha * x^{(d - max)}*f(x)}
/// See: Section 5 SYSTEM OF CONSTRAINTS
pub fn poly_comm<'a, E: Engine, I: IntoIterator<Item = &'a E::Fr>>(
        max: usize,                 // a maximum degree
        largest_neg_power: usize,   // largest negative power
        largest_pos_power: usize,   // largest positive power
        srs: &'a SRS<E>,
        poly_coeffs: I
    ) -> E::G1Affine
    where I::IntoIter: ExactSizeIterator
{
    let d = srs.d;
    assert!(max >= largest_pos_power);

    // smallest power is `|(srs.d - max) - largest_neg_power|`. (See Figure.3)
    // If the smallest power is negative, use both positive and negative powers for commitment,
    // otherwise use only positive powers.
    if d < max + largest_neg_power + 1 {
        let max_power = largest_pos_power + d - max;
        let min_power = largest_neg_power - d + max;

        return multiexp(
            srs.g_neg_x_alpha[0..min_power].iter().rev() // Reverse to permute for negative powers
            .chain_ext(srs.g_pos_x_alpha[..max_power].iter()),
            poly_coeffs
        ).into_affine();
    } else {
        let max_power = srs.d - max - largest_neg_power;

        return multiexp(
            srs.g_pos_x_alpha[..max_power].iter(), // TODO: Ensure the range is correct
            poly_coeffs
        ).into_affine();
    }
}

/// Opening a polynomial commitment
pub fn poly_comm_opening<'a, E: Engine, I: IntoIterator<Item = &'a E::Fr>>(
    largest_neg_power: usize,
    largest_pos_power: usize,
    srs: &'a SRS<E>,
    poly_coeffs: I,
    point: E::Fr,
) -> E::G1Affine
where
    I::IntoIter: DoubleEndedIterator + ExactSizeIterator
{
    let quotient_poly = kate_division(
        poly_coeffs,
        point
    );

    let neg_poly = quotient_poly[..largest_neg_power].iter().rev(); // ,...,-1
    let pos_poly = quotient_poly[largest_neg_power..].iter();

    multiexp(
        srs.g_neg_x[1..(neg_poly.len() + 1)].iter().chain_ext(
            srs.g_pos_x[..pos_poly.len()].iter()
        ),
        neg_poly.chain_ext(pos_poly)
    ).into_affine()
}

// TODO: Parallelization
/// Divides polynomial `a` in `x` by `x-b` with no remainder.
pub fn kate_division<'a, F: Field, I: IntoIterator<Item = &'a F>>(a: I, mut b: F) -> Vec<F>
    where
        I::IntoIter: DoubleEndedIterator + ExactSizeIterator,
{
    b.negate();
    let a_poly = a.into_iter();

    let mut quotient_poly = vec![F::zero(); a_poly.len() - 1];

    let mut tmp = F::zero();
    for (q, r) in quotient_poly.iter_mut().rev().zip(a_poly.rev()) {
        let mut lead_coeff = *r;
        lead_coeff.sub_assign(&tmp);
        *q = lead_coeff;
        tmp = lead_coeff;
        tmp.mul_assign(&b)
    }

    quotient_poly
}

pub fn multiexp<
    'a,
    G: CurveAffine,
    IE: IntoIterator<Item = &'a G>,
    IS: IntoIterator<Item = &'a G::Scalar>,
>(
    exponent: IE,
    scalar: IS,
) -> G::Projective
where
    IE::IntoIter: ExactSizeIterator + Clone,
    IS::IntoIter: ExactSizeIterator,
{
    use bellman::multicore::Worker;
    use bellman::multiexp::{multiexp, FullDensity};
    use std::sync::Arc;
    use futures::Future;

    let scalar: Vec<<G::Scalar as PrimeField>::Repr> = scalar
        .into_iter()
        .map(|e| e.into_repr())
        .collect::<Vec<_>>();

    let exponent: Vec<G> = exponent
        .into_iter()
        .map(|e| *e)
        .collect::<Vec<_>>();

    assert_eq!(
        scalar.len(),
        exponent.len(),
        "scalars and exponents must have the same length."
    );

    let pool = Worker::new();

    let result = multiexp(
        &pool,
        (Arc::new(exponent), 0),
        FullDensity,
        Arc::new(scalar)
    ).wait().unwrap();

    result
}
