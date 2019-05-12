use pairing::{Field, Engine, CurveAffine, CurveProjective, PrimeField};
use crate::srs::SRS;
use crate::utils::{ChainExt, multiexp};
use crate::traits::{Commitment, PolyEngine};

/// Commit a polynomial `F`.
/// F \from g^{\alpha * x^{(d - max)}*f(x)}
/// See: Section 5 SYSTEM OF CONSTRAINTS
pub fn poly_comm<'a, E: Engine, I: IntoIterator<Item = &'a E::Fr>, PE: PolyEngine>(
        max: usize,                 // a maximum degree
        largest_neg_power: usize,   // largest negative power
        largest_pos_power: usize,   // largest positive power
        srs: &'a SRS<E>,
        poly_coeffs: I
    ) -> PE::Commitment
    where
        I::IntoIter: ExactSizeIterator,
{
    let d = srs.d;
    assert!(max >= largest_pos_power);

    // smallest power is `|(srs.d - max) - largest_neg_power|`. (See Figure.3)
    // If the smallest power is negative, use both positive and negative powers for commitment,
    // otherwise use only positive powers.
    if d < max + largest_neg_power + 1 {
        let min_power = largest_neg_power + max - d;
        let max_power = largest_pos_power + d - max;

        let point = multiexp(
            srs.g_neg_x_alpha[0..min_power].iter().rev() // Reverse to permute for negative powers
            .chain_ext(srs.g_pos_x_alpha[..max_power].iter()),
            poly_coeffs
        ).into_affine();

        return PE::Commitment::from_point(&point)
    } else {
        let _max_power = srs.d - max - largest_neg_power + 1;

        let point = multiexp(
            // srs.g_pos_x_alpha[..max_power].iter(), // TODO: Ensure the range is correct
            srs.g_pos_x_alpha[(srs.d - max - largest_neg_power - 1)..].iter(),
            poly_coeffs
        ).into_affine();

        return PE::Commitment::from_point(&point)
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

    let neg_poly = quotient_poly[0..largest_neg_power].iter().rev(); // -n,...,-1
    // let pos_poly = quotient_poly[largest_pos_power..].iter();       // n,...,1,0
    let pos_poly = quotient_poly[largest_neg_power..].iter();       // n,...,1,0

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
