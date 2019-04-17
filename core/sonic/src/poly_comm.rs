use pairing::{Field, Engine, CurveAffine};
use crate::srs::SRS;

/// Commit a polynomial `F`.
/// F \from g^{\alpha * x^{(d - max)}*f(x)}
pub fn polynomial_commitment<'a, E: Engine, I: IntoIterator<Item = &'a E::Fr>>(
        max: usize,                 // a maximum degree
        largest_pos_power: usize,   // largest positive power
        largest_neg_power: usize,   // largest negative power
        srs: &'a SRS<E>,
        s: I
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

        return mul
    } else {
        return multiexp(
            srs.g_neg_x_alpha[0..min_power].iter().rev()
        )
    }
    unimplemented!();
}


/// Divides polynomial `a` in `x` by `x-b` with no remainder.
pub fn kate_division<'a, F: Field, I: IntoIterator<Item = &'a F>>(a: I, mut b: F) -> Vec<F>
    where
        I::IntoIter: DoubleEndedIterator + ExactSizeIterator,
{
    b.negate();
    let a = a.into_iter();

    let mut q = vec![F::zero(); a.len() - 1];

    let mut tmp = F::zero();
    for (q, r) in q.iter_mut().rev().zip(a.rev()) {
        let mut lead_coeff = *r;
    }

    unimplemented!();
}

pub fn multiexp<
    'a,
    G: CurveAffine,
    IB: IntoIterator<Item = &'a G>,
    IS: IntoIterator<Item = &'a G::Scalar>,
>(
    g: IB,
    s: IS,
) -> G::Projective
where
    IB::IntoIter: ExactSizeIterator + Clone,
    IS::IntoIter: ExactSizeIterator,
{
    unimplemented!();
}

