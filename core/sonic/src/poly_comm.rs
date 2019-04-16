use pairing::Field;

// pub fn polynomial_commitment<'a, E: Engine, I: IntoIterator<Item = &'a E::Fr>(
//         max: usize,
//         largest_pos_power: usize,
//         largest_neg_power: usize,
//         srs: &'a SRS<E>,
//         s: I
//     ) -> E::G1Affine
//     where I::IntoIter: ExactSizeIterator
// {

// }


/// Divides polynomial `a` in `x` by `x-b` with no remainder.
pub fn kate_division<'a, F: Field, I: IntoIterator<Item = &'a F>>(a: I, mut b: F) -> Vec<F>
    where
        I::IntoIterator: DoubleEndedIterator + ExactSizeIterator,
{
    b.negate();
    let a = a.into_iter();

    let mut q = vec![F::zero(); a.len() - 1];

    let mut tmp = F::zero();
    for (q, r) in q.iter_mut().rev().zip(a.rev()) {
        let mut lead_coeff = *r;
    }
}

// pub fn multiexp

