use pairing::{Field, Engine, CurveAffine, CurveProjective, PrimeField};
use bellman::multicore::Worker;
use bellman::domain::{EvaluationDomain, Scalar};
pub mod commitment;
pub mod s_eval;
pub mod operations;

pub use operations::*;
pub use commitment::*;
pub use s_eval::*;
use crate::srs::SRS;
use crate::utils::ChainExt;

use std::borrow::Borrow;
use std::ops::{Add, Mul};

pub struct Polynomial<E: Engine>(Vec<E::Fr>);

impl<E: Engine> Add<Polynomial<E>> for Polynomial<E> {
    type Output = Polynomial<E>;

    fn add(mut self, other: Polynomial<E>) -> Polynomial<E> {
        assert_eq!(self.0.len(), other.0.len());

        let worker = Worker::new();

        worker.scope(self.0.len(), |scope, chunk| {
            for (a, b) in self.0.chunks_mut(chunk).zip(other.0.chunks(chunk)) {
                scope.spawn(move |_| {
                    for (a, b) in a.iter_mut().zip(b.iter()) {
                        a.add_assign(b);
                    }
                });
            }
        });

        self
    }
}

impl<E: Engine> Mul<Polynomial<E>> for Polynomial<E> {
    type Output = Polynomial<E>;

    fn mul(self, other: Polynomial<E>) -> Polynomial<E> {
        let res_len = self.0.len() + other.0.len() - 1;

        let worker = Worker::new();
        let scalars_a = self.0.iter().map(|e| Scalar::<E>(*e)).collect();
        // the size of evaluation domain is polynomial's multiplied by other.
        let mut domain_a = EvaluationDomain::from_coeffs_into_sized(scalars_a, res_len)
            .expect("The degree of polynomial should be under the rational size");

        let scalars_b = other.0.iter().map(|e| Scalar::<E>(*e)).collect();
        let mut domain_b = EvaluationDomain::from_coeffs_into_sized(scalars_b, res_len)
            .expect("The degree of polynomial should be under the rational size");

        // Convert to point-value representations
        domain_a.fft(&worker);
        domain_b.fft(&worker);

        // Perform O(n) multiplication of two polynomials in the domain.
        domain_a.mul_assign(&worker, &domain_b);
        drop(domain_b);

        // Convert back to point-value representations
        domain_a.ifft(&worker);

        let mut mul_res: Vec<E::Fr> = domain_a.into_coeffs().iter().map(|e| e.0).collect();
        mul_res.truncate(res_len);

        Polynomial(mul_res)
    }
}

impl<'a, E: Engine> Polynomial<E> {
    /// Commit a polynomial `F`.
    /// F \from g^{\alpha * x^{(d - max)}*f(x)}
    /// See: Section 5 SYSTEM OF CONSTRAINTS
    pub fn commit(
        &self,
        max: usize,                 // a maximum degree
        largest_neg_power: usize,   // largest negative power
        largest_pos_power: usize,   // largest positive power
        srs: &'a SRS<E>,
    ) -> PolyComm<E>
    {
        let d = srs.d;
        assert!(max >= largest_pos_power);

        // smallest power is `|(srs.d - max) - largest_neg_power|`. (See Figure.3)
        // If the smallest power is negative, use both positive and negative powers for commitment,
        // otherwise use only positive powers.
        if d < max + largest_neg_power + 1 {
            let min_power = largest_neg_power + max - d;
            let max_power = largest_pos_power + d - max;

            let res = multiexp(
                srs.g_neg_x_alpha[0..min_power].iter().rev() // Reverse to permute for negative powers
                .chain_ext(srs.g_pos_x_alpha[..max_power].iter()),
                &self.0
            ).into_affine();

            return PolyComm(res);
        } else {
            let _max_power = srs.d - max - largest_neg_power + 1;

            let res = multiexp(
                // srs.g_pos_x_alpha[..max_power].iter(), // TODO: Ensure the range is correct
                srs.g_pos_x_alpha[(srs.d - max - largest_neg_power - 1)..].iter(),
                &self.0
            ).into_affine();

            return PolyComm(res);
        }
    }

    /// Opening a polynomial commitment
    pub fn open(
        &self,
        largest_neg_power: usize,
        largest_pos_power: usize,
        srs: &'a SRS<E>,
        point: E::Fr,
    ) -> PolyCommOpening<E>
    {
        let quotient_poly = self.kate_division(point);

        let neg_poly = quotient_poly.0[..largest_neg_power].iter().rev(); // -n,...,-1
        let pos_poly = quotient_poly.0[largest_pos_power..].iter();       // n,...,1,0

        let res = multiexp(
            srs.g_neg_x[1..(neg_poly.len() + 1)].iter().chain_ext(
                srs.g_pos_x[..pos_poly.len()].iter()
            ),
            neg_poly.chain_ext(pos_poly)
        ).into_affine();

        PolyCommOpening(res)
    }

    // TODO: Parallelization
    /// Divides polynomial `a` in `x` by `x-b` with no remainder.
    pub fn kate_division(&self, mut b: E::Fr) -> Self
    {
        b.negate();
        let a_poly = &self.0.into_iter();

        let mut quotient_poly = vec![E::Fr::zero(); a_poly.len() - 1];

        let mut tmp = E::Fr::zero();
        for (q, r) in quotient_poly.iter_mut().rev().zip(a_poly.rev()) {
            let mut lead_coeff = r;
            lead_coeff.sub_assign(&tmp);
            *q = lead_coeff;
            tmp = lead_coeff;
            tmp.mul_assign(&b)
        }

        Polynomial(quotient_poly)
    }
}

pub struct PolyComm<E: Engine>(E::G1Affine);

pub struct PolyCommOpening<E: Engine>(E::G1Affine);

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
