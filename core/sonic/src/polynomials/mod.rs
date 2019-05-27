use pairing::{Field, Engine, CurveAffine, CurveProjective, PrimeField};
use bellman::multicore::Worker;
use bellman::domain::{EvaluationDomain, Scalar};
use crossbeam::channel::unbounded;
pub mod commitment;
pub mod s_eval;
pub mod operations;

pub use operations::*;
pub use commitment::*;
pub use s_eval::*;
use crate::srs::SRS;
use crate::utils::ChainExt;
use crate::traits::*;
use std::borrow::Borrow;
use std::ops::{Add, Mul, Index, IndexMut, Range};

pub struct Polynomial<E: Engine>(Vec<E::Fr>);

impl<E: Engine> PolyEngine for Polynomial<E> {
    type Commitment = PolyComm<E>;
    type Opening = PolyCommOpening<E>;
    type Pairing = E;
}

impl<E: Engine> IntoIterator for Polynomial<E> {
    type Item = <Vec<E::Fr> as IntoIterator>::Item;
    type IntoIter = <Vec<E::Fr> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<E: Engine> Index<usize> for Polynomial<E> {
    type Output = E::Fr;

    fn index(&self, id: usize) -> &Self::Output {
        &self.0[id]
    }
}

impl<E: Engine> IndexMut<usize> for Polynomial<E> {
    fn index_mut(&mut self, id: usize) -> &mut Self::Output {
        &mut self.0[id]
    }
}

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
    type Output = Vec<E::Fr>; // TODO

    fn mul(self, other: Polynomial<E>) -> Vec<E::Fr> {
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

        mul_res
    }
}

impl<E: Engine> Polynomial<E> {
    pub fn from_slice(s: &mut [E::Fr]) -> Self {
        Polynomial(s.to_vec())
    }

    /// Commit a polynomial `F`.
    /// F \from g^{\alpha * x^{(d - max)}*f(x)}
    /// See: Section 5 SYSTEM OF CONSTRAINTS
    pub fn commit<PE: PolyEngine<Pairing = E>>(
        &self,
        max: usize,                 // a maximum degree
        largest_neg_power: usize,   // largest negative power
        largest_pos_power: usize,   // largest positive power
        srs: &SRS<E>,
    ) -> PE::Commitment
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
                self.0.iter()
            ).into_affine();

            PE::Commitment::from_point(&point)
        } else {
            let _max_power = srs.d - max - largest_neg_power + 1;

            let point = multiexp(
                // srs.g_pos_x_alpha[..max_power].iter(), // TODO: Ensure the range is correct
                srs.g_pos_x_alpha[(srs.d - max - largest_neg_power - 1)..].iter(),
                self.0.iter()
            ).into_affine();

            PE::Commitment::from_point(&point)
        }
    }

    /// Opening a polynomial commitment
    pub fn open(
        &self,
        largest_neg_power: usize,
        largest_pos_power: usize,
        srs: &SRS<E>,
        mut point: E::Fr,
    ) -> E::G1Affine
    {
        // let quotient_poly = self.kate_division(point);

        // kate division
        point.negate();
        let a_poly = self.0.iter();

        let mut quotient_poly = vec![E::Fr::zero(); a_poly.len() - 1];

        let mut tmp = E::Fr::zero();
        for (q, r) in quotient_poly.iter_mut().rev().zip(a_poly.rev()) {
            let mut lead_coeff = *r;
            lead_coeff.sub_assign(&tmp);
            *q = lead_coeff;
            tmp = lead_coeff;
            tmp.mul_assign(&point)
        }

        let neg_poly = quotient_poly[..largest_neg_power].iter().rev(); // -n,...,-1
        let pos_poly = quotient_poly[largest_pos_power..].iter();       // n,...,1,0

        multiexp(
            srs.g_neg_x[1..(neg_poly.len() + 1)].iter().chain_ext(
                srs.g_pos_x[..pos_poly.len()].iter()
            ),
            neg_poly.chain_ext(pos_poly)
        ).into_affine()
    }

    // TODO: Parallelization
    // Divides polynomial `a` in `x` by `x-b` with no remainder.
    // pub fn kate_division(self, mut b: E::Fr) -> Self
    // {
    //     b.negate();
    //     let a_poly = self.0.into_iter();

    //     let mut quotient_poly = vec![E::Fr::zero(); a_poly.len() - 1];

    //     let mut tmp = E::Fr::zero();
    //     for (q, r) in quotient_poly.iter_mut().rev().zip(a_poly.rev()) {
    //         let mut lead_coeff = *r;
    //         lead_coeff.sub_assign(&tmp);
    //         *q = lead_coeff;
    //         tmp = lead_coeff;
    //         tmp.mul_assign(&b)
    //     }

    //     Polynomial(&quotient_poly[..])
    // }

    /// Multiply each coefficient by some power of the base in a form
    /// `first_power * base^{i}`
    /// This would be sparse, consecutive multiplication based on non-zero coefficients.
    /// Basically, it is for the evaluation of one of the variables of bivariate polynomials.
    /// For example, r(X, Y) at y.
    pub fn eval_bivar_poly(
        &mut self,
        first_power: E::Fr,
        base: E::Fr
    ) {
        let worker = Worker::new();

        worker.scope(self.0.len(), |scope, chunk| {
            for (i, coeffs_chunk) in self.0.chunks_mut(chunk).enumerate() {
                scope.spawn(move |_| {
                    let mut current_power = base.pow(&[(i * chunk) as u64]);
                    current_power.mul_assign(&first_power);

                    for mut p in coeffs_chunk {
                        p.mul_assign(&current_power);

                        current_power.mul_assign(&base);
                    }
                });
            }
        });
    }

    /// It is for the evaluation of univariate polynomials. For example, r(X, y) at z.
    pub fn eval_univar_poly(
        &self,
        first_power: E::Fr,
        base: E::Fr
    ) -> E::Fr
    {
        let (tx, rx) = unbounded();
        let worker = Worker::new();

        worker.scope(self.0.len(), |scope, chunk| {
            for (i, coeffs_chunk) in self.0.chunks(chunk).enumerate() {
                let tx = tx.clone();

                scope.spawn(move |_| {
                    let mut current_power = base.pow(&[(i * chunk) as u64]);
                    current_power.mul_assign(&first_power);

                    let mut acc = E::Fr::zero();

                    for p in coeffs_chunk {
                        let mut tmp = *p;
                        tmp.mul_assign(&current_power);
                        acc.add_assign(&tmp);

                        current_power.mul_assign(&base);
                    }

                    tx.send(acc).expect("must send");
                });
            }
        });

        // The sender is dropped, disconnect the channel.
        drop(tx);

        let mut res = E::Fr::zero();

        loop {
            if rx.is_empty() {
                break;
            }

            let val = rx.recv().expect("must not be empty");
            res.add_assign(&val);
        }

        res
    }
}

#[derive(Clone)]
pub struct PolyComm<E: Engine>(pub E::G1Affine);

impl<E: Engine> Commitment for PolyComm<E> {
    type Point = E::G1Affine;

    fn from_point(point: &Self::Point) -> Self {
        PolyComm(*point)
    }

    fn into_point(&self) -> Self::Point {
        self.0
    }

    fn into_bytes(&self) -> Vec<u8> { // TODO
        self.0.into_compressed().as_ref().to_vec()
    }
}

impl<E: Engine> Copy for PolyComm<E> {}

pub struct PolyCommOpening<E: Engine>(E::G1Affine);

impl<E: Engine> Opening for PolyCommOpening<E> {}

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

pub fn multiexp_mut<
    'a,
    G: CurveAffine,
    IE: IntoIterator<Item = &'a G>,
    IS: IntoIterator<Item = &'a mut G::Scalar>,
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
