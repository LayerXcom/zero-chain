//! Our protocol allows the verification of multiple proofs and even
//! of individual proofs to batch the pairing operations such that
//! only a smaller, fixed number of pairings must occur for an entire
//! batch of proofs. This is possible because G2 elements are fixed
//! in our protocol and never appear in proofs; everything can be
//! combined probabilistically.
//!
//! The helper protocol for computing aggregated signatures
//! of correct computation to ensure that an element `s` is equal to `s(z, y)` for
//! known polynomial.
//! The helper algorithm is run on a batch of proofs.
//!
//! This submodule contains the `Batch` abstraction for creating a
//! context for batch verification.

use pairing::{Engine, CurveAffine, CurveProjective, Field};
use crate::srs::SRS;
use crate::polynomials::commitment::multiexp;

#[derive(Clone)]
pub struct Batch<E: Engine> {
    /// Context of openings of polynomial commitment
    alpha_x: Vec<(E::G1Affine, E::Fr)>,
    alpha_x_precomp: <E::G2Affine as CurveAffine>::Prepared,

    /// Context of openings of polynomial commitment
    alpha: Vec<(E::G1Affine, E::Fr)>,
    alpha_precomp: <E::G2Affine as CurveAffine>::Prepared,

    /// Context of polynomial commitment and randomness
    neg_h: Vec<(E::G1Affine, E::Fr)>,
    neg_h_precomp: <E::G2Affine as CurveAffine>::Prepared,

    neg_x_n_minus_d: Vec<(E::G1Affine, E::Fr)>,
    neg_x_n_minus_d_precomp: <E::G2Affine as CurveAffine>::Prepared,

    value: E::Fr,
    g: E::G1Affine,
}

impl<E: Engine> Batch<E> {
    pub fn new(srs: &SRS<E>, n: usize) -> Self {
        Batch {
            alpha_x: vec![],
            // Prepares `alpha * h^{x^{1}}` for pairing purposes.
            alpha_x_precomp: srs.h_pos_x_alpha[1].prepare(),

            alpha: vec![],
            // Prepares `alpha * h^{x^{0}}` for pairing purposes.
            alpha_precomp: srs.h_pos_x_alpha[0].prepare(),

            neg_h: vec![],
            // Prepares `-h^{x^0}` for pairing purposes.
            neg_h_precomp: {
                let mut tmp = srs.h_neg_x[0];
                tmp.negate();
                tmp.prepare()
            },

            neg_x_n_minus_d: vec![],
            // Prepares `-h^{x^{d-n}}` for pairing purposes.
            neg_x_n_minus_d_precomp: {
                let mut tmp = srs.h_neg_x[srs.d - n];
                tmp.negate();
                tmp.prepare()
            },

            value: E::Fr::zero(),
            g: srs.g_pos_x[0], // g^{x^0}
        }
    }

    pub fn add_comm(&mut self, comm: E::G1Affine, random: E::Fr) {
        self.neg_h.push((comm, random));
    }

    pub fn add_comm_max_n(&mut self, comm: E::G1Affine, random: E::Fr) {
        self.neg_x_n_minus_d.push((comm, random));
    }

    pub fn add_opening(&mut self, opening: E::G1Affine, mut random: E::Fr, point: E::Fr) {
        self.alpha_x.push((opening, random));

        random.mul_assign(&point);
        random.negate();
        self.alpha.push((opening, random));
    }

    pub fn add_opening_value(&mut self, eval_val: E::Fr, mut random: E::Fr) {
        random.mul_assign(&eval_val);
        self.value.add_assign(&random);
    }

    pub fn check_all(mut self) -> bool {
        self.alpha.push((self.g, self.value));

        let alpha_x = multiexp(
            self.alpha_x.iter().map(|x| &x.0),
            self.alpha_x.iter().map(|x| &x.1),
        ).into_affine();

        let alpha_x = alpha_x.prepare();

        let alpha = multiexp(
            self.alpha.iter().map(|x| &x.0),
            self.alpha.iter().map(|x| &x.1),
        ).into_affine();

        let alpha = alpha.prepare();

        let neg_h = multiexp(
            self.neg_h.iter().map(|x| &x.0),
            self.neg_h.iter().map(|x| &x.1),
        ).into_affine();

        let neg_h = neg_h.prepare();

        let neg_x_n_minus_d = multiexp(
            self.neg_x_n_minus_d.iter().map(|x| &x.0),
            self.neg_x_n_minus_d.iter().map(|x| &x.1),
        ).into_affine();

        let neg_x_n_minus_d = neg_x_n_minus_d.prepare();

        E::final_exponentiation(&E::miller_loop(&[
            (&alpha_x, &self.alpha_x_precomp),
            (&alpha, &self.alpha_precomp),
            (&neg_h, &self.neg_h_precomp),
            (&neg_x_n_minus_d, &self.neg_x_n_minus_d_precomp),
        ])).unwrap() == E::Fqk::one()
    }
}
