//! This module contains the helper protocol for computing aggregated signatures
//! of correct computation to ensure that an element `s` is equal to `s(z, y)` for
//! known polynomial.
//! The helper algorithm is run on a batch of proofs.

use pairing::{Engine, Field};
use bellman::SynthesisError;
use merlin::Transcript;
use crate::cs::{SynthesisDriver, Circuit};
use crate::srs::SRS;
use crate::transcript::ProvingTranscript;
use crate::polynomials::{SyEval, SxEval, poly_comm, poly_comm_opening};
use crate::utils::{ChainExt, eval_univar_poly, mul_add_poly};
use super::prover::{Proof, SxyAdvice};

#[derive(Clone)]
pub struct Aggregate<E: Engine> {
    /// Commitment to s(z, Y)
    pub c_comm: E::G1Affine,

    pub s_opening: E::G1Affine,

    pub c_openings: Vec<(E::G1Affine, E::Fr)>,

    pub opening: E::G1Affine,

}

impl<E: Engine> Aggregate<E> {
    pub fn create_aggregate<C: Circuit<E>, S: SynthesisDriver>(
        circuit: &C,
        inputs: &[(Proof<E>, SxyAdvice<E>)],
        srs: &SRS<E>,
        n: usize,
        q: usize,
    ) -> Result<Self, SynthesisError> {
        let mut transcript = Transcript::new(&[]);
        let mut y_values: Vec<E::Fr> = Vec::with_capacity(inputs.len());

        for &(ref proof, ref s_xy_advice) in inputs {
            {
                let mut transcript = Transcript::new(&[]);
                transcript.commit_point(&proof.r_comm);
                y_values.push(transcript.challenge_scalar());
            }

            transcript.commit_point(&s_xy_advice.s_comm);
        }

        let z: E::Fr = transcript.challenge_scalar();

        // Evaluate s(X, Y) at X=z
        let (s_neg_poly, s_pos_poly) = {
            let mut tmp = SyEval::new(z, n, q)?;
            S::synthesize(&mut tmp, circuit)?;

            tmp.neg_pos_poly()
        };

        // max = srs.d
        let c_comm = poly_comm(
            srs.d,
            n,
            n + q,
            srs,
            s_neg_poly.iter()
                .chain_ext(s_pos_poly.iter())
        );

        transcript.commit_point(&c_comm);

        let w: E::Fr = transcript.challenge_scalar();
        let w_inv = w.inverse().ok_or(SynthesisError::DivisionByZero)?;

        // Evaluate s(z, Y) at w
        let mut s_zw = E::Fr::zero();
        s_zw.add_assign(&eval_univar_poly::<E>(&s_neg_poly[..], w_inv, w_inv));
        s_zw.add_assign(&eval_univar_poly::<E>(&s_pos_poly[..], w, w));

        let opening = {
            s_zw.negate();
            poly_comm_opening(
                n,
                0,
                srs,
                s_neg_poly.iter().rev()
                    .chain_ext(Some(s_zw).iter())
                    .chain_ext(s_pos_poly.iter()),
                w
            )
        };

        let mut c_openings = vec![];
        for y in &y_values {
            // Evaluate s(z, Y) at y_i
            let mut s_zy = E::Fr::zero();
            let y_inv = y.inverse().ok_or(SynthesisError::DivisionByZero)?;

            s_zy.add_assign(&eval_univar_poly::<E>(&s_neg_poly[..], y_inv, y_inv));
            s_zy.add_assign(&eval_univar_poly::<E>(&s_pos_poly[..], *y, *y));

            let opening = {
                s_zy.negate();
                poly_comm_opening(
                    n,
                    0,
                    srs,
                    s_neg_poly.iter().rev()
                        .chain_ext(Some(s_zy).iter())
                        .chain_ext(s_pos_poly.iter()),
                    *y
                )
            };

            c_openings.push((opening, s_zy));
        }

        let mut neg_poly = vec![E::Fr::zero(); n];
        let mut pos_poly = vec![E::Fr::zero(); n];
        let mut expected_value = E::Fr::zero();

        for (y, c_opening) in y_values.iter().zip(c_openings.iter()) {
            // Evaluate s(X, Y) at Y=y_i
            let (s_neg_poly, s_pos_poly) = {
                let mut sx_poly = SxEval::new(*y, n)?;
                S::synthesize(&mut sx_poly, circuit)?;

                sx_poly.neg_pos_poly()
            };

            let mut s_zy = c_opening.1;
            let r: E::Fr = transcript.challenge_scalar();
            s_zy.mul_assign(&r);
            expected_value.add_assign(&s_zy);

            mul_add_poly::<E>(&mut neg_poly[..], &s_neg_poly[..], r);
            mul_add_poly::<E>(&mut pos_poly[..], &s_pos_poly[..], r);
        }

        let s_opening = {
            let mut value = expected_value;
            value.negate();

            poly_comm_opening(
                n,
                0,
                srs,
                neg_poly.iter().rev()
                    .chain_ext(Some(value).iter())
                    .chain_ext(pos_poly.iter()),
                z
            )
        };

        Ok(Aggregate {
            c_comm,
            s_opening,
            c_openings,
            opening,
        })
    }
}
