//! This module contains the helper protocol for computing aggregated signatures
//! of correct computation to ensure that an element `s` is equal to `s(z, y)` for
//! known polynomial.
//! The helper algorithm is run on a batch of proofs.

use pairing::Engine;
use bellman::SynthesisError;
use merlin::Transcript;
use crate::cs::{SynthesisDriver, Circuit};
use crate::srs::SRS;
use crate::transcript::ProvingTranscript;
use super::prover::{Proof, SxyAdvice};

#[derive(Clone)]
pub struct Aggregate<E: Engine> {
    /// Commitment to s(z, Y)
    pub c: E::G1Affine,

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

        for &(ref proof, ref sxyadvice) in inputs {
            {
                let mut transcript = Transcript::new(&[]);
                transcript.commit_point(&proof.r_comm);
                y_values.push(transcript.challenge_scalar());
            }

            transcript.commit_point(&sxyadvice.s_comm);
        }

        let z: E::Fr = transcript.challenge_scalar();

        // let (s_neg_poly, s_pos_poly) = {

        // };

        unimplemented!();
    }
}
