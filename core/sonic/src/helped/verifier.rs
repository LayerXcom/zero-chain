use pairing::Engine;
use rand::{Rand, Rng};
use bellman::SynthesisError;
use crate::cs::{Circuit, Backend, SynthesisDriver};
use crate::srs::SRS;
use super::prover::Proof;
use std::marker::PhantomData;

pub struct MultiVerifier<E: Engine, C: Circuit<E>, S: SynthesisDriver, R: Rng> {
    circuit: C,
    // pub(crate) batch: Batch<E>,
    k_map: Vec<usize>,
    n: usize,
    q: usize,
    randommness: R,
    _marker: PhantomData<(E, S)>,
}

pub fn verify_a_proof<'a, E: Engine>() {
    unimplemented!();
}

pub fn verify_proofs<E: Engine, C: Circuit<E>, S: SynthesisDriver, R: Rng>(
    proofs: &[Proof<E>],
    inputs: &[Vec<E::Fr>],
    circuit: C,
    rng: R,
    srs: &SRS<E>,
) -> Result<bool, SynthesisError> {
    unimplemented!();
}