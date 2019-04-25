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

impl<E: Engine, C: Circuit<E>, S: SynthesisDriver, R: Rng> MultiVerifier<E, C, S, R> {
    pub fn new(circuit: C, srs: &SRS<E>, rng: R) -> Result<Self, SynthesisError> {
        struct Preprocess<E: Engine> {
            k_map: Vec<usize>,
            n: usize,
            q: usize,
            _marker: PhantomData<E>
        }

        impl<'a, E: Engine> Backend<E> for &'a mut Preprocess<E> {
            fn new_multiplication_gate(&mut self) {
                self.n += 1;
            }

            fn new_linear_constraint(&mut self) {
                self.q += 1;
            }

            fn new_k_power(&mut self, index: usize) {
                self.k_map.push(index);
            }
        }

        let mut preprocess = Preprocess {
            k_map: vec![],
            n: 0,
            q: 0,
            _marker: PhantomData
        };

        S::synthesize(&mut preprocess, &circuit)?;

        Ok(MultiVerifier {
            circuit,
            // batch: Batch::new(srs, preprocess.n),
            k_map: preprocess.k_map,
            n: preprocess.n,
            q: preprocess.q,
            randommness: rng,
            _marker: PhantomData,
        })
    }
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