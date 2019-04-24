//! This module contains the helper protocol for computing aggregated signatures
//! of correct computation to ensure that an element `s` is equal to `s(z, y)` for
//! known polynomial.
//! The helper algorithm is run on a batch of proofs.

use pairing::Engine;
use crate::cs::{SynthesisDriver, Circuit};

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

    ) {
        unimplemented!();
    }
}
