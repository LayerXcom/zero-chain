use pairing::{Engine, Field};
use bellman::SynthesisError;
use rand::{Rand, Rng, thread_rng};
use crate::cs::{SynthesisDriver, Circuit};
use crate::srs::SRS;

#[derive(Clone, Debug, Eq)]
pub struct Proof<E: Engine> {
    /// A commitment of `r(X, 1)`
    pub r_comm: E::G1Affine,

    /// A commitment of `t(X, y)`. `y` represents a random challenge from the verifier.
    pub t_comm: E::G1Affine,

    /// An evaluation `r(z, 1)`. `z` represents a random challenge from the verifier.
    pub r_z1: E::Fr,

    /// An evaluation `r(z, y)`. `y` and `z` represent a random challenge from the verifier.
    pub r_zy: E::Fr,

    /// An opening of `r(z, 1)`.
    pub z1_opening: E::G1Affine,

    /// An opening of `r(z, y)`.
    pub zy_opening: E::G1Affine,
}

impl<E: Engine> for Proof<E> {
    pub fn create_proof<C: Circuit<E>, S: SynthesisDriver>(
        circuit: &C,
        srs: &SRS<E>
    ) -> Result<Self, SynthesisError>
    {
        unimplemented!();
    }
}
