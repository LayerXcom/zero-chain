// use pairing::{Engine, Field};
// use bellman::SynthesisError;
// use rand::{Rand, Rng, thread_rng};
// use crate::cs::{SynthesisDriver, Circuit};
// use crate::srs::SRS;

// #[derive(Clone, Debug, Eq)]
// pub struct Proof<E: Engine> {
//     pub r: E::G1Affine,
// }

// impl<E: Engine> for <E>Proof<E>
// {
//     fn create_proof_on_srs<C: Circuit<E>, S: SynthesisDriver>(circuit: &C, srs: &SRS<E>)
//         -> Result<Self, SynthesisError>
//     {
//         unimplemented!();
//     }
// }