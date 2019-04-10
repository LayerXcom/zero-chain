//! This module contains an implementtion of sonic's constraint system.
//! The form is based on (Linear-Time Zero-Knowledge Proofs for
//! Arithmetic Circuit Satisfiability)[https://eprint.iacr.org/2017/872.pdf],
//! but made several modifications as defined in section 5: SYSTEM OF CONSTRAINTS.

use pairing::{Engine, Field};
use std::marker::PhantomData;

// pub trait Circuit<E: Engine> {
//     fn synthesize<CS: ConstraintSystem<E>>
// }

/// Represents a sonic's constraint system which can have new variables
/// allocated and constrains between them formed.
pub trait ConstraintSystem<E: Engine>: Sized {

    fn alloc<F, A, AR>(
        &mut self,
        annotation: A,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>;
}