//! This module contains an implementtion of sonic's constraint system.
//! The form is based on (Linear-Time Zero-Knowledge Proofs for
//! Arithmetic Circuit Satisfiability)[https://eprint.iacr.org/2017/872.pdf],
//! but made several modifications as defined in section 5: SYSTEM OF CONSTRAINTS.

use pairing::{Engine, Field};
use std::marker::PhantomData;


pub mod lc;
use lc::{Variable, Coeff};

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



/// This is a backend for the `SynthesisDriver` to replay information abount
/// the concrete circuit. One backend might just collect basic information
/// about the circuit for verification, while another actually constructs
/// a witness.
pub trait Backend<E: Engine> {
    /// Get the value of a variable. Can return None if we don't know.
    fn get_var(&self, _variable: Variable) -> Option<E::Fr> { None }


}