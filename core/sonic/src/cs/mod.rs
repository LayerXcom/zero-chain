//! This module contains an implementtion of sonic's constraint system.
//! The form is based on (Linear-Time Zero-Knowledge Proofs for
//! Arithmetic Circuit Satisfiability)[https://eprint.iacr.org/2017/872.pdf],
//! but made several modifications as defined in section 5: SYSTEM OF CONSTRAINTS.

use pairing::{Engine, Field};
use std::marker::PhantomData;
use bellman::SynthesisError;

pub mod lc;
pub use lc::{Variable, Coeff, LinearCombination};

pub trait Circuit<E: Engine> {
    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError>;
}

/// Represents a sonic's constraint system which can have new variables
/// allocated and constrains between them formed.
pub trait ConstraintSystem<E: Engine>: Sized {
    const ONE: Variable;

    /// Allocate a private variable in the constraint system.
    /// The provided function is used to determin the assignment of the variable.
    fn alloc<F>(
        &mut self,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>;

    /// Allocate a public variable in the constraint system.
    /// The provided function is used to determine the assignment of the variable.
    fn alloc_input<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>;

    /// Enforce that `LinearCombination` = 0
    fn enforce_zero(&mut self, lc: LinearCombination<E>);

    fn multiply<F>(&mut self, values: F) -> Result<(Variable, Variable, Variable), SynthesisError>
        where F: FnOnce() -> Result<(E::Fr, E::Fr, E::Fr), SynthesisError>;

    fn get_value(&self, _var: Variable) -> Result<E::Fr, ()> { Err(()) }
}

/// This is a backend for the `SynthesisDriver` to replay information abount
/// the concrete circuit. One backend might just collect basic information
/// about the circuit for verification, while another actually constructs
/// a witness.
pub trait Backend<E: Engine> {
    /// Get the value of a variable. Can return None if we don't know.
    fn get_var(&self, _variable: Variable) -> Option<E::Fr> { None }

    /// Set the value of a variable. Might error if this backend expects to know it.
    fn set_var<F>(&mut self, _variable: Variable, _value: F) -> Result<(), SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError> { Ok(()) }

    /// Create a new multiplication gate.
    fn new_multiplication_gate(&mut self) { }

    /// Create a new linear constraint.
    fn new_linear_constraint(&mut self) { }

    /// Insert a term into a linear constraint.
    fn insert_coefficient(&mut self, _var: Variable, _coeff: Coeff<E>) { }

    /// Mark y^{_index} as the power of y cooresponding to the public input
    /// coeefficient for the next public input, in the k(Y) polynomial.
    fn new_k_power(&mut self, _index: usize) { }
}

/// This is an abstraction which synthesizes circuits.
pub trait SynthesisDriver {
    fn synthesize<E: Engine, C: Circuit<E>, B: Backend<E>> (backend: B, circuit: &C)
        -> Result<(), SynthesisError>;
}

pub struct Basic;

impl SynthesisDriver for Basic {
    fn synthesize<E: Engine, C: Circuit<E>, B: Backend<E>>(backend: B, circuit: &C)
        -> Result<(), SynthesisError>
    {
        unimplemented!();
    }
}