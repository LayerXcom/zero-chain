//! This module contains an implementtion of sonic's constraint system.
//! The form is based on (Linear-Time Zero-Knowledge Proofs for
//! Arithmetic Circuit Satisfiability)[https://eprint.iacr.org/2017/872.pdf],
//! but made several modifications as defined in section 5: SYSTEM OF CONSTRAINTS.

use pairing::{Engine, Field};
use std::marker::PhantomData;
use bellman::SynthesisError;

pub mod lc;
pub mod permutation;
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

    /// Constrain a linear combination to zero.
    fn enforce_zero(&mut self, lc: LinearCombination<E>);

    /// Constrain each varible to multiplication gate.
    fn multiply<F>(&mut self, values: F) -> Result<(Variable, Variable, Variable), SynthesisError>
        where F: FnOnce() -> Result<(E::Fr, E::Fr, E::Fr), SynthesisError>;

    /// Get a value corresponding to the given variable
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
/// Synthesize circuits to the backend object.
pub trait SynthesisDriver {
    fn synthesize<E: Engine, C: Circuit<E>, B: Backend<E>> (backend: B, circuit: &C)
        -> Result<(), SynthesisError>;
}

pub struct Basic;

impl SynthesisDriver for Basic {
    fn synthesize<E: Engine, C: Circuit<E>, B: Backend<E>>(backend: B, circuit: &C)
        -> Result<(), SynthesisError>
    {
        struct Synthesizer<E: Engine, B: Backend<E>> {
            backend: B,
            current_variable: Option<usize>,    // Index of the current variable
            q: usize,                           // q-th linear constraint
            n: usize,                           // Degree of the current synthesizing step
            _marker: PhantomData<E>,
        }

        impl<E: Engine, B: Backend<E>> ConstraintSystem<E> for Synthesizer<E, B> {
            // Variable starts from index 1
            const ONE: Variable = Variable::A(1);

            fn alloc<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
            where
                F: FnOnce() -> Result<E::Fr, SynthesisError>
            {
                match self.current_variable.take() {
                    Some(index) => {
                        let var_a = Variable::A(index);
                        let var_b = Variable::B(index);
                        let var_c = Variable::C(index);

                        let mut product = None;

                        let value_a = self.backend.get_var(var_a);

                        // Set the value_b from the argument to the variable B
                        // and then calculate a product of value_a and value_b.
                        self.backend.set_var(var_b, || {
                            let value_b = value()?;
                            product = Some(value_a.ok_or(SynthesisError::AssignmentMissing)?);
                            product.as_mut().map(|product| product.mul_assign(&value_b));

                            Ok(value_b)
                        })?;

                        // Set the product to the variable C
                        self.backend.set_var(var_c, || {
                            product.ok_or(SynthesisError::AssignmentMissing)
                        })?;

                        self.current_variable = None;

                        // Return the Variable
                        Ok(var_b)
                    },
                    None => {
                        // One step further because there's not variable in the degree
                        self.n += 1;
                        let index = self.n;

                        self.backend.new_multiplication_gate();
                        let var_a = Variable::A(index);

                        self.backend.set_var(var_a, value)?;
                        self.current_variable = Some(index);

                        Ok(var_a)
                    }
                }
            }

            fn alloc_input<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
            where
                F: FnOnce() -> Result<E::Fr, SynthesisError>
            {
                let input_var = self.alloc(value)?;

                self.enforce_zero(LinearCombination::zero() + input_var);
                self.backend.new_k_power(self.q);

                Ok(input_var)
            }

            fn enforce_zero(&mut self, lc: LinearCombination<E>) {
                self.q += 1;
                self.backend.new_linear_constraint();

                for (var, coeff) in lc.as_ref() {
                    self.backend.insert_coefficient(*var, *coeff);
                }
            }

            fn multiply<F>(&mut self, values: F)
                -> Result<(Variable, Variable, Variable), SynthesisError>
            where
                F: FnOnce() -> Result<(E::Fr, E::Fr, E::Fr), SynthesisError>
            {
                self.n += 1;
                let index = self.n;
                self.backend.new_multiplication_gate();

                let var_a = Variable::A(index);
                let var_b = Variable::B(index);
                let var_c = Variable::C(index);

                let mut value_b = None;
                let mut value_c = None;

                self.backend.set_var(var_a, || {
                    let (a, b, c) = values()?;

                    value_b = Some(b);
                    value_c = Some(c);

                    Ok(a)
                })?;

                self.backend.set_var(var_b, || {
                    value_b.ok_or(SynthesisError::AssignmentMissing)
                })?;

                self.backend.set_var(var_c, || {
                    value_c.ok_or(SynthesisError::AssignmentMissing)
                })?;

                Ok((var_a, var_b, var_c))
            }

            fn get_value(&self, var: Variable) -> Result<E::Fr, ()> {
                self.backend.get_var(var).ok_or(())
            }
        }

        let mut instance: Synthesizer<E, B> = Synthesizer {
            backend: backend,
            current_variable: None,
            q: 0,
            n: 0,
            _marker: PhantomData,
        };

        let one_var = instance.alloc_input(|| Ok(E::Fr::one())).expect("should have no issues.");

        match (one_var, <Synthesizer<E, B> as ConstraintSystem<E>>::ONE) {
            (Variable::A(1), Variable::A(1)) => {},
            _ => panic!("one variable is incorrect.")
        }

        circuit.synthesize(&mut instance)?;

        Ok(())
    }
}
