//! This module contains an adaptor which translates circuits written in the form of
//! quadratic "rank-1 constraint systems"(R1CS) into the system of constraints natural to
//! sonic's proving system.
//! R1CS is a constraint system which is widely deployed NP language currently undergoing
//! standardisation.

use std::marker::PhantomData;
use pairing::{Engine, CurveProjective, Field};
use bellman::{ConstraintSystem, Variable, Index, SynthesisError, LinearCombination, Circuit};
use crate::cs::{
    ConstraintSystem as SonicCS,
    Variable as SonicVar,
    Coeff as SonicCoeff,
    LinearCombination as SonicLC,
    Circuit as SonicCircuit,
    };

/// Define an adaptor type which translates R1CS to Sonic's constraint system.
pub struct Adaptor<'a, E: Engine, CS: SonicCS<E> + 'a> {
    cs: &'a mut CS,
    _maker: PhantomData<E>,
}

/// Apply R1CS trait to Adaptor type
impl <'a, E: Engine, CS: SonicCS<E> + 'a> ConstraintSystem<E>
    for Adaptor<'a, E, CS>
{
    /// Represents the type of the "root" of this constraint system
    /// so that nested namespaces can minimize indirection.
    type Root = Self;

    /// Return the "one" input variable
    fn one() -> Variable {
        Variable::new_unchecked(Index::Input(1))
    }

    /// Allocate a private variable in the constraint system. The provided function is used to
    /// determine the assignment of the variable.
    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
        where
            F: FnOnce() -> Result<E::Fr, SynthesisError>,
            A: FnOnce() -> AR,
            AR: Into<String>,
    {
        // Get a allocated private variable in the sonic's constraint system.
        let var = self.cs.alloc(|| {
            f().map_err(|_| SynthesisError::AssignmentMissing)
        }).map_err(|_| SynthesisError::AssignmentMissing)?;

        Ok(match var {
            SonicVar::A(index) => Variable::new_unchecked(Index::Input(index)),
            SonicVar::B(index) => Variable::new_unchecked(Index::Aux(index)),
            _ => unreachable!(),
        })
    }

    /// Allocate a public variable in the constraint system. The provided function is used to
    /// determine the assignment of the variable.
    fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
        where
            F: FnOnce() -> Result<E::Fr, SynthesisError>,
            A: FnOnce() -> AR,
            AR: Into<String>,
    {
        let var = self.cs.alloc_input(|| {
            f().map_err(|_| SynthesisError::AssignmentMissing)
        }).map_err(|_| SynthesisError::AssignmentMissing)?;

        Ok(match var {
            SonicVar::A(index) => Variable::new_unchecked(Index::Input(index)),
            SonicVar::B(index) => Variable::new_unchecked(Index::Aux(index)),
            _ => unreachable!(),
        })
    }



    /// Enforce that `A` * `B` = `C`.
    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
        where
            A: FnOnce() -> AR,
            AR: Into<String>,
            LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
            LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
            LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
    {
        /// Convert r1cs's linear combination to sonic's one.
        fn convert<E: Engine>(lc: LinearCombination<E>) -> SonicLC<E> {
            let mut ret = SonicLC::zero();

            for &(v, coeff) in lc.as_ref().iter() {
                let var = match v.get_unchecked() {
                    Index::Input(i) => SonicVar::A(i),
                    Index::Aux(i) => SonicVar::B(i),
                };

                ret = ret + (SonicCoeff::Full(coeff), var);
            }

            ret
        }

        /// Get an evaluation of a linear combination.
        fn eval<E: Engine, CS: SonicCS<E>>(
            lc: &SonicLC<E>,
            cs: &CS,
        ) -> Option<E::Fr> {
            let mut ret = E::Fr::zero();

            for &(v, coeff) in lc.as_ref().iter() {
                let mut tmp = match cs.get_value(v) {
                    Ok(tmp) => tmp,
                    Err(_) => return None,
                };
                coeff.multiply(&mut tmp);
                ret.add_assign(&tmp);
            }

            Some(ret)
        }

        // Get each sonic's linear combination and evaluated value
        let a_lc = convert(a(LinearCombination::zero()));
        let a_value = eval(&a_lc, &*self.cs);
        let b_lc = convert(b(LinearCombination::zero()));
        let b_value = eval(&b_lc, &*self.cs);
        let c_lc = convert(c(LinearCombination::zero()));
        let c_value = eval(&c_lc, &*self.cs);

        // Convert scalars into variables in a multipilication gate.
        let (a, b, c) = self
            .cs
            .multiply(|| Ok((a_value.unwrap(), b_value.unwrap(), c_value.unwrap())))
            .unwrap();

        // Ensure each linear conbination is equal to evaluated value
        self.cs.enforce_zero(a_lc - a);
        self.cs.enforce_zero(b_lc - b);
        self.cs.enforce_zero(c_lc - c);
    }

    fn push_namespace<NR, N>(&mut self, _: N)
        where
            NR: Into<String>,
            N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

#[derive(Clone)]
pub struct AdaptorCircuit<T>(pub T);

impl<'a, E: Engine, C: Circuit<E> + Clone> SonicCircuit<E> for AdaptorCircuit<C> {
    fn synthesize<CS: SonicCS<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let mut adaptor = Adaptor {
            cs,
            _maker: PhantomData,
        };

        self.0.clone().synthesize(&mut adaptor)?;

        Ok(())
    }
}
