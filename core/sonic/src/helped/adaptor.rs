//! This module contains an adaptor which translates circuits written in the form of
//! quadratic "rank-1 constraint systems"(R1CS) into the system of constraints natural to
//! sonic's proving system.
//! R1CS is a constraint system which is widely deployed NP language currently undergoing
//! standardisation.

use std::marker::PhantomData;
use pairing::{Engine, CurveProjective};
use bellman::{ConstraintSystem, Variable, Index, SynthesisError};
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
    type Root = Self;

    fn one() -> Variable {
        Variable::new_unchecked(Index::Input(1))
    }

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

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
        where
            A: FnOnce() -> AR,
            AR: Into<String>,
            LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
            LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
            LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
    {
        unimplemented!();
    }
}