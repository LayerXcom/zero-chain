use pairing::{Engine, Field};
use std::ops::{Add, Sub, Neg};


/// This represents a linear combination of some variables, with coefficients
/// in the scalar field of a pairing-friendly elliptic curve group.
#[derive(Clone)]
pub struct LinearCombination<E: Engine>(Vec<(Variable, Coeff<E>)>);

impl<E: Engine> From<Variable> for LinearCombination<E> {
    fn from(var: Variable) -> LinearCombination<E> {
        LinearCombination::<E>::zero() + var
    }
}

impl<E: Engine> AsRef<[(Variable, Coeff<E>)]> for LinearCombination<E> {
    fn as_ref(&self) -> &[(Variable, Coeff<E>)] {
        &self.0
    }
}

impl<E: Engine> LinearCombination<E> {
    pub fn zero() -> LinearCombination<E> {
        LinearCombination(vec![])
    }
}

impl<E: Engine> Add<(Coeff<E>, Variable)> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn add(mut self, (coeff, var): (Coeff<E>, Variable)) -> LinearCombination<E> {
        self.0.push((var, coeff));
        self
    }
}

impl<E: Engine> Add<Variable> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn add(mut self, var: Variable) -> LinearCombination<E> {
        self + (Coeff::One, var)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Variable {
    A(usize),   // input variable in r1cs
    B(usize),   // Auxillary variable in r1cs
    C(usize),
}

#[derive(Copy, Clone, Debug)]
pub enum Coeff<E: Engine> {
    Zero,
    One,
    NegativeOne,
    Full(E::Fr),
}

/// Multiply the coefficient with a given variable.
impl<E: Engine> Coeff<E> {
    pub fn multiply(&self, with: &mut E::Fr) {
        match self {
            Coeff::Zero => {
                *with = E::Fr::zero();
            },
            Coeff::One => {},
            Coeff::NegativeOne => {
                with.negate();
            },
            Coeff::Full(val) => {
                with.mul_assign(val);
            }
        }
    }
}