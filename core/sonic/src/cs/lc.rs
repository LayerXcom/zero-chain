//! This module contains some type difinitions like `LinearCombination`, `Variable`, and `Coeff`
//! and implementation of some operator overloadings for those types.
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

/// Return an empty linear combination
impl<E: Engine> LinearCombination<E> {
    pub fn zero() -> LinearCombination<E> {
        LinearCombination(vec![])
    }
}

impl<E: Engine> Add<LinearCombination<E>> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn add(mut self, lc: LinearCombination<E>) -> LinearCombination<E> {
        for (var, coeff) in lc.as_ref() {
            self.0.push((*var, *coeff));
        }

        self
    }
}

/// Operetor overloading for linear combination
/// `LinearCombination` + `(Coeff, Variable)` = `LinearCombination`
impl<E: Engine> Add<(Coeff<E>, Variable)> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn add(mut self, (coeff, var): (Coeff<E>, Variable)) -> LinearCombination<E> {
        self.0.push((var, coeff));
        self
    }
}

/// Operetor overloading for linear combination
/// `LinearCombination` - `(Coeff, Variable)` = `LinearCombination`
impl<E: Engine> Sub<(Coeff<E>, Variable)> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn sub(self, (coeff, var): (Coeff<E>, Variable)) -> LinearCombination<E> {
        self + (-coeff, var)
    }
}

/// Operetor overloading for linear combination
/// `LinearCombination` + `(Coeff::One, Variable)` = `LinearCombination`
impl<E: Engine> Add<Variable> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn add(self, var: Variable) -> LinearCombination<E> {
        self + (Coeff::One, var)
    }
}

/// Operetor overloading for linear combination
/// `LinearCombination` - `(Coeff::one, Variable) = `LinearCombination`
impl<E: Engine> Sub<Variable> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn sub(self, var: Variable) -> LinearCombination<E> {
        self - (Coeff::One, var)
    }
}

/// Operetor overloading for linear combination
/// `LinearCombination` + `&LinearCombination` = `LinearCombination`
impl<'a, E: Engine> Add<&'a LinearCombination<E>> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn add(mut self, other: &'a LinearCombination<E>) -> LinearCombination<E> {
        for s in &other.0 {
            // `LinearCombination` = `LinearCombination` + `(Coeff, Variable)`
            self = self + (s.1, s.0);
        }

        self
    }
}

/// Operetor overloading for linear combination
/// `LinearCombination` - `&LinearCombination` = `LinearCombination`
impl<'a, E: Engine> Sub<&'a LinearCombination<E>> for LinearCombination<E> {
    type Output = LinearCombination<E>;

    fn sub(mut self, other: &'a LinearCombination<E>) -> LinearCombination<E> {
        for s in &other.0 {
            // `LinearCombination` = `LinearCombination` - `(Coeff, Variable)`
            self = self - (s.1, s.0);
        }

        self
    }
}

/// A difinition of Variable for linear combination used in our constraint system.
#[derive(Copy, Clone, Debug)]
pub enum Variable {
    A(usize),   // input variable in r1cs
    B(usize),   // Auxillary variable in r1cs
    C(usize),
}

// like DensityTracker
/// A difinition of Coefficient for linear combination used in our constraint system.
#[derive(Debug)]
pub enum Coeff<E: Engine> {
    Zero,
    One,
    NegativeOne,
    Full(E::Fr),
}

impl<E: Engine> Copy for Coeff<E> {}
impl<E: Engine> Clone for Coeff<E> {
    fn clone(&self) -> Self {
        *self
    }
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

/// Operetor overloading for Coefficient
/// used for Substraction overloading for linear combination
impl<E: Engine> Neg for Coeff<E> {
    type Output = Coeff<E>;

    fn neg(self) -> Self {
        match self {
            Coeff::Zero => Coeff::Zero,
            Coeff::One => Coeff::NegativeOne,
            Coeff::NegativeOne => Coeff::One,
            Coeff::Full(mut a) => {
                a.negate();
                Coeff::Full(a)
            }
        }
    }
}