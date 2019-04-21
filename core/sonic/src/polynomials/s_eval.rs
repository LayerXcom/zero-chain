use pairing::{Engine, Field};
use bellman::SynthesisError;
use crate::utils::coeffs_consecutive_powers;
use crate::cs::Backend;
use crate::cs::lc::{Variable, Coeff};
use super::add_polynomials;

/// Defined in Section 5: SYSTEM OF CONSTRAINTS
/// Evaluation of s(X, Y) at x
#[derive(Clone)]
pub struct SxEval<E: Engine> {
    y: E::Fr,

    /// Current value of y^{q+n}
    yqn: E::Fr,

    /// X^{-i} * (Y^{1+n} * u_{1,i}), X^{-i} * (Y^{2+n} * u_{2,i}),... , X^{-i} * (Y^{Q+n} * u_{Q,i})
    u: Vec<E::Fr>,

    /// X^{i} * (Y^{1+n} * v_{1,i}), X^{i} * (Y^{2+n} * v_{2,i}),... , X^{i} * (Y^{Q+n} * v_{Q,i})
    v: Vec<E::Fr>,

    /// X^{i+n} * (-Y^{i}-Y^{-i} + Y^{1+n}*w_{1,i}), X^{i+n} * (-Y^{i}-Y^{-i} + Y^{2+n}*w_{2,i}),... , X^{i+n} * (-Y^{i}-Y^{-i} + Y^{Q+n}*w_{Q,i})
    w: Vec<E::Fr>,
}

impl<E: Engine> SxEval<E> {
    ///  Initialize s(X, y) where y is fixed.
    pub fn new(y: E::Fr, n: usize) -> Result<Self, SynthesisError>  {
        let yqn = y.pow(&[n as u64]);

        // because of u_{q,i} is zero
        let u = vec![E::Fr::zero(); n];

        // because of v_{q,i} is zero
        let v = vec![E::Fr::zero(); n];

        let mut neg_one = E::Fr::one();
        neg_one.negate();

        let mut w = vec![neg_one; n];
        let mut neg_w = vec![neg_one; n];

        let y_inv = match y.inverse() {
            Some(v) => v,
            None => return Err(SynthesisError::DivisionByZero)
        };

        coeffs_consecutive_powers::<E>(&mut w[..], y, y);
        coeffs_consecutive_powers::<E>(&mut neg_w[..], y_inv, y_inv);
        add_polynomials::<E>(&mut w[..], &neg_w[..]);

        Ok(SxEval {
            y,
            yqn,
            u,
            v,
            w,
        })
    }

    /// Return polynomials each of negative and positive powers
    pub fn neg_pos_poly(mut self) -> (Vec<E::Fr>, Vec<E::Fr>) {
        self.v.extend(self.w);

        (self.u, self.v)
    }
}

impl<'a, E: Engine> Backend<E> for &'a mut SxEval<E> {
    /// One step further of q-th linear constraint
    fn new_linear_constraint(&mut self) {
        self.yqn.mul_assign(&self.y);
    }

    /// Add coefficient to a value of u and v, and w polynomials.
    fn insert_coefficient(&mut self, var: Variable, coeff: Coeff<E>) {
        let uvw_val = match var {
            Variable::A(index) => {
                &mut self.u[index - 1]
            },
            Variable::B(index) => {
                &mut self.v[index - 1]
            },
            Variable::C(index) => {
                &mut self.w[index - 1]
            },
        };

        match coeff {
            Coeff::Zero => {},
            Coeff::One => {
                // Addition is because the current value is not filled.
                uvw_val.add_assign(&self.yqn);
            },
            Coeff::NegativeOne => {
                uvw_val.sub_assign(&self.yqn);
            },
            Coeff::Full(mut val) => {
                val.mul_assign(&self.yqn);
                uvw_val.add_assign(&val);
            }
        }
    }
}
