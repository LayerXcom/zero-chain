use pairing::{Engine, Field};
use bellman::SynthesisError;
use crate::utils::coeffs_consecutive_powers;
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
}
