use pairing::{Engine, Field};
use bellman::SynthesisError;
use crate::utils::{eval_bivar_poly, eval_univar_poly};
use crate::cs::Backend;
use crate::cs::lc::{Variable, Coeff};
use super::add_polynomials;

/// Defined in Section 5: SYSTEM OF CONSTRAINTS
/// Evaluation of s(X, Y) at x
#[derive(Clone)]
pub struct SyEval<E: Engine> {
    max_n: usize,
    current_q: usize,

    /// Coefficients of u term
    /// x^{-1}, ..., x^{-N}
    a: Vec<E::Fr>,

    /// Coefficients of v term
    /// x^1, ..., x^{N}
    b: Vec<E::Fr>,

    /// Coefficients of w term
    /// x^{N+1}, ..., x^{2*N+1}
    c: Vec<E::Fr>,

    /// Coefficients of Y^1, ..., Y^{N+Q}
    pos_coeffs: Vec<E::Fr>,

    /// Coefficients of Y^{-1}, Y^{-2}, ..., Y^{-N}
    neg_coeffs: Vec<E::Fr>,
}

impl<E: Engine> SyEval<E> {
    pub fn new(x: E::Fr, n: usize, q: usize) -> Result<Self, SynthesisError> {
        let x_inv = x.inverse().ok_or(SynthesisError::DivisionByZero)?;

        let mut a = vec![E::Fr::one(); n];
        let mut b = vec![E::Fr::one(); n];
        let mut c = vec![E::Fr::one(); n];

        // Evaluate polynomial s
        eval_bivar_poly::<E>(&mut a[..], x_inv, x_inv);
        eval_bivar_poly::<E>(&mut b[..], x, x);
        eval_bivar_poly::<E>(&mut c[..], x.pow(&[(n+1) as u64]), x);

        let mut minus_one = E::Fr::one();
        minus_one.negate();

        // Coefficients of powers [-1, -n] and [1, n] are fixed to -1
        // because of -Y^{i}-Y^{-i} term in w_i(Y)
        let mut pos_coeffs = vec![minus_one; n];
        eval_bivar_poly::<E>(&mut pos_coeffs[..], x.pow(&[(n+1) as u64]), x);
        let neg_coeffs = pos_coeffs.clone();

        // Coefficients of powers [1+n, n+q] will be assigned via synthesizing.
        pos_coeffs.resize(n+q, E::Fr::zero());

        Ok(SyEval {
            max_n: n,
            current_q: 0,
            a,
            b,
            c,
            pos_coeffs,
            neg_coeffs,
        })
    }

    /// Return polynomials each of negative and positive powers
    pub fn neg_pos_poly(self) -> (Vec<E::Fr>, Vec<E::Fr>) {
        (self.neg_coeffs, self.pos_coeffs)
    }
}

impl<'a, E: Engine> Backend<E> for &'a mut SyEval<E> {
    fn new_linear_constraint(&mut self) {
        self.current_q += 1;
    }

    fn insert_coefficient(&mut self, var: Variable, coeff: Coeff<E>) {
        match var {
            Variable::A(index) => {
                let index = index - 1;

                // Y^{q+N} += X^{-i} * coeff
                let mut tmp = self.a[index];
                coeff.multiply(&mut tmp);

                let y_idnex = self.current_q + self.max_n;
                self.pos_coeffs[y_idnex - 1].add_assign(&tmp);

            },
            Variable::B(index) => {
                let index = index - 1;

                // Y^{q+N} += X^{i} * coeff
                let mut tmp = self.b[index];
                coeff.multiply(&mut tmp);

                let y_index = self.current_q + self.max_n;
                self.pos_coeffs[y_index - 1].add_assign(&tmp);
            },
            Variable::C(index) => {
                let index = index - 1;

                // Y^{q+N} += X^{i+N} * coeff
                let mut tmp = self.c[index];
                coeff.multiply(&mut tmp);

                let y_index = self.current_q + self.max_n;
                self.pos_coeffs[y_index - 1].add_assign(&tmp);
            }
        };
    }
}

/// Defined in Section 5: SYSTEM OF CONSTRAINTS
/// Evaluation of s(X, Y) at y
#[derive(Clone)]
pub struct SxEval<E: Engine> {
    y: E::Fr,

    /// Current value of y^{q+n}
    yqn: E::Fr,

    /// Coefficients of X^{-i} term
    /// Y^{1+n} * u_{1,i}, Y^{2+n} * u_{2,i},... , Y^{Q+n} * u_{Q,i}
    u: Vec<E::Fr>,

    /// Coefficients of X^{i} term
    /// Y^{1+n} * v_{1,i}, Y^{2+n} * v_{2,i},... , Y^{Q+n} * v_{Q,i}
    v: Vec<E::Fr>,

    /// Coefficients of X^{i+n} term
    /// -Y^{i}-Y^{-i} + Y^{1+n}*w_{1,i}, -Y^{i}-Y^{-i} + Y^{2+n}*w_{2,i},... , -Y^{i}-Y^{-i} + Y^{Q+n}*w_{Q,i}
    w: Vec<E::Fr>,
}

impl<E: Engine> SxEval<E> {
    ///  Initialize s(X, y) where y is fixed.
    pub fn new(y: E::Fr, n: usize) -> Result<Self, SynthesisError>  {
        let y_inv = y.inverse().ok_or(SynthesisError::DivisionByZero)?;
        let yqn = y.pow(&[n as u64]);

        // because of u_{q,i} is zero
        let u = vec![E::Fr::zero(); n];

        // because of v_{q,i} is zero
        let v = vec![E::Fr::zero(); n];

        let mut minus_one = E::Fr::one();
        minus_one.negate();

        let mut w = vec![minus_one; n];
        let mut neg_w = vec![minus_one; n];

        eval_bivar_poly::<E>(&mut w[..], y, y);
        eval_bivar_poly::<E>(&mut neg_w[..], y_inv, y_inv);
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

    /// Evaluation of s(X, y) at x
    pub fn finalize(self, x: E::Fr) -> E::Fr {
        let x_inv = x.inverse().unwrap();
        let mut res = E::Fr::zero();

        let tmp = x_inv;
        res.add_assign(&eval_univar_poly::<E>(&self.u[..], tmp, tmp));

        let tmp = x;
        res.add_assign(&eval_univar_poly::<E>(&self.v[..], tmp, tmp));

        let tmp = x.pow(&[(self.v.len()+1) as u64]);
        res.add_assign(&eval_univar_poly::<E>(&self.w[..], tmp, x));

        res
    }
}

impl<'a, E: Engine> Backend<E> for &'a mut SxEval<E> {
    /// One step further of q-th linear constraint
    fn new_linear_constraint(&mut self) {
        self.yqn.mul_assign(&self.y);
    }

    /// Add coefficients u, v, and w to a polynomial.
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
