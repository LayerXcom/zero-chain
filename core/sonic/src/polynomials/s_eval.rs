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
    pub fn new(
        x: E::Fr,
        n: usize,   // Max N
        q: usize,   // Max Q
    ) -> Result<Self, SynthesisError>
    {
        let x_inv = x.inverse().ok_or(SynthesisError::DivisionByZero)?;
        let x_n_plus_1 = x.pow(&[(n + 1) as u64]);

        let mut a = vec![E::Fr::one(); n];
        let mut b = vec![E::Fr::one(); n];
        let mut c = vec![E::Fr::one(); n];

        // Evaluate polynomial S(X, Y) at x for each coefficients u, v ,and w.
        eval_bivar_poly::<E>(&mut a[..], x_inv, x_inv);
        eval_bivar_poly::<E>(&mut b[..], x, x);
        eval_bivar_poly::<E>(&mut c[..], x_n_plus_1, x);

        let mut minus_one = E::Fr::one();
        minus_one.negate();

        // Coefficients of powers [-1, -n] and [1, n] are fixed to -1
        // because of -Y^{i}-Y^{-i} term in w_i(Y)
        let mut pos_coeffs = vec![minus_one; n];
        eval_bivar_poly::<E>(&mut pos_coeffs[..], x_n_plus_1, x);
        let neg_coeffs = pos_coeffs.clone();

        // Coefficients of powers [1+n, q+n] will be assigned with u, v, and w via synthesizing.
        // We don't append a, b, and c as coefficients because u, v, and w haven't be determined yet.
        // We store the a, b, and c as separate elements, so can add those coefficients at the time of
        // synthesizing u,v,w.
        pos_coeffs.resize(q + n, E::Fr::zero());

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

    // Evaluate S(x, Y) at y
    pub fn finalize(&self, y: E::Fr) -> Result<E::Fr, SynthesisError> {
        let y_inv = y.inverse().ok_or(SynthesisError::DivisionByZero)?;

        let pos_eval = eval_univar_poly::<E>(&self.pos_coeffs[..], y, y);
        let neg_eval = eval_univar_poly::<E>(&self.neg_coeffs[..], y_inv, y_inv);

        let mut acc = E::Fr::zero();
        acc.add_assign(&pos_eval);
        acc.add_assign(&neg_eval);

        Ok(acc)
    }
}

impl<'a, E: Engine> Backend<E> for &'a mut SyEval<E> {
    fn new_linear_constraint(&mut self) {
        self.current_q += 1;
    }

    /// Append coefficients u, v, w to Y powers [1+n, Q+n]
    fn insert_coefficient(
        &mut self,
        var: Variable,  // a, b, and c
        coeff: Coeff<E> // u, v, and w for current q
    ) {
        let y_index = self.current_q + self.max_n;

        match var {
            Variable::A(index) => {
                // index starts from 1
                let mut a = self.a[index - 1];
                coeff.multiply(&mut a);

                self.pos_coeffs[y_index - 1].add_assign(&a);
            },
            Variable::B(index) => {
                let mut b = self.b[index - 1];
                coeff.multiply(&mut b);

                self.pos_coeffs[y_index - 1].add_assign(&b);
            },
            Variable::C(index) => {
                let mut c = self.c[index - 1];
                coeff.multiply(&mut c);

                self.pos_coeffs[y_index - 1].add_assign(&c);
            }
        }
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
    /// Y^{q+n} * u_{q,1}, Y^{q+n} * u_{q,2},... , Y^{q+n} * u_{q,n}
    u: Vec<E::Fr>,

    /// Coefficients of X^{i} term
    /// Y^{q+n} * v_{q,1}, Y^{q+n} * v_{q,2},... , Y^{q+n} * v_{q,n}
    v: Vec<E::Fr>,

    /// Coefficients of X^{i+n} term
    /// -Y^{1}-Y^{-1} + Y^{q+n}*w_{q,1}, -Y^{2}-Y^{-2} + Y^{q+n}*w_{q,2},... , -Y^{n}-Y^{-n} + Y^{q+n}*w_{q,n}
    w: Vec<E::Fr>,
}

impl<E: Engine> SxEval<E> {
    pub fn new(y: E::Fr, n: usize) -> Result<Self, SynthesisError> {
        let y_inv = y.inverse().ok_or(SynthesisError::DivisionByZero)?;
        let yqn = y.pow(&[n as u64]);

        // because of u_{q,i} and q is zero
        let u = vec![E::Fr::zero(); n];

        // because of v_{q,i} and q is zero
        let v = vec![E::Fr::zero(); n];

        let mut minus_one = E::Fr::one();
        minus_one.negate();

        let mut w = vec![minus_one; n];
        let mut inv_w = vec![minus_one; n];

        eval_bivar_poly::<E>(&mut w[..], y, y);
        eval_bivar_poly::<E>(&mut inv_w[..], y_inv, y_inv);
        add_polynomials::<E>(&mut w[..], &inv_w[..]);

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
    pub fn finalize(self, x: E::Fr) -> Result<E::Fr, SynthesisError> {
        let x_inv = x.inverse().ok_or(SynthesisError::DivisionByZero)?;
        let x_n_plus_1 = x.pow(&[(self.v.len() + 1) as u64]);
        let mut acc = E::Fr::zero();

        acc.add_assign(&eval_univar_poly::<E>(&self.u, x_inv, x_inv));
        acc.add_assign(&eval_univar_poly::<E>(&self.v, x, x));
        acc.add_assign(&eval_univar_poly::<E>(&self.w, x_n_plus_1, x));

        Ok(acc)
    }
}

impl<'a, E: Engine> Backend<E> for &'a mut SxEval<E> {
    /// One step further of q-th linear constraint
    fn new_linear_constraint(&mut self) {
        self.yqn.mul_assign(&self.y);
    }

    /// Add coefficients u, v, and w terms.
    fn insert_coefficient(&mut self, var: Variable, coeff: Coeff<E>) {
        let mut yqn = self.yqn;

        match var {
            Variable::A(index) => {
                coeff.multiply(&mut yqn);

                let u = &mut self.u[index - 1];
                u.add_assign(&yqn);
            },
            Variable::B(index) => {
                coeff.multiply(&mut yqn);

                let v = &mut self.v[index - 1];
                v.add_assign(&yqn);
            },
            Variable::C(index) => {
                coeff.multiply(&mut yqn);

                let w = &mut self.w[index - 1];
                w.add_assign(&mut yqn);
            }
        }
    }
}
