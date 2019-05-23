use pairing::{Engine, Field};
use bellman::SynthesisError;
use crate::cs::{Backend, Variable, Coeff};

pub struct SxPerm<E: Engine> {
    y: E::Fr,

    max_n: usize,

    current_q: usize,

    /// Current value of y^{q}
    yq: E::Fr,

    /// Coefficients of X^{-i+n+1} term
    u: Vec<E::Fr>,
    u_q: Vec<usize>,

    /// Coefficients of X^{i+n+1} term
    v: Vec<E::Fr>,
    v_q: Vec<usize>,

    /// Coefficients of X^{i+2n+1} term
    w: Vec<E::Fr>,
    w_q: Vec<usize>,
}

impl<E: Engine> SxPerm<E> {
    pub fn new(y: E::Fr, n: usize) -> Self {
        // because of u_{q,i} and q is zero
        let u = vec![E::Fr::zero(); n];
        let u_q = vec![0; n];

        // because of v_{q,i} and q is zero
        let v = vec![E::Fr::zero(); n];
        let v_q = vec![0; n];

        // because of w_{q,i} and q is zero
        let w = vec![E::Fr::zero(); n];
        let w_q = vec![0; n];

        SxPerm {
            y,
            max_n: n,
            current_q: 0,
            yq: E::Fr::one(),
            u,
            u_q,
            v,
            v_q,
            w,
            w_q,
        }
    }

    pub fn poly(self) -> Vec<Vec<E::Fr>> {
        vec![self.u, self.v, self.w]
    }

    pub fn perm(self) -> Vec<Vec<usize>> {
        vec![self.u_q, self.v_q, self.w_q]
    }
}

impl<'a, E: Engine> Backend<E> for &'a mut SxPerm<E> {
    fn new_linear_constraint(&mut self) {
        self.yq.mul_assign(&self.y);
        self.current_q += 1;
    }

    fn insert_coefficient(&mut self, var: Variable, coeff: Coeff<E>) {
        let mut yq = self.yq;

        match var {
            Variable::A(index) => {
                coeff.multiply(&mut yq);

                let u = &mut self.u[index - 1];
                u.add_assign(&yq);

                let u_q = &mut self.u_q[index - 1];
                *u_q += self.current_q;
            },
            Variable::B(index) => {
                coeff.multiply(&mut yq);

                let v = &mut self.v[index - 1];
                v.add_assign(&yq);

                let v_q = &mut self.v_q[index - 1];
                *v_q += self.current_q;
            },
            Variable::C(index) => {
                coeff.multiply(&mut yq);

                let w = &mut self.w[index - 1];
                w.add_assign(&yq);

                let w_q = &mut self.w_q[index - 1];
                *w_q += self.current_q;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::{PrimeField, CurveAffine, CurveProjective};
    use crate::cs::{Basic, ConstraintSystem, LinearCombination, Circuit, SynthesisDriver};
    use rand::{thread_rng};
    use crate::polynomials::{PolyComm, Polynomial};
    use crate::srs::SRS;

    struct SimpleCircuit;

    impl<E: Engine> Circuit<E> for SimpleCircuit {
        fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS)
            -> Result<(), SynthesisError>
        {
            let (a, b, _) = cs.multiply(|| {
                Ok((
                    E::Fr::from_str("10").unwrap(),
                    E::Fr::from_str("20").unwrap(),
                    E::Fr::from_str("200").unwrap(),
                ))
            })?;

            cs.enforce_zero(LinearCombination::from(a) + a - b);

            Ok(())
        }
    }

    fn dummy_s_prove<E: Engine, C: Circuit<E>, S: SynthesisDriver>(
        circuit: &C,
        n: usize,
    ) -> Vec<Vec<usize>> {
        let y = E::Fr::from_str("2").unwrap();

        let perm = {
            let mut s_1 = SxPerm::new(y, n);
            S::synthesize(&mut s_1, circuit);

            s_1.perm()
        };

        perm
    }

    #[test]
    fn test_perm_s1() {
        let perm = dummy_s_prove::<Bls12, _, Basic>(&SimpleCircuit, 1 << 4);
        println!("perm: {:?}", perm);
    }
}
