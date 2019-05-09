use pairing::{Engine, Field};
use bellman::SynthesisError;
use rand::{Rand, Rng, thread_rng};
use merlin::Transcript;
use crate::cs::{SynthesisDriver, Circuit, Backend, Variable, Coeff};
use crate::srs::SRS;
use crate::transcript::ProvingTranscript;
use crate::polynomials::{Polynomial, poly_comm, poly_comm_opening, SxEval, add_polynomials, mul_polynomials};
use crate::utils::{ChainExt, eval_bivar_poly, eval_univar_poly, mul_add_poly};

pub const NUM_BLINDINGS: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<E: Engine> {
    /// A commitment of `r(X, 1)`
    pub r_comm: E::G1Affine,

    /// A commitment of `t(X, y)`. `y` represents a random challenge from the verifier.
    pub t_comm: E::G1Affine,

    /// An evaluation `r(z, 1)`. `z` represents a random challenge from the verifier.
    pub r_z1: E::Fr,

    /// An evaluation `r(z, y)`. `y` and `z` represent a random challenge from the verifier.
    pub r_zy: E::Fr,

    /// An opening of `t(z, y)` and `r(z, 1)` which are evaluated at `X = z`.
    pub z_opening: E::G1Affine,

    /// An opening of `r(z, y)` which are evaluated at `X = yz`.
    pub yz_opening: E::G1Affine,
}

impl<E: Engine> Proof<E> {
    pub fn create_proof<C: Circuit<E>, S: SynthesisDriver>(
        circuit: &C,
        srs: &SRS<E>
    ) -> Result<Self, SynthesisError>
    {
        let mut wires = Wires {
            a: vec![],
            b: vec![],
            c: vec![],
        };

        // Synthesize polynomial coefficients from circuit
        S::synthesize(&mut wires, circuit)?;

        let n = wires.a.len();
        // TODO: Make better entropy
        let rng = &mut thread_rng();
        let mut transcript = Transcript::new(&[]);


        // ------------------------------------------------------
        // zkP_1(info, a, b, c) -> R:
        // ------------------------------------------------------

        // c_{n+1}, c_{n+2}, c_{n+3}, c_{n+4} <- F_p
        let blindings: Vec<E::Fr> = (0..NUM_BLINDINGS)
            .into_iter()
            .map(|_| E::Fr::rand(rng))
            .collect();

        // A coefficients vector which can be used in common with polynomials r and r'
        // associated with powers for X.
        let mut r_x1 = wires.b;         // X^{-n}...X^{-1}
        r_x1.extend(wires.c);           // X^{-2n}...X^{-n-1}
        r_x1.extend(blindings); // X^{-2n-4}...X^{-2n-1}
        r_x1.reverse();
        r_x1.push(E::Fr::zero());
        r_x1.extend(wires.a);           // X^{1}...X^{n}

        let r_comm = Polynomial::from_slice(&mut r_x1[..]).commit(
            n,
            2*n + NUM_BLINDINGS,
            n,
            &srs
        );

        // A prover commits polynomial
        transcript.commit_point(&r_comm);


        // ------------------------------------------------------
        // zkV -> zkP: Send y <- F_p to prover
        // ------------------------------------------------------

        // A varifier send to challenge scalar to prover
        let y: E::Fr = transcript.challenge_scalar();
        let y_inv = y.inverse().ok_or(SynthesisError::DivisionByZero)?;
        let y_first_power = y_inv.pow(&[(2 * n + NUM_BLINDINGS) as u64]);


        // ------------------------------------------------------
        // zkP_2(y) -> T:
        // ------------------------------------------------------

        // powers: [-2n-4, n]
        let mut r_xy = r_x1.clone();

        // Evaluate the polynomial r(X, Y) at y
        eval_bivar_poly::<E>(
            &mut r_xy,
            y_first_power,
            y,
        );

        // negative powers [-1, -n], positive [1, 2n] of Polynomial s(X, y)
        let (mut s_neg_poly, s_pos_poly) = {
            let mut sx_poly = SxEval::new(y, n)?;
            S::synthesize(&mut sx_poly, circuit)?;

            sx_poly.neg_pos_poly()
        };

        // Evaluate the polynomial r'(X, Y) = r(X, Y) + s(X, Y) at y
        let mut r_xy_prime = r_xy.clone();
        {
            // extend to have powers [n+1, 2n] for w_i(Y)X^{i+n}
            r_xy_prime.resize(4 * n + 1 + NUM_BLINDINGS, E::Fr::zero());
            // negative powers: [-n, -1]
            s_neg_poly.reverse();

            let neg_poly_len = s_neg_poly.len();
            // Add negative powers [-n, -1]
            add_polynomials::<E>(&mut r_xy_prime[(neg_poly_len + NUM_BLINDINGS)..(2 * n + NUM_BLINDINGS)], &s_neg_poly[..]);
            s_neg_poly.reverse();

            // Add positive powers [1, 2n]
            add_polynomials::<E>(&mut r_xy_prime[(2 * n + 1 + NUM_BLINDINGS)..], &s_pos_poly[..]);
        }

        // Compute t(X, y) = r(X, 1) * r'(X, y)
        let mut t_xy = mul_polynomials::<E>(&r_x1[..], &r_xy_prime[..])?;
        // the constant term of t(X,Y) is zero
        t_xy[4 * n + 2 * NUM_BLINDINGS] = E::Fr::zero(); // -k(y)

        // commitment of t(X, y)
        let mut t_comm_vec = t_xy[..(4 * n + 2 * NUM_BLINDINGS)].iter()
                .chain_ext(t_xy[(4 * n + 2 * NUM_BLINDINGS + 1)..].iter())
                .map(|e| *e)
                .collect::<Vec<_>>();

        let t_comm = Polynomial::from_slice(&mut t_comm_vec[..])
                .commit(
                    srs.d,
                    4 * n + 2 * NUM_BLINDINGS,
                    3 * n,
                    srs
                );

        transcript.commit_point(&t_comm);


        // ------------------------------------------------------
        // zkV -> zkP: Send z <- F_p to prover
        // ------------------------------------------------------

        // A varifier send to challenge scalar to prover
        let z: E::Fr = transcript.challenge_scalar();
        let z_inv = z.inverse().ok_or(SynthesisError::DivisionByZero)?;
        let z_first_power = z_inv.pow(&[(2 * n + NUM_BLINDINGS) as u64]);

        // ------------------------------------------------------
        // zkP_3(z) -> (a, W_a, b, W_b, W_t, s, sc):
        // ------------------------------------------------------

        // r(X, 1) -> r(z, 1)
        let r_z1 = eval_univar_poly::<E>(&r_x1, z_first_power, z);
        transcript.commit_scalar(&r_z1);

        // Ensure: r(X, 1) -> r(yz, 1) = r(z, y)
        // let r_zy = evaluate_poly(&r_x1, z_first_power, z*y);
        // r(X, y) -> r(z, y)
        let r_zy = eval_univar_poly::<E>(&r_xy, z_first_power, z);
        transcript.commit_scalar(&r_zy);

        let r1: E::Fr = transcript.challenge_scalar();

        // An opening of r(X, 1) at yz
        let yz_opening = {
            // r(X, 1) - r(z, y)
            // substract constant term from r(X, 1)
            r_x1[2 * n + NUM_BLINDINGS].sub_assign(&r_zy);

            let mut point = y;
            point.mul_assign(&z);

            poly_comm_opening(
                2 * n + NUM_BLINDINGS,
                n,
                srs,
                &r_x1,
                point
            )
        };

        assert_eq!(r_x1.len(), 3*n + NUM_BLINDINGS + 1);

        // An opening of t(X, y) and r(X, 1) at z
        let z_opening = {
            // Add constant term
            r_x1[(2 * n + NUM_BLINDINGS)].add_assign(&r_zy);

            let r_x1_len = r_x1.len();

            // Batching polynomial commitments t(X, y) and r(X, 1)
            // powers domain: [-2n-4, n]
            mul_add_poly::<E>(
                &mut t_xy[(2 * n + NUM_BLINDINGS)..(2 * n + NUM_BLINDINGS + r_x1_len)],
                &r_x1[..],
                r1
            );

            // Evaluate t(X, y) at z
            let t_zy = {
                let z4_first_power = z_inv.pow(&[(4 * n + 2 * NUM_BLINDINGS) as u64]);
                eval_univar_poly::<E>(&t_xy, z4_first_power, z)
            };

            // Sub constant term
            t_xy[(4 * n + 2 * NUM_BLINDINGS)].sub_assign(&t_zy);

            poly_comm_opening(
                4 * n + 2 * NUM_BLINDINGS,
                3 * n,
                srs,
                &t_xy,
                z
            )
        };

        Ok(
            Proof {
                r_comm,
                t_comm,
                r_z1,
                r_zy,
                z_opening,
                yz_opening,
            }
        )
    }
}

/// Three vectors representing the left inputs, right inputs, and outputs of
/// multiplication constraints respectively in sonic's constraint system.
/// Basically, these are value of a variable.
struct Wires<E: Engine> {
    a: Vec<E::Fr>,
    b: Vec<E::Fr>,
    c: Vec<E::Fr>
}

impl<'a, E: Engine> Backend<E> for &'a mut Wires<E> {
    fn new_multiplication_gate(&mut self) {
        self.a.push(E::Fr::zero());
        self.b.push(E::Fr::zero());
        self.c.push(E::Fr::zero());
    }

    fn get_var(&self, var: Variable) -> Option<E::Fr> {
        Some(match var {
            Variable::A(index) => {
                self.a[index - 1]
            },
            Variable::B(index) => {
                self.b[index - 1]
            },
            Variable::C(index) => {
                self.c[index - 1]
            }
        })
    }

    fn set_var<F>(&mut self, var: Variable, value: F) -> Result<(), SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>
    {
        let value = value()?;

        match var {
            Variable::A(index) => {
                self.a[index - 1] = value;
            },
            Variable::B(index) => {
                self.b[index - 1] = value;
            },
            Variable::C(index) => {
                self.c[index - 1] = value;
            },
        }

        Ok(())
    }
}


pub struct SxyAdvice<E: Engine> {
    pub s_comm: E::G1Affine, // TODO: commitment type
    pub s_zy_opening: E::G1Affine, // TODO: W opening type
    pub s_zy: E::Fr, // s(z, y)
}

impl<E: Engine> SxyAdvice<E> {
    pub fn create_advice<C: Circuit<E>, S: SynthesisDriver> (
        circuit: &C,
        proof: &Proof<E>,
        srs: &SRS<E>,
        n: usize,
    ) -> Result<Self, SynthesisError>
    {
        let y: E::Fr;
        let z: E::Fr;

        {
            let mut transcript = Transcript::new(&[]);

            transcript.commit_point(&proof.r_comm);
            y = transcript.challenge_scalar();

            transcript.commit_point(&proof.t_comm);
            z = transcript.challenge_scalar();
        }

        let z_inv = z.inverse().ok_or(SynthesisError::DivisionByZero)?;

        let (s_neg_poly, s_pos_poly) = {
            let mut sx_poly = SxEval::new(y, n)?;
            S::synthesize(&mut sx_poly, circuit)?;

            sx_poly.neg_pos_poly()
        };

        // a commitment to s(X, y)
        let s_comm = poly_comm(
            srs.d,
            n,
            2 * n,
            srs,
            s_neg_poly.iter()
                .chain_ext(s_pos_poly.iter())
        );

        // Evaluate s(X, y) at z
        let mut s_zy = E::Fr::zero();
        s_zy.add_assign(&eval_univar_poly::<E>(&s_neg_poly[..], z_inv, z_inv));
        s_zy.add_assign(&eval_univar_poly::<E>(&s_pos_poly[..], z, z));

        let s_zy_opening = {
            s_zy.negate();

            poly_comm_opening(
                n,
                2 * n,
                srs,
                s_neg_poly.iter().rev()
                    .chain_ext(Some(s_zy).iter()) // f(X) - f(z)
                    .chain_ext(s_pos_poly.iter()),
                z,
            )
        };

        Ok(SxyAdvice {
            s_comm,
            s_zy,
            s_zy_opening,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::{PrimeField, CurveAffine, CurveProjective};
    use crate::cs::{Basic, ConstraintSystem, LinearCombination};
    use super::super::verifier::MultiVerifier;
    use rand::{thread_rng};

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

    #[test]
    fn test_create_proof() {
        let rng = thread_rng();
        let srs = SRS::<Bls12>::new(
            20,
            Fr::from_str("22222").unwrap(),
            Fr::from_str("33333333").unwrap(),
        );

        let proof = Proof::create_proof::<_, Basic>(&SimpleCircuit, &srs).unwrap();

        let mut batch = MultiVerifier::<Bls12, _, Basic, _>::new(SimpleCircuit, &srs, rng).unwrap();

        for _ in 0..1 {
            batch.add_proof(&proof, &[], |_, _| None);
        }

        assert!(batch.check_all());
    }

    #[test]
    fn polynomial_commitment_test() {
        let srs = SRS::<Bls12>::new(
            20,
            Fr::from_str("22222").unwrap(),
            Fr::from_str("33333333").unwrap(),
        );

        // x^-4 + x^-3 + x^-2 + x^-1 + x + x^2
        let mut poly = vec![Fr::one(), Fr::one(), Fr::one(), Fr::one(), Fr::zero(), Fr::one(), Fr::one()];
        // make commitment to the poly
        let commitment = poly_comm(2, 4, 2, &srs, poly.iter());

        let point: Fr = Fr::one();
        let mut tmp = point.inverse().unwrap();
        tmp.square();
        let value = eval_univar_poly::<Bls12>(&poly, tmp, point);

        // evaluate f(z)
        poly[4] = value;
        poly[4].negate();
        // f(x) - f(z)

        let opening = poly_comm_opening(4, 2, &srs,  poly.iter(), point);

        // e(W , hα x )e(g^{v} * W{-z} , hα ) = e(F , h^{x^{−d +max}} )

        let alpha_x_precomp = srs.h_pos_x_alpha[1].prepare();
        let alpha_precomp = srs.h_pos_x_alpha[0].prepare();
        let mut neg_x_n_minus_d_precomp = srs.h_neg_x[srs.d - 2];
        neg_x_n_minus_d_precomp.negate();
        let neg_x_n_minus_d_precomp = neg_x_n_minus_d_precomp.prepare();

        let w = opening.prepare();
        let mut gv = srs.g_pos_x[0].mul(value.into_repr());
        let mut z_neg = point;
        z_neg.negate();
        let w_minus_z = opening.mul(z_neg.into_repr());
        gv.add_assign(&w_minus_z);

        let gv = gv.into_affine().prepare();

        assert!(Bls12::final_exponentiation(&Bls12::miller_loop(&[
                (&w, &alpha_x_precomp),
                (&gv, &alpha_precomp),
                (&commitment.prepare(), &neg_x_n_minus_d_precomp),
            ])).unwrap() == <Bls12 as Engine>::Fqk::one());
    }
}
