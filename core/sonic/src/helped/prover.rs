use pairing::{Engine, Field};
use bellman::SynthesisError;
use rand::{Rand, Rng, thread_rng};
use merlin::Transcript;
use crate::cs::{SynthesisDriver, Circuit, Backend, Variable, Coeff};
use crate::srs::SRS;
use crate::transcript::ProvingTranscript;
use crate::polynomials::{poly_comm, poly_comm_opening, SxEval, add_polynomials, mul_polynomials};
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

    /// An opening of `t(z, y)`.
    pub t_zy_opening: E::G1Affine,

    /// An opening of `r(z, y)`.
    pub r_zy_opening: E::G1Affine,
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

        // Synthesize variables from circuit
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

        // a commitment to r(X, 1)
        let r_comm = poly_comm::<E, _>(
            n,                      // a max degree
            2*n + NUM_BLINDINGS,    // largest negative power;
            n,                      // largest positive power
            &srs,                   // structured reference string
            blindings.iter().rev()  // coefficients orderd by ascending powers
                .chain_ext(wires.c.iter().rev())
                .chain_ext(wires.b.iter().rev())
                .chain_ext(Some(E::Fr::zero()).iter()) // power i is not equal zero
                .chain_ext(wires.a.iter()),
        );

        // A prover commits polynomial
        transcript.commit_point(&r_comm);


        // ------------------------------------------------------
        // zkV -> zkP: Send y <- F_p to prover
        // ------------------------------------------------------

        // A varifier send to challenge scalar to prover
        let y: E::Fr = transcript.challenge_scalar();
        let y_inv = y.inverse().ok_or(SynthesisError::DivisionByZero)?;


        // ------------------------------------------------------
        // zkP_2(y) -> T:
        // ------------------------------------------------------

        // A coefficients vector which can be used in common with polynomials r and r'
        // associated with powers for X.
        let mut r_x1 = wires.b;         // X^{-n}...X^{-1}
        r_x1.extend(wires.c);           // X^{-2n}...X^{-n-1}
        r_x1.extend(blindings.clone()); // X^{-2n-4}...X^{-2n-1}
        r_x1.reverse();
        r_x1.push(E::Fr::zero());
        r_x1.extend(wires.a);           // X^{1}...X^{n}

        // powers: [-2n-4, n]
        let mut r_xy = r_x1.clone();

        let first_power = y_inv.pow(&[(2 * n + NUM_BLINDINGS) as u64]);

        // Evaluate the polynomial r(X, Y) at y
        eval_bivar_poly::<E>(
            &mut r_xy,
            first_power,
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

        // extend to have powers [n+1, 2n] for w_i(Y)X^{i+n}
        r_xy_prime.resize(4 * n + 1 + NUM_BLINDINGS, E::Fr::zero());
        // negative powers: [-n, -1]
        s_neg_poly.reverse();

        // Add negative powers [-n, -1]
        add_polynomials::<E>(&mut r_xy_prime[(n + NUM_BLINDINGS)..(2 * n + NUM_BLINDINGS)], &s_neg_poly[..]);

        // Add positive powers [1, 2n]
        add_polynomials::<E>(&mut r_xy_prime[(2 * n + 1 + NUM_BLINDINGS)..], &s_pos_poly[..]);

        // Compute t(X, y) = r(X, 1) * r'(X, y)
        let mut txy = mul_polynomials::<E>(&r_x1[..], &r_xy_prime[..])?;
        // the constant term of t(X,Y) is zero
        txy[4 * n + 2 * NUM_BLINDINGS] = E::Fr::zero(); // -k(y)

        // commitment of t(X, y)
        let t_comm = poly_comm(
            srs.d,
            4 * n + 2 * NUM_BLINDINGS,
            3 * n,
            srs,
            txy[..(4 * n + 2 * NUM_BLINDINGS)].iter()
                .chain_ext(txy[(4 * n + 2 * NUM_BLINDINGS + 1)..].iter())
        );

        transcript.commit_point(&t_comm);


        // ------------------------------------------------------
        // zkV -> zkP: Send z <- F_p to prover
        // ------------------------------------------------------

        // A varifier send to challenge scalar to prover
        let z: E::Fr = transcript.challenge_scalar();
        let z_inv = z.inverse().ok_or(SynthesisError::DivisionByZero)?;


        // ------------------------------------------------------
        // zkP_3(z) -> (a, W_a, b, W_b, W_t, s, sc):
        // ------------------------------------------------------

        // r(X, 1) -> r(z, 1)
        let r_z1 = eval_univar_poly::<E>(&r_x1, first_power, z);
        transcript.commit_scalar(&r_z1);

        // Ensure: r(X, 1) -> r(yz, 1) = r(z, y)
        // let r_zy = evaluate_poly(&r_x1, first_power, z*y);
        // r(X, y) -> r(z, y)
        let r_zy = eval_univar_poly::<E>(&r_xy, first_power, z);
        transcript.commit_scalar(&r_zy);

        let r1: E::Fr = transcript.challenge_scalar();

        // An opening of t(X, y) at z
        let t_zy_opening = {
            // Add constant term
            r_x1[(2 * n + NUM_BLINDINGS)].add_assign(&r_zy);

            let r_x1_len = r_x1.len();
            // powers domain: [-2n-4, n]
            mul_add_poly::<E>(
                &mut txy[(2 * n + NUM_BLINDINGS)..(2 * n + NUM_BLINDINGS + r_x1_len)],
                &r_x1[..],
                r1
            );

            // Evaluate t(X, y) at z
            let val = {
                let first_power = z_inv.pow(&[(4 * n + 2 * NUM_BLINDINGS) as u64]);
                eval_univar_poly::<E>(&txy, first_power, z)
            };

            txy[(4 * n + 2 * NUM_BLINDINGS)].sub_assign(&val);

            poly_comm_opening(
                4 * n + 2 * NUM_BLINDINGS,
                3 * n,
                srs,
                &txy,
                z
            )
        };

        // An opening of r(X, 1) at yz
        let r_zy_opening = {
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

        Ok(
            Proof {
                r_comm,
                t_comm,
                r_z1,
                r_zy,
                t_zy_opening,
                r_zy_opening,
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

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::PrimeField;
    use crate::cs::{Basic, ConstraintSystem, LinearCombination};

    struct SimpleCircuit;

    impl<E: Engine> Circuit<E> for SimpleCircuit {
        fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS)
            -> Result<(), SynthesisError>
        {
            let (a, b, _) = cs.multiply(|| {
                Ok((
                    E::Fr::from_str("3").unwrap(),
                    E::Fr::from_str("4").unwrap(),
                    E::Fr::from_str("12").unwrap(),
                ))
            })?;

            cs.enforce_zero(LinearCombination::from(a) + a - b);

            Ok(())
        }
    }

    #[test]
    fn test_create_proof() {
        let srs = SRS::<Bls12>::new(
            20,
            Fr::from_str("33").unwrap(),
            Fr::from_str("44").unwrap(),
        );

        let proof = Proof::create_proof::<_, Basic>(&SimpleCircuit, &srs).unwrap();

    }
}
