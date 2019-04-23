use pairing::{Engine, Field};
use bellman::SynthesisError;
use rand::{Rand, Rng, thread_rng};
use merlin::Transcript;
use crate::cs::{SynthesisDriver, Circuit, Backend, Variable, Coeff};
use crate::srs::SRS;
use crate::transcript::ProvingTranscript;
use crate::polynomials::{polynomial_commitment, SxEval, add_polynomials, mul_polynomials};
use crate::utils::{ChainExt, coeffs_consecutive_powers, evaluate_poly};

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

    /// An opening of `r(z, 1)`.
    pub z1_opening: E::G1Affine,

    /// An opening of `r(z, y)`.
    pub zy_opening: E::G1Affine,
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
        let r_comm = polynomial_commitment::<E, _>(
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
        let mut rx1 = wires.b;         // X^{-n}...X^{-1}
        rx1.extend(wires.c);           // X^{-2n}...X^{-n-1}
        rx1.extend(blindings.clone()); // X^{-2n-4}...X^{-2n-1}
        rx1.reverse();
        rx1.push(E::Fr::zero());
        rx1.extend(wires.a);           // X^{1}...X^{n}

        // powers: [-2n-4, n]
        let mut rxy = rx1.clone();

        let first_power = y_inv.pow(&[(2 * n + NUM_BLINDINGS) as u64]);

        // Evaluate the polynomial r(X, Y) at y
        coeffs_consecutive_powers::<E>(
            &mut rxy,
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
        let mut rxy_prime = rxy.clone();

        // extend to have powers [n+1, 2n] for w_i(Y)X^{i+n}
        rxy_prime.resize(4 * n + 1 + NUM_BLINDINGS, E::Fr::zero());
        // negative powers: [-n, -1]
        s_neg_poly.reverse();

        // Add negative powers [-n, -1]
        add_polynomials::<E>(&mut rxy_prime[(n + NUM_BLINDINGS)..(2 * n + NUM_BLINDINGS)], &s_neg_poly[..]);

        // Add positive powers [1, 2n]
        add_polynomials::<E>(&mut rxy_prime[(2 * n + 1 + NUM_BLINDINGS)..], &s_pos_poly[..]);

        // Compute t(X, y) = r(X, 1) * r'(X, y)
        let mut txy = mul_polynomials::<E>(&rx1[..], &rxy_prime[..])?;
        txy[4 * n + 2 * NUM_BLINDINGS] = E::Fr::zero(); // -k(y)

        // commitment of t(X, y)
        let t_comm = polynomial_commitment(
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

        let rz_1 = {
            let first_power = z_inv.pow(&[(2 * n + NUM_BLINDINGS) as u64]);
            evaluate_poly(&rx1, first_power, z)
        };


        // let ryz_1


        unimplemented!();
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


