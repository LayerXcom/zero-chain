use pairing::{Engine, Field};
use bellman::SynthesisError;
use rand::{Rand, Rng, thread_rng};
use merlin::Transcript;
use crate::cs::{SynthesisDriver, Circuit, Backend, Variable, Coeff};
use crate::srs::SRS;
use crate::transcript::ProvingTranscript;
use crate::polynomials::commitment::{polynomial_commitment};
use crate::utils::{ChainExt, coeffs_consecutive_powers};

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


        //
        // === zkP_1(info, a, b, c) -> R: === //
        //

        // c_{n+1}, c_{n+2}, c_{n+3}, c_{n+4} <- F_p
        let blindings: Vec<E::Fr> = (0..NUM_BLINDINGS)
            .into_iter()
            .map(|_| E::Fr::rand(rng))
            .collect();

        // a commitment to r(X, 1)
        let r_comm = polynomial_commitment::<E, _>(
            n,                      // a max degree
            n,                      // largest positive power
            2*n + NUM_BLINDINGS,    // largest negative power;
            &srs,                   // structured reference string
            blindings.iter().rev()  // ascending order variables
                .chain_ext(wires.c.iter().rev())
                .chain_ext(wires.b.iter().rev())
                .chain_ext(Some(E::Fr::zero()).iter()) // power i is not equal zero
                .chain_ext(wires.a.iter()),
        );

        // A prover commits polynomial
        transcript.commit_point(&r_comm);


        //
        // === zkV -> zkP: Send y <- F_p to prover === //
        //

        // A varifier send to challenge scalar to prover
        let y: E::Fr = transcript.challenge_scalar();


        //
        // === zkP_2(y) -> T: === //
        //

        // A coefficients vector which can be used in common with polynomials r and r'
        // associated with powers for X.
        let mut rx1 = wires.b;         // X^{-n}...X^{-1}
        rx1.extend(wires.c);           // X^{-2n}...X^{-n-1}
        rx1.extend(blindings.clone()); // X^{-2n-4}...X^{-2n-1}
        rx1.reverse();
        rx1.push(E::Fr::zero());
        rx1.extend(wires.a);           // X^{1}...X^{n}

        let mut rxy = rx1.clone();
        let y_inv = y.inverse().ok_or(SynthesisError::DivisionByZero)?;

        let first_power = y_inv.pow(&[(2 * n + NUM_BLINDINGS) as u64]);

        // Evaluate the polynomial r(X, Y) at y
        coeffs_consecutive_powers::<E>(
            &mut rxy,
            first_power,
            y,
        );

        //
        // === zkV -> zkP: Send z <- F_p to prover === //
        //



        //
        // === zkP_3(z) -> (a, W_a, b, W_b, W_t, s, sc): === //
        //


        unimplemented!();
    }
}

/// Three vectors representing the left inputs, right inputs, and outputs of
/// multiplication constraints respectively in sonic's constraint system.
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


