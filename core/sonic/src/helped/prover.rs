use pairing::{Engine, Field};
use bellman::SynthesisError;
use rand::{Rand, Rng, thread_rng};
use merlin::Transcript;
use crate::cs::{SynthesisDriver, Circuit, Backend, Variable, Coeff};
use crate::srs::SRS;
use crate::transcript::ProvingTranscript;
use crate::poly_comm::{polynomial_commitment};

pub const NUM_BINDINGS: usize = 4;

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

        S::synthesize(&mut wires, circuit)?;

        let n = wires.a.len();
        // TODO: Make better entropy
        let rng = &mut thread_rng();
        let mut transcript = Transcript::new(&[]);

        // c_{n+1}, c_{n+2}, c_{n+3}, c_{n+4}
        let bindings: Vec<E::Fr> = (0..NUM_BINDINGS)
            .into_iter()
            .map(|_| E::Fr::rand(rng))
            .collect();

        // r is a commitment to r(X, 1)
        let r = polynomial_commitment::<E, _>(
            n,                      // max
            n,                      // largest positive power
            2*n + NUM_BINDINGS,     // largest negative power
            &srs,
        );

        // A prover commits polynomial
        transcript.commit_point(&r);

        // A varifier send to challenge scalar to prover
        let y: E::Fr = transcript.challenge_scalar();



        unimplemented!();
    }
}


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


