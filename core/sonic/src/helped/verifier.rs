use pairing::{Engine, Field};
use rand::{Rand, Rng};
use bellman::SynthesisError;
use merlin::Transcript;
use crate::cs::{Circuit, Backend, SynthesisDriver};
use crate::srs::SRS;
use crate::transcript::ProvingTranscript;
use crate::polynomials::SxEval;
use crate::traits::{PolyEngine, Commitment};
use super::prover::{Proof, SxyAdvice};
use super::helper::Batch;
use std::marker::PhantomData;

pub struct MultiVerifier<E: Engine, C: Circuit<E>, S: SynthesisDriver, R: Rng> {
    circuit: C,
    pub(crate) batch: Batch<E>,
    k_map: Vec<usize>,
    n: usize,
    q: usize,
    randommness: R,
    _marker: PhantomData<(E, S)>,
}

impl<E: Engine, C: Circuit<E>, S: SynthesisDriver, R: Rng> MultiVerifier<E, C, S, R> {
    pub fn new(circuit: C, srs: &SRS<E>, rng: R) -> Result<Self, SynthesisError> {
        struct Preprocess<E: Engine> {
            k_map: Vec<usize>,
            n: usize,
            q: usize,
            _marker: PhantomData<E>
        }

        impl<'a, E: Engine> Backend<E> for &'a mut Preprocess<E> {
            fn new_multiplication_gate(&mut self) {
                self.n += 1;
            }

            fn new_linear_constraint(&mut self) {
                self.q += 1;
            }

            fn new_k_power(&mut self, index: usize) {
                self.k_map.push(index);
            }
        }

        let mut preprocess = Preprocess {
            k_map: vec![],
            n: 0,
            q: 0,
            _marker: PhantomData
        };

        S::synthesize(&mut preprocess, &circuit)?;

        Ok(MultiVerifier {
            circuit,
            batch: Batch::new(srs, preprocess.n),
            k_map: preprocess.k_map,
            n: preprocess.n,
            q: preprocess.q,
            randommness: rng,
            _marker: PhantomData,
        })
    }

    pub fn add_proof<F, PE>(&mut self, proof: &Proof<E, PE>, inputs: &[E::Fr], s_xy: F)
    where
        F: FnOnce(E::Fr, E::Fr) -> Option<E::Fr>,
        PE: PolyEngine<Pairing = E>
    {
        let mut transcript = Transcript::new(&[]);

        transcript.commit_point::<PE>(&proof.r_comm);
        let y: E::Fr = transcript.challenge_scalar();

        transcript.commit_point::<PE>(&proof.t_comm);
        let z: E::Fr = transcript.challenge_scalar();

        transcript.commit_scalar(&proof.r_z1);
        transcript.commit_scalar(&proof.r_zy);
        let r1: E::Fr = transcript.challenge_scalar();

        // transcript.commit_point::<PE>(&proof.z_opening);
        // transcript.commit_point::<PE>(&proof.yz_opening);


        // Open up proof.r_comm at zy, using proof.yz_opening
        // as the evidence and proof.r_zy as the opening
        {
            let random: E::Fr = self.randommness.gen();
            let mut zy = z;
            zy.mul_assign(&y);

            self.batch.add_opening(proof.yz_opening, random, zy);
            self.batch.add_comm_max_n::<PE>(proof.r_comm, random);
            self.batch.add_opening_value(proof.r_zy, random);
        }

        // Compute k(y)
        let mut k_y = E::Fr::zero();
        for (exp, input) in self.k_map.iter().zip(Some(E::Fr::one()).iter().chain(inputs.iter())) {
            let mut term = y.pow(&[(*exp + self.n) as u64]);
            term.mul_assign(input);
            k_y.add_assign(&term);
        }

        // Compute s(z, y) // TODO
        let s_zy = s_xy(z, y).unwrap_or_else(|| {
            let mut tmp = SxEval::new(y, self.n).unwrap();
            S::synthesize(&mut tmp, &self.circuit).unwrap();

            tmp.finalize(z).unwrap()
        });

        // Compute t(z, y)
        let mut t_zy = proof.r_zy;
        t_zy.add_assign(&s_zy);
        t_zy.mul_assign(&proof.r_z1);
        t_zy.sub_assign(&k_y);

        // Open up proof.t_comm and proof.r_comm at z by keeping thier commitments
        // linearly independent.
        {
            let mut random: E::Fr = self.randommness.gen();

            self.batch.add_opening(proof.z_opening, random, z);
            self.batch.add_opening_value(t_zy, random);
            self.batch.add_comm::<PE>(proof.t_comm, random);

            random.mul_assign(&r1); // for batching

            self.batch.add_opening_value(proof.r_z1, random);
            self.batch.add_comm_max_n::<PE>(proof.r_comm, random);
        }
    }

    pub fn add_proof_with_advice<PE>(
        &mut self,
        proof: &Proof<E, PE>,
        inputs: &[E::Fr],
        advice: &SxyAdvice<E, PE>,
    )
    where PE: PolyEngine<Pairing = E>
    {
        let mut z = None;
        self.add_proof(proof, inputs, |_z, _y| {
            z = Some(_z);
            Some(advice.s_zy)
        });

        let z = z.unwrap();

        let mut transcript = Transcript::new(&[]);
        // transcript.commit_point::<PE>(&advice.s_zy_opening);
        transcript.commit_point::<PE>(&advice.s_comm);
        transcript.commit_scalar(&advice.s_zy);
        let random: E::Fr = self.randommness.gen();

        self.batch.add_opening(advice.s_zy_opening, random, z);
        self.batch.add_comm::<PE>(advice.s_comm, random);
        self.batch.add_opening_value(advice.s_zy, random);
    }

    // pub fn add_aggregate(
    //     &mut self,
    //     proofs: &[(Proof<E>, SxyAdvice<E>)],
    //     aggregate: &Aggregate<E>,
    // )
    // {
    //     unimplemented!();
    // }

    pub fn get_k_map(&self) -> Vec<usize> {
        self.k_map.clone()
    }

    pub fn get_n(&self) -> usize {
        self.n
    }

    pub fn get_q(&self) -> usize {
        self.q
    }

    pub fn check_all(self) -> bool {
        self.batch.check_all()
    }
}

pub fn verify_a_proof<'a, E: Engine, PE: PolyEngine>(
    proof: Proof<E, PE>,
    public_inputs: &[E::Fr],
) -> Result<bool, SynthesisError>
{

    unimplemented!();
}

pub fn verify_proofs<E: Engine, C: Circuit<E>, S: SynthesisDriver, R: Rng, PE: PolyEngine<Pairing = E>>(
    proofs: &[Proof<E, PE>],
    inputs: &[Vec<E::Fr>],
    circuit: C,
    rng: R,
    srs: &SRS<E>,
) -> Result<bool, SynthesisError> {
    let mut verifier = MultiVerifier::<E, C, S, R>::new(circuit, srs, rng)?;
    // minus one because of the inputize ONE
    let expected_inputs_size = verifier.get_k_map().len() - 1;

    for (proof, inputs) in proofs.iter().zip(inputs.iter()) {
        if inputs.len() != expected_inputs_size {
            return Err(SynthesisError::Unsatisfiable);
        }
        verifier.add_proof(proof, &inputs, |_, _| None);
    }

    Ok(verifier.check_all())
}
