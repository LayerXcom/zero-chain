use pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use std::marker::PhantomData;
use crate::cs::{ConstraintSystem as SonicCS, Circuit};
use crate::srs::SRS;

/// This is our assembly structure that we will use to synthesize the circuit into
#[derive(Clone, Debug)]
pub struct CircuitParameters<E: Engine> {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_constraints: usize,
    pub k_map: Vec<usize>,
    pub n: usize,
    pub q: usize,
    _marker: PhantomData<E>
}

/// This is our assembly structure that we will use to syhthesize the circuit into
#[derive(Debug)]
pub struct GeneratorAssembly<'a, E: Engine, CS: SonicCS<E> + 'a> {
    cs: &'a mut CS,
    num_inputs: usize,
    num_aux: usize,
    num_constraints: usize,
    _maker: PhantomData<E>,
}

// impl<'a, E: Engine, CS: SonicCS<E> + 'a> ConstraintSystem<E>
//     for GeneratorAssembly<'a, E, CS>
// {
//     type Root = Self;


// }

/// Get circuit information such as number of input, variables, constraints,
/// and the corresponding SONIC parameters k_map, n, q
pub fn get_circuit_parameters<E, C>(circuit: C) -> Result<CircuitParameters<E>, SynthesisError>
    where E: Engine, C: Circuit<E>,
{
    unimplemented!();
}

// pub fn generate_parameters<E, C>(circuit: C, alpha: E::Fr, x: E::Fr)
//     -> Result<Parameters<E>, SynthesisError>
//     where E: Engine, C: Circuit<E>
// {
//     unimplemented!();
// }

pub fn generate_srs<E: Engine>(alpha: E::Fr, x: E::Fr, d: usize)
    -> Result<SRS<E>, SynthesisError>
{
    unimplemented!();
}