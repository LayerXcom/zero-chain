use pairing::Engine;
use crate::cs::ConstraintSystem as SonicCS;
use bellman::ConstraintSystem;
use std::marker::PhantomData;

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
#[derive(Clone, Debug)]
pub struct GeneratorAssembly<'a, E: Engine, CS: SonicCS<E> + 'a> {
    cs: &'a mut CS,
    num_inputs: usize,
    num_aux: usize,
    num_constraints: usize,
    _maker: PhantomData<E>,
}

