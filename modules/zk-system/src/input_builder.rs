use jubjub::curve::JubjubEngine;
use zprimitives::IntoXY;
use pairing::io;
use rstd::prelude::*;

// TODO: make compatible with smallvec
pub struct PublicInputBuilder<E: JubjubEngine>(Vec<E::Fr>);

impl<E: JubjubEngine> PublicInputBuilder<E> {
    pub fn new(capacity: usize) -> Self {
        PublicInputBuilder(Vec::with_capacity(capacity))
    }

    pub fn push<I>(&self, input: I) -> Result<Self, io::Error>
    where
        I: IntoXY<E> + IntoIterator
    {
        unimplemented!();
    }

    pub fn ensure_length(&self, expected_length: usize) -> bool {
        self.0.len() == expected_length
    }

    pub fn as_slice(&self) -> &[E::Fr] {
        &self.0[..]
    }
}
