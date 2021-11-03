use jubjub::curve::JubjubEngine;
use pairing::io;
use rstd::prelude::*;
use rstd::result;
use zprimitives::IntoXY;

// TODO: make compatible with smallvec
pub struct PublicInputBuilder<E: JubjubEngine>(Vec<E::Fr>);

impl<E: JubjubEngine> PublicInputBuilder<E> {
    pub fn new(capacity: usize) -> Self {
        PublicInputBuilder(Vec::with_capacity(capacity))
    }

    pub fn push<I>(&mut self, input: I) -> result::Result<(), io::Error>
    where
        I: IntoIterator,
        I::Item: IntoXY<E>,
    {
        for i in input {
            let (x, y) = i.into_xy()?;
            self.0.push(x);
            self.0.push(y);
        }

        Ok(())
    }

    pub fn as_slice(&self) -> &[E::Fr] {
        &self.0[..]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}
