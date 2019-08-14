use scrypto::jubjub::{PrimeOrder, Unknown, edwards};
use pairing::bls12_381::Bls12;
use zprimitives::{Nonce};
use crate::PARAMS;
use std::{
    convert::TryFrom,
    io,
};

pub struct StdPoint(edwards::Point<Bls12, PrimeOrder>);

impl TryFrom<Nonce> for StdPoint {
    type Error = io::Error;

    fn try_from(nonce: Nonce) -> Result<Self, io::Error> {
        let mut bytes = nonce.as_bytes();

        let point = edwards::Point::<Bls12, Unknown>::read(&mut bytes, &PARAMS)?
            .as_prime_order(&PARAMS)
            .ok_or(io::Error::new(io::ErrorKind::InvalidData, ""))?;

        Ok(StdPoint(point))
    }
}

