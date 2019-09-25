use jubjub::redjubjub::{PrivateKey, PublicKey};
use jubjub::curve::JubjubEngine;
use transcript::*;
use commitment::*;

mod transcript;
mod commitment;

pub struct Signers<E: JubjubEngine>{
    public_keys: Vec<PublicKey<E>>,
    aggregated_key: PublicKey<E>,
}

impl<E: JubjubEngine> Signers<E> {
    pub fn new<T>(pub_keys: Vec<PublicKey<E>>, t: T) -> Self
    where
        T: TranscriptProtocol,
    {
        unimplemented!();
    }

    pub fn commit(&self, x_i: PrivateKey<E>) -> CommitmentStage {
        unimplemented!();
    }
}

pub struct CommitmentStage{

}

impl CommitmentStage {
    pub fn reveal(&self) -> RevealStage {
        unimplemented!();
    }
}

pub struct RevealStage{

}

impl RevealStage {
    pub fn share(&self) -> ShareStage {
        unimplemented!();
    }
}

pub struct ShareStage{

}

