use merlin::Transcript;
use pairing::PrimeField;
use jubjub::redjubjub::{PrivateKey, PublicKey};
use jubjub::curve::JubjubEngine;

pub trait TranscriptProtocol<E: JubjubEngine> {
    fn commit_point(&mut self, point: &PublicKey<E>);

    fn commit_scalar(&mut self, scalar: &PrivateKey<E>);

    fn challenge_scalar(&mut self) -> PrivateKey<E>;

    fn witness_scalar(&self) -> PrivateKey<E>;
}

impl<E: JubjubEngine> TranscriptProtocol<E> for Transcript {
    fn commit_point(&mut self, point: &PublicKey<E>) {
        
        unimplemented!();
    }

    fn commit_scalar(&mut self, scalar: &PrivateKey<E>) {
        unimplemented!();
    }

    fn challenge_scalar(&mut self) -> PrivateKey<E> {
        unimplemented!();
    }

    fn witness_scalar(&self) -> PrivateKey<E> {
        unimplemented!();
    }
}
