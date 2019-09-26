use pairing::io;
use jubjub::redjubjub::{PrivateKey, PublicKey};
use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder, FixedGenerators, JubjubParams};
use merlin::Transcript;
use transcript::*;
use commitment::*;

mod transcript;
mod commitment;

pub struct Signers<E: JubjubEngine>{
    pub_keys: Vec<Point<E, PrimeOrder>>,
    aggregated_pub_key: Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> Signers<E> {
    pub fn new<T>(pub_keys: Vec<Point<E, PrimeOrder>>, t: T, params: &E::Params) -> io::Result<Self>
    where
        T: TranscriptProtocol,
    {
        assert!(pub_keys.len() > 1);

        let mut t = Transcript::new(b"aggregated-pub-key");
        for pk in &pub_keys {
            t.commit_point(b"pub-key", pk)?;
        }

        let mut aggregated_pub_key = Point::<E, PrimeOrder>::zero();
        for pk in &pub_keys {
            let a_i = Self::a_factor(t.clone(), pk)?;
            aggregated_pub_key = aggregated_pub_key.add(&pk.mul(a_i, params), params);
        }

        Ok(Signers {
            pub_keys,
            aggregated_pub_key,
        })
    }

    pub fn commit<T>(&self, t: T, x_i: E::Fs, p_g: FixedGenerators, params: &E::Params) -> io::Result<CommitmentStage>
    where
        T: TranscriptProtocol,
    {
        let r_i = t.witness_scalar(b"", &x_i)?;
        let R_i = params.generator(p_g).mul(r_i, params);
        unimplemented!();
    }

    /// Compute `a_i` factors for aggregated key.
    fn a_factor(mut t: Transcript, pk: &Point<E, PrimeOrder>) -> io::Result<E::Fs> {
        t.commit_point(b"commit-pk", pk)?;
        t.challenge_scalar(b"challenge-a_i")
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

