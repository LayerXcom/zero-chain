use pairing::io;
use jubjub::redjubjub::{PrivateKey, PublicKey};
use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder, FixedGenerators, JubjubParams};
use merlin::Transcript;
use transcript::*;
use commitment::*;

mod transcript;
mod commitment;

#[derive(Clone)]
pub struct SignerKeys<E: JubjubEngine>{
    pub_keys: Vec<Point<E, PrimeOrder>>,
    aggregated_pub_key: Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> SignerKeys<E> {
    pub fn new(pub_keys: Vec<Point<E, PrimeOrder>>, params: &E::Params) -> io::Result<Self> {
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

        Ok(SignerKeys {
            pub_keys,
            aggregated_pub_key,
        })
    }

    #[allow(non_snake_case)]
    pub fn commit<'t, T>(
        &self,
        // The message `m` has already been fed into the transcript
        transcript: &'t mut T,
        x_i: E::Fs,
        p_g: FixedGenerators,
        params: &E::Params
    ) -> io::Result<CommitmentStage<'t, E, T>>
    where
        T: TranscriptProtocol,
    {
        let r_i = transcript.witness_scalar(b"", &x_i)?;
        let R_i = params.generator(p_g).mul(r_i, params);
        let commitment = Commitment::from_R(&R_i)?;

        Ok(CommitmentStage {
            r_i,
            R_i,
            commitment,
            transcript,
        })
    }

    /// Compute `a_i` factors for aggregated key.
    fn a_factor(mut t: Transcript, pk: &Point<E, PrimeOrder>) -> io::Result<E::Fs> {
        t.commit_point(b"commit-pk", pk)?;
        t.challenge_scalar(b"challenge-a_i")
    }
}

#[allow(non_snake_case)]
pub struct CommitmentStage<'t, E: JubjubEngine, T: TranscriptProtocol>{
    commitment: Commitment,
    r_i: E::Fs,
    R_i: Point<E, PrimeOrder>,
    transcript: &'t mut T,
    // signers: Vec<>,
}

impl<'t, E: JubjubEngine, T: TranscriptProtocol> CommitmentStage<'t, E, T> {
    #[allow(non_snake_case)]
    pub fn reveal(&self, reveals: Vec<Point<E, PrimeOrder>>, params: &E::Params) -> RevealStage {
        let sum_R = sum_commitment(&reveals[..], params);

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

