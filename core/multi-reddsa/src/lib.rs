use pairing::{io, Field};
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
    transcript: Transcript,
}

impl<E: JubjubEngine> SignerKeys<E> {
    pub fn new(pub_keys: Vec<Point<E, PrimeOrder>>, params: &E::Params) -> io::Result<Self> {
        assert!(pub_keys.len() > 1);

        let mut transcript = Transcript::new(b"aggregated-pub-key");
        for pk in &pub_keys {
            transcript.commit_point(b"pub-key", pk)?;
        }

        let mut aggregated_pub_key = Point::<E, PrimeOrder>::zero();
        for pk in &pub_keys {
            let a_i = Self::a_factor(&transcript, pk)?;
            aggregated_pub_key = aggregated_pub_key.add(&pk.mul(a_i, params), params);
        }

        Ok(SignerKeys {
            pub_keys,
            aggregated_pub_key,
            transcript,
        })
    }

    pub fn commit(&self, transcript: &mut Transcript) -> io::Result<()> {
        transcript.commit_point(b"X", &self.aggregated_pub_key)
    }

    pub fn challenge(&self, transcript: &mut Transcript, pk: &Point<E, PrimeOrder>) -> io::Result<E::Fs> {
        // Compute c = H(X, R, m).
        let mut c: E::Fs = transcript.challenge_scalar(b"c")?;
        // Compute a_i = H(<L>, X_i).
        let a_i = Self::a_factor(&self.transcript, &pk)?;
        c.mul_assign(&a_i);

        Ok(c)
    }

    /// Compute `a_i` factors for aggregated key.
    fn a_factor(t: &Transcript, pk: &Point<E, PrimeOrder>) -> io::Result<E::Fs> {
        let mut t = t.clone();
        t.commit_point(b"commit-pk", pk)?;
        t.challenge_scalar(b"challenge-a_i")
    }
}

#[allow(non_snake_case)]
pub struct CommitmentStage<'t, E: JubjubEngine>{
    commitment: Commitment,
    x_i: E::Fs,
    r_i: E::Fs,
    R_i: Point<E, PrimeOrder>,
    signer_keys: SignerKeys<E>,
    transcript: &'t mut Transcript,
    // signers: Vec<>,
}

impl<'t, E: JubjubEngine> CommitmentStage<'t, E> {
    #[allow(non_snake_case)]
    pub fn commit(
        // The message `m` has already been fed into the transcript
        transcript: &'t mut Transcript,
        x_i: E::Fs,
        signer_keys: SignerKeys<E>,
        p_g: FixedGenerators,
        params: &E::Params
    ) -> io::Result<CommitmentStage<'t, E>>
    {
        let r_i = transcript.witness_scalar(b"", &x_i)?;
        let R_i = params.generator(p_g).mul(r_i, params);
        let commitment = Commitment::from_R(&R_i)?;

        Ok(CommitmentStage {
            commitment,
            x_i,
            r_i,
            R_i,
            signer_keys,
            transcript,
        })
    }

    #[allow(non_snake_case)]
    pub fn reveal(mut self, reveals: Vec<Point<E, PrimeOrder>>, params: &E::Params) -> io::Result<RevealStage<E>> {
        let sum_R = sum_commitment(&reveals[..], params);

        // Verify nonce

        self.signer_keys.commit(&mut self.transcript)?;
        self.transcript.commit_point(b"R", &sum_R)?;
        let transcript = self.transcript.clone();

        let c_i = self.signer_keys.challenge(&mut self.transcript, &self.R_i)?;
        let mut s_i = c_i;
        s_i.mul_assign(&self.x_i);
        s_i.add_assign(&self.r_i);

        Ok(RevealStage {
            transcript,
            s_i,
            sum_R,
        })
    }
}

pub struct RevealStage<E: JubjubEngine>{
    transcript: Transcript,
    s_i: E::Fs,
    sum_R: Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> RevealStage<E> {
    pub fn share(&self) -> ShareStage {
        unimplemented!();
    }
}

pub struct ShareStage{

}

