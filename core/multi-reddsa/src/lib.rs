use pairing::{io, Field};
use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder, FixedGenerators, JubjubParams};
use merlin::Transcript;
use transcript::*;
use commitment::*;
use cosigners::*;

mod transcript;
mod commitment;
mod cosigners;
mod error;

pub struct NewStage<'t, E: JubjubEngine> {
    commitment: Commitment,
    x_i: E::Fs,
    r_i: E::Fs,
    R_i: Point<E, PrimeOrder>,
    signer_keys: SignerKeys<E>,
    cosigners: Vec<Cosigners<E>>,
    transcript: &'t mut Transcript,
}

impl<'t, E: JubjubEngine> NewStage<'t, E> {
    pub fn new(
        // The message `m` has already been fed into the transcript
        transcript: &'t mut Transcript,
        x_i: E::Fs,
        pos: usize,
        signer_keys: SignerKeys<E>,
        p_g: FixedGenerators,
        params: &E::Params,
    ) -> io::Result<NewStage<'t, E>>
    {
        let r_i = transcript.witness_scalar(b"", &x_i)?;
        let R_i = params.generator(p_g).mul(r_i, params);
        let commitment = Commitment::from_R(&R_i)?;

        let cosigners = (0..signer_keys.len())
            .map(|i| Cosigners::new(i, signer_keys.get_pub_key(i)))
            .collect();

        Ok(NewStage {
            commitment,
            x_i,
            r_i,
            R_i,
            signer_keys,
            cosigners,
            transcript,
        })
    }
}

#[allow(non_snake_case)]
pub struct CommitmentStage<'t, E: JubjubEngine>{
    commitment: Commitment,
    x_i: E::Fs,
    r_i: E::Fs,
    signer_keys: SignerKeys<E>,
    cosigners: Vec<CosignersCommited<E>>,
    transcript: &'t mut Transcript,
}

impl<'t, E: JubjubEngine> CommitmentStage<'t, E> {
    #[allow(non_snake_case)]
    pub fn commit(
        self,
        commitment: Vec<Commitment>,
    ) -> io::Result<CommitmentStage<'t, E>>
    {
        let

        Ok(CommitmentStage {
            commitment,
            x_i,
            r_i,
            R_i,
            signer_keys,
            cosigners,
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
        let X_i = s_i.clone();
        s_i.add_assign(&self.r_i);

        Ok(RevealStage {
            transcript,
            s_i,
            sum_R,
            X_i,
            signer_keys: self.signer_keys
        })
    }
}

pub struct RevealStage<E: JubjubEngine>{
    transcript: Transcript,
    s_i: E::Fs,
    sum_R: Point<E, PrimeOrder>,
    X_i: Point<E, PrimeOrder>,
    signer_keys: SignerKeys<E>,
    cosigners: Vec<CosignersRevealed<E>>,
}

impl<E: JubjubEngine> RevealStage<E> {
    pub fn share(&self, shares: Vec< E::Fs>) -> AggSignature<E> {

        let transcript = self.transcript;

        unimplemented!();
    }

    fn verify_share(&self, share: E::Fs, transcript: &mut Transcript, params: &E::Params, p_g: FixedGenerators) {
        let S_i = params.generator(p_g).mul(share, params);
        let c_i = self.signer_keys.challenge(transcript, &self.X_i);
        let X_i = self.X_i;

    }
}

pub struct AggSignature<E: JubjubEngine>{
    s: E::Fs,
    R: Point<E, PrimeOrder>,
}

