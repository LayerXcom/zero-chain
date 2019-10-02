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

#[allow(non_snake_case)]
pub struct CommitmentStage<'t, E: JubjubEngine>{
    x_i: E::Fs,
    r_i: E::Fs,
    R_i: Point<E, PrimeOrder>,
    pos: usize,
    signer_keys: SignerKeys<E>,
    cosigners: Vec<Cosigners<E>>,
    transcript: &'t mut Transcript,
}

impl<'t, E: JubjubEngine> CommitmentStage<'t, E> {
    pub fn new(
        // The message `m` has already been fed into the transcript
        transcript: &'t mut Transcript,
        x_i: E::Fs,
        pos: usize,
        signer_keys: SignerKeys<E>,
        p_g: FixedGenerators,
        params: &E::Params,
    ) -> io::Result<(CommitmentStage<'t, E>, Commitment)>
    {
        let r_i = transcript.witness_scalar(b"", &x_i)?;
        let R_i = params.generator(p_g).mul(r_i, params);
        let commitment = Commitment::from_R(&R_i)?;

        let cosigners = (0..signer_keys.len())
            .map(|i| Cosigners::new(i, signer_keys.get_pub_key(i)))
            .collect();

        Ok((CommitmentStage {
            x_i,
            r_i,
            R_i,
            pos,
            signer_keys,
            cosigners,
            transcript,
        }, commitment))
    }

    #[allow(non_snake_case)]
    pub fn commit(
        self,
        commitment: Vec<Commitment>,
    ) -> io::Result<(RevealStage<'t, E>, Point<E, PrimeOrder>)>
    {
        let cosigners = self.cosigners.into_iter().zip(commitment)
            .map(|(signer, comm)| signer.commit(comm)).collect();

        Ok((RevealStage {
            transcript: self.transcript,
            x_i: self.x_i,
            r_i: self.r_i,
            pos: self.pos,
            signer_keys: self.signer_keys,
            cosigners,
        }, self.R_i))
    }
}

pub struct RevealStage<'t, E: JubjubEngine>{
    transcript: &'t mut Transcript,
    x_i: E::Fs,
    r_i: E::Fs,
    pos: usize,
    signer_keys: SignerKeys<E>,
    cosigners: Vec<CosignersCommited<E>>,
}

impl<'t, E: JubjubEngine> RevealStage<'t, E> {
    #[allow(non_snake_case)]
    pub fn reveal(
        mut self,
        reveals: Vec<Point<E, PrimeOrder>>,
        params: &E::Params) -> io::Result<(ShareStage<E>, E::Fs)>
    {
        let sum_R = sum_commitment(&reveals[..], params);

        // Verify nonce
        let cosigners = self.cosigners.into_iter().zip(reveals)
            .map(|(signer, reveal)| signer.verify_witness(&reveal))
            .collect::<Result<_, _>>()?;

        self.signer_keys.commit(&mut self.transcript)?;
        self.transcript.commit_point(b"R", &sum_R)?;
        let transcript = self.transcript.clone();

        let c_i = self.signer_keys.challenge(&mut self.transcript, self.pos)?;
        let mut s_i = c_i;
        s_i.mul_assign(&self.x_i);
        s_i.add_assign(&self.r_i);

        Ok((ShareStage {
            transcript,
            sum_R,
            signer_keys: self.signer_keys,
            cosigners,
        }, s_i))
    }
}

pub struct ShareStage<E: JubjubEngine> {
    transcript: Transcript,
    signer_keys: SignerKeys<E>,
    sum_R: Point<E, PrimeOrder>,
    cosigners: Vec<CosignersRevealed<E>>,
}

impl<E: JubjubEngine> ShareStage<E> {
    pub fn share(&self, shares: Vec<E::Fs>) -> AggSignature<E> {
        let transcript = &self.transcript;

        unimplemented!();
    }
}

pub struct AggSignature<E: JubjubEngine>{
    s: E::Fs,
    R: Point<E, PrimeOrder>,
}

