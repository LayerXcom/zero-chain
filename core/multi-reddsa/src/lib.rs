#![allow(non_snake_case)]

use pairing::{io, Field, PrimeField, PrimeFieldRepr};
use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder, FixedGenerators, JubjubParams};
use jubjub::redjubjub::Signature;
use merlin::Transcript;
use transcript::*;
use commitment::*;
use cosigners::*;
use core::convert::TryFrom;

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
    #[allow(non_snake_case)]
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
        let r_i = transcript.witness_scalar(b"r_i", &x_i)?;
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
    pub fn share(self, shares: Vec<E::Fs>, p_g: FixedGenerators, params: &E::Params) -> AggSignature<E> {
        let signer_keys = &self.signer_keys;
        let transcript = &self.transcript;

        let s = self.cosigners.into_iter().zip(shares)
            .map(|(signer, share)| signer.verify_share(share, signer_keys, transcript, p_g, params).unwrap()) // TODO
            .fold(E::Fs::zero(), |mut sum, s| { sum.add_assign(&s); sum });

        AggSignature {
            s,
            R: self.sum_R,
        }
    }
}

#[derive(Clone)]
pub struct AggSignature<E: JubjubEngine>{
    s: E::Fs,
    R: Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> TryFrom<AggSignature<E>> for Signature {
    type Error = io::Error;

    fn try_from(agg_sig: AggSignature<E>) -> Result<Self, io::Error> {
        let mut s_buf = [0u8; 32];
        agg_sig.s.into_repr().write_le(&mut &mut s_buf[..])?;

        let mut r_buf = [0u8; 32];
        agg_sig.R.write(&mut &mut r_buf[..])?;

        Ok(Signature {
            sbar: s_buf,
            rbar: r_buf,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use jubjub::curve::{fs::Fs, JubjubBls12};
    use pairing::bls12_381::Bls12;
    use core::convert::TryInto;

    fn sign_helper(secrets: &[Fs], signer_keys: &SignerKeys<Bls12>, transcript: Transcript) -> Signature {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier;
        let pub_keys: Vec<Point<Bls12, PrimeOrder>> = secrets.iter().map(|s| params.generator(p_g).mul::<Fs>(*s, params)).collect();
        let mut transcript: Vec<_> = pub_keys.iter().map(|_| transcript.clone()).collect();

        let (cosigners, comms): (Vec<_>, Vec<_>) = secrets.clone().into_iter().zip(transcript.iter_mut()).enumerate()
            .map(|(i, (x_i, transcript))| CommitmentStage::new(transcript, *x_i, i, signer_keys.clone(), p_g, params).unwrap())
            .unzip();

        let (cosigners, reveals): (Vec<_>, Vec<_>) = cosigners.into_iter().map(|c| c.commit(comms.clone()).unwrap()).unzip();
        let (cosigners, shares): (Vec<_>, Vec<_>) = cosigners.into_iter().map(|c| c.reveal(reveals.clone(), params).unwrap()).unzip();
        let sigs: Vec<Signature> = cosigners.into_iter().map(|c| c.share(shares.clone(), p_g, params).try_into().unwrap()).collect();

        let cmp = &sigs[0];
        for s in &sigs {
            assert_eq!(cmp, s);
        }

        sigs[0]
    }

    fn signer_keys_helper(secrets: &[Fs]) -> SignerKeys<Bls12> {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier;
        let pub_keys = secrets.iter().map(|s| params.generator(p_g).mul(*s, params)).collect();
        SignerKeys::new(pub_keys, params).unwrap()
    }

    #[test]
    fn test_multi_verify() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier;
        let secrets = vec![
            Fs::from_str("1").unwrap(),
            Fs::from_str("2").unwrap(),
            Fs::from_str("3").unwrap(),
        ];

        let signer_keys = signer_keys_helper(&secrets[..]);
        let sig = sign_helper(&secrets[..], &signer_keys, Transcript::new(b"test-sign"));
        // assert!(signer_keys.get_agg_pub_key().verify(b"test-sign", &sig, p_g, params));
    }
}
