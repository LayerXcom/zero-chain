#![allow(non_snake_case)]

use pairing::{io, Field, PrimeField, PrimeFieldRepr};
use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder, FixedGenerators, JubjubParams};
use jubjub::redjubjub::{Signature, h_star};
use merlin::Transcript;
use transcript::*;
use commitment::*;
use cosigners::*;
use core::convert::TryFrom;
use rand::Rng;

mod transcript;
mod commitment;
mod cosigners;
mod error;

#[allow(non_snake_case)]
pub struct CommitmentStage<'m, E: JubjubEngine>{
    msg: &'m [u8],
    x_i: E::Fs,
    r_i: E::Fs,
    R_i: Point<E, PrimeOrder>,
    cosigners: Vec<Cosigners<E>>,
    signer_keys: SignerKeys<E>,
    pos: usize,
}

impl<'m, E: JubjubEngine> CommitmentStage<'m, E> {
    #[allow(non_snake_case)]
    pub fn new<R: Rng>(
        msg: &'m [u8],
        x_i: E::Fs,
        signer_keys: SignerKeys<E>,
        pos: usize,
        p_g: FixedGenerators,
        params: &E::Params,
        rng: &mut R,
    ) -> io::Result<(CommitmentStage<'m, E>, Commitment)>
    {
        // T = (l_H + 128) bits of randomness
        // For H*, l_H = 512 bits
        let mut t = [0u8; 80];
        rng.fill_bytes(&mut t[..]);
        let r_i = h_star::<E>(&t[..], msg);

        let R_i = params.generator(p_g).mul(r_i, params);
        let commitment = Commitment::from_R(&R_i)?;

        let cosigners = (0..signer_keys.len())
            .map(|i| Cosigners::new(signer_keys.get_pub_key(i)))
            .collect();

        Ok((CommitmentStage {
            msg,
            x_i,
            r_i,
            R_i,
            cosigners,
            signer_keys,
            pos,
        }, commitment))
    }

    #[allow(non_snake_case)]
    pub fn commit(
        self,
        commitment: Vec<Commitment>,
    ) -> io::Result<(RevealStage<'m, E>, Point<E, PrimeOrder>)>
    {
        let cosigners = self.cosigners.into_iter().zip(commitment)
            .map(|(signer, comm)| signer.commit(comm)).collect();

        Ok((RevealStage {
            msg: self.msg,
            x_i: self.x_i,
            r_i: self.r_i,
            R_i: self.R_i.clone(),
            cosigners,
            signer_keys: self.signer_keys,
            pos: self.pos,
        }, self.R_i))
    }
}

pub struct RevealStage<'m, E: JubjubEngine>{
    msg: &'m [u8],
    x_i: E::Fs,
    r_i: E::Fs,
    R_i: Point<E, PrimeOrder>,
    cosigners: Vec<CosignersCommited<E>>,
    signer_keys: SignerKeys<E>,
    pos: usize,
}

impl<'m, E: JubjubEngine> RevealStage<'m, E> {
    #[allow(non_snake_case)]
    pub fn reveal(
        mut self,
        reveals: Vec<Point<E, PrimeOrder>>,
        params: &E::Params
    ) -> io::Result<(ShareStage<'m, E>, E::Fs)> {
        let sum_R = sum_commitment(&reveals[..], params);

        // Verify nonce
        let cosigners = self.cosigners.into_iter().zip(reveals)
            .map(|(signer, reveal)| signer.verify_witness(&reveal))
            .collect::<Result<_, _>>()?;

        let mut X_bar_R_buf = [0u8; 64];
        self.R_i.write(&mut &mut X_bar_R_buf[..32])?;
        self.signer_keys.clone().get_agg_pub_key().write(&mut &mut X_bar_R_buf[32..])?;

        // c = H*(X_bar, R, m)
        let mut s_i = h_star::<E>(&X_bar_R_buf[..], self.msg);
        // c * a
        s_i.mul_assign(&self.signer_keys.get_a(&self.signer_keys.get_pub_key(self.pos))?);
        // c * a * x
        s_i.mul_assign(&self.x_i);
        // r + c * a * x
        s_i.add_assign(&self.r_i);

        Ok((ShareStage {
            msg: self.msg,
            X_bar_R_buf,
            sum_R,
            cosigners,
            signer_keys: self.signer_keys,
            pos: self.pos,
        }, s_i))
    }
}

#[derive(Clone)]
pub struct ShareStage<'m, E: JubjubEngine> {
    msg: &'m [u8],
    X_bar_R_buf: [u8; 64],
    sum_R: Point<E, PrimeOrder>,
    cosigners: Vec<CosignersRevealed<E>>,
    signer_keys: SignerKeys<E>,
    pos: usize,
}

impl<'m, E: JubjubEngine> ShareStage<'m, E> {
    pub fn share(
        self,
        shares: Vec<E::Fs>,
        p_g: FixedGenerators,
        params: &E::Params,
    ) -> AggSignature<E> {
        let s = self.clone().cosigners.into_iter().zip(shares)
            .map(|(signer, share)| signer.verify_share(
                self.msg,
                share,
                &self.X_bar_R_buf[..],
                &self.signer_keys,
                self.pos,
                p_g,
                params
            ).unwrap()) // TODO
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

    fn sign_helper(msg: &[u8], secrets: &[Fs], signer_keys: &SignerKeys<Bls12>) -> Signature {
        let rng = &mut rand::thread_rng();
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier;
        let pub_keys: Vec<Point<Bls12, PrimeOrder>> = secrets.iter().map(|s| params.generator(p_g).mul::<Fs>(*s, params)).collect();

        let (cosigners, comms): (Vec<_>, Vec<_>) = secrets.clone().into_iter().enumerate()
            .map(|(i, x_i)| CommitmentStage::new(msg, *x_i, signer_keys.clone(), i, p_g, params, rng).unwrap())
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
        let sig = sign_helper(b"test-sign", &secrets[..], &signer_keys);

        assert!(signer_keys.get_agg_pub_key().verify(b"test-sign", &sig, p_g, params));
    }
}
