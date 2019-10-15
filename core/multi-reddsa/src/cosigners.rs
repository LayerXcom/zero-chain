use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder, FixedGenerators, JubjubParams};
use jubjub::redjubjub::h_star;
use pairing::{io, Field};
use crate::commitment::{Commitment, SignerKeys};

pub struct Cosigners<E: JubjubEngine> {
    pos: usize,
    pub_key: Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> Cosigners<E> {
    pub fn new(pos: usize, pub_key: Point<E, PrimeOrder>) -> Self {
        Cosigners {
            pos,
            pub_key,
        }
    }

    pub fn commit(self, commitment: Commitment) -> CosignersCommited<E> {
        CosignersCommited {
            pos: self.pos,
            pub_key: self.pub_key,
            commitment,
        }
    }
}

pub struct CosignersCommited<E: JubjubEngine> {
    pos: usize,
    pub_key: Point<E, PrimeOrder>,
    commitment: Commitment,
}

impl<E: JubjubEngine> CosignersCommited<E> {
    pub fn verify_witness(self, R: &Point<E, PrimeOrder>) -> io::Result<CosignersRevealed<E>> {
        let received_comm = Commitment::from_R(R)?;
        let eq = self.commitment.ct_eq(&received_comm);

        if !eq {
            return Err(io::Error::InvalidData)
        }

        Ok(CosignersRevealed {
            pos: self.pos,
            pub_key: self.pub_key,
            reveal: R.clone(),
        })
    }
}

#[derive(Clone)]
pub struct CosignersRevealed<E: JubjubEngine> {
    pos: usize,
    pub_key: Point<E, PrimeOrder>,
    reveal: Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> CosignersRevealed<E> {
    pub fn verify_share(
        self,
        msg: &[u8],
        share: E::Fs,
        X_bar_R_buf: &[u8],
        signer_keys: &SignerKeys<E>,
        p_g: FixedGenerators,
        params: &E::Params
    ) -> io::Result<E::Fs> {
        let S_i = params.generator(p_g).mul(share, params);
        let mut c_i = h_star::<E>(&X_bar_R_buf[..], msg);
        c_i.mul_assign(&signer_keys.get_a(&signer_keys.get_pub_key(self.pos))?);
        let X_i = self.pub_key;

        // Check s_i * G == R_i + c_i * a_i * X_i.
        if S_i != X_i.mul(c_i, params).add(&self.reveal, params) {
            return Err(io::Error::InvalidData)
        }
        Ok(share)
    }
}
