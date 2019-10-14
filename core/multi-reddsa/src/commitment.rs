use merlin::Transcript;
use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder, Unknown};
use jubjub::redjubjub::{PublicKey, h_star};
use pairing::{io, Field};
use crate::transcript::TranscriptProtocol;

const COMMITMENT_SIZE: usize = 32;

/// Commitments to `R_i`.
#[derive(Copy, Clone)]
pub struct Commitment([u8; COMMITMENT_SIZE]);

impl Commitment {
    #[allow(non_snake_case)]
    pub(super) fn from_R<E: JubjubEngine>(R: &Point<E, PrimeOrder>) -> io::Result<Self> {
        let mut t = Transcript::new(b"R-commitment");
        t.commit_point(b"", R)?;
        let mut commitment = [0u8; COMMITMENT_SIZE];
        t.challenge_bytes(b"commitment", &mut commitment[..]);
        Ok(Commitment(commitment))
    }

    pub fn ct_eq(&self, other: &Commitment) -> bool {
        use subtle::ConstantTimeEq;

        let eq = self.0.ct_eq(&other.0);
        eq.unwrap_u8() == 1
    }
}

pub(super) fn sum_commitment<E: JubjubEngine>(
    reveals: &[Point<E, PrimeOrder>],
    params: &E::Params
) -> Point<E, PrimeOrder>
{
    let mut acc = Point::zero();
    for r in reveals {
        acc = acc.add(r, params);
    }
    acc
}

#[derive(Clone)]
pub struct SignerKeys<E: JubjubEngine>{
    pub_keys: Vec<Point<E, PrimeOrder>>,
    aggregated_pub_key: Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> SignerKeys<E> {
    pub fn new(pub_keys: Vec<Point<E, PrimeOrder>>, params: &E::Params) -> io::Result<Self> {
        assert!(pub_keys.len() > 1);

        let mut L = vec![];
        for pk in &pub_keys {
            let mut tmp = [0u8; 32];
            pk.write(&mut &mut tmp[..])?;
            L.append(&mut tmp[..].to_vec());
        }
        assert_eq!(L.len(), 32*pub_keys.len());

        let mut aggregated_pub_key = Point::<E, PrimeOrder>::zero();
        for (i, pk) in pub_keys.iter().enumerate() {
            let a_i = Self::a_factor(&L[..], &pk)?;
            aggregated_pub_key = aggregated_pub_key.add(&pk.mul(a_i, params), params);
        }

        Ok(SignerKeys {
            pub_keys,
            aggregated_pub_key,
        })
    }

    pub fn len(&self) -> usize {
        self.pub_keys.len()
    }

    pub fn get_pub_key(&self, index: usize) -> Point<E, PrimeOrder> {
        self.pub_keys[index].clone()
    }

    pub fn get_agg_pub_key(self) -> PublicKey<E> {
        let a = self.aggregated_pub_key;
        PublicKey(a.into())
    }

    pub fn get_a(&self, pk: &Point<E, PrimeOrder>) -> io::Result<E::Fs> {
        let L = self.get_L()?;
        Self::a_factor(&L[..], pk)
    }

    fn get_L(&self) -> io::Result<Vec<u8>> {
        let mut L = vec![];
        for pk in &self.pub_keys {
            let mut tmp = [0u8; 32];
            pk.write(&mut &mut tmp[..])?;
            L.append(&mut tmp[..].to_vec());
        }
        assert_eq!(L.len(), 32*self.pub_keys.len());

        Ok(L)
    }

    /// Compute `a_i` factors for aggregated key.
    fn a_factor(L: &[u8], pk: &Point<E, PrimeOrder>) -> io::Result<E::Fs> {
        let mut buf = [0u8; 32];
        pk.write(&mut &mut buf[..])?;
        Ok(h_star::<E>(L, &buf[..]))
    }
}
