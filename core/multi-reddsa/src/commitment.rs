use merlin::Transcript;
use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder, Unknown};
use jubjub::redjubjub::PublicKey;
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
        for (i, pk) in pub_keys.iter().enumerate() {
            let a_i = Self::a_factor(&transcript, i)?;
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

    pub fn challenge(&self, transcript: &mut Transcript, index: usize) -> io::Result<E::Fs> {
        // Compute c = H(X, R, m).
        let mut c: E::Fs = transcript.challenge_scalar(b"c")?;
        // Compute a_i = H(<L>, X_i).
        let a_i = Self::a_factor(&self.transcript, index)?;
        c.mul_assign(&a_i);

        Ok(c)
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

    /// Compute `a_i` factors for aggregated key.
    fn a_factor(t: &Transcript, index: usize) -> io::Result<E::Fs> {
        let mut t = t.clone();
        t.append_u64(b"i", index as u64);
        t.challenge_scalar(b"challenge-a_i")
    }
}
