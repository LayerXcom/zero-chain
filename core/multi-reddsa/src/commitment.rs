use merlin::Transcript;
use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder, JubjubParams};
use pairing::io;
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
}

pub(super) fn sum_commitment<E: JubjubEngine>(reveals: &[Point<E, PrimeOrder>], params: &E::Params) -> Point<E, PrimeOrder> {
    let mut acc = Point::zero();
    for r in reveals {
        acc = acc.add(r, params);
    }
    acc
}
