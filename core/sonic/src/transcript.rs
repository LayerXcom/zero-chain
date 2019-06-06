use merlin::Transcript;
use pairing::{CurveAffine, PrimeField, Field, PrimeFieldRepr};
use crate::traits::{Commitment, PolyEngine};

/// In this trait, we provide an interface for Fiat-Shamir transformation
/// which takes an interactive argument and replaces the verifier challenges.
pub trait ProvingTranscript {
    /// Extend the transcript with an affine representation of an elliptic curve point
    /// guaranteed to be in the correct prime order subgroup.
    fn commit_point<PE: PolyEngine>(&mut self, point: &PE::Commitment);

    /// Extend the transcript with scalar
    fn commit_scalar<F: PrimeField>(&mut self, scalar: &F);

    /// Produce the public challenge scalar.
    fn challenge_scalar<F: PrimeField>(&mut self) -> F;
}

/// The transcript trait is compatible with `merlin::Transcript`.
impl ProvingTranscript for Transcript {
    fn commit_point<PE: PolyEngine>(&mut self, point: &PE::Commitment) {
        self.commit_bytes(b"point", &point.into_bytes()[..]);
    }

    fn commit_scalar<F: PrimeField>(&mut self, scalar: &F) {
        let mut v = vec![];
        scalar.into_repr().write_le(&mut v).unwrap();
        self.commit_bytes(b"scalar", &v);
    }

    // TODO: Avoid infinite loop
    fn challenge_scalar<F: PrimeField>(&mut self) -> F {
        loop {
            let mut repr: F::Repr = Default::default();
            repr.read_be(TranscriptReader(self)).unwrap();

            if let Ok(res) = F::from_repr(repr) {
                return res;
            }
        }
    }
}

/// A reader for transcript
struct TranscriptReader<'a>(&'a mut Transcript);

impl<'a> std::io::Read for TranscriptReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.challenge_bytes(b"read", buf);
        Ok(buf.len())
    }
}
