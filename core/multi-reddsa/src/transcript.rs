use merlin::Transcript;
use pairing::{io, PrimeField, PrimeFieldRepr};
// use jubjub::redjubjub::{PrivateKey, PublicKey};
use jubjub::curve::{JubjubEngine, edwards::Point, PrimeOrder};
use rand::Rng;

pub trait TranscriptProtocol {
    fn commit_point<E: JubjubEngine>(&mut self, label: &'static [u8], point: &Point<E, PrimeOrder>)  -> io::Result<()>;

    fn commit_scalar<PF: PrimeField>(&mut self, label: &'static [u8], scalar: &PF) -> io::Result<()>;

    fn challenge_scalar<PF: PrimeField>(&mut self, label: &'static [u8]) -> io::Result<PF>;

    fn witness_scalar<PF: PrimeField, R: Rng>(&self, label: &'static [u8], witness: &[u8], rng: &mut R) -> PF;
}

impl TranscriptProtocol for Transcript {
    fn commit_point<E: JubjubEngine>(&mut self, label: &'static [u8], point: &Point<E, PrimeOrder>) -> io::Result<()> {
        let mut buf = [0u8; 32];
        point.write(&mut &mut buf[..])?;
        self.append_message(label, &buf);

        Ok(())
    }

    fn commit_scalar<PF: PrimeField>(&mut self, label: &'static [u8], scalar: &PF) -> io::Result<()> {
        let mut buf = [0u8; 32];
        scalar.into_repr().write_le(&mut &mut buf[..])?;
        self.append_message(label, &buf);

        Ok(())
    }

    fn challenge_scalar<PF: PrimeField>(&mut self, label: &'static [u8]) -> io::Result<PF> {
        // TODO: Avoid infinite loop
        loop {
            let mut repr: PF::Repr = Default::default();
            // TODO: Check endian
            repr.read_be(&mut TranscriptReader(self))?;

            if let Ok(res) = PF::from_repr(repr) {
                return Ok(res)
            }
        }
    }

    // TODO: Update `rand` to v0.6 to use `merlin::TranscriptRngBuilder`.
    fn witness_scalar<PF, R>(&self, label: &'static [u8], witness: &[u8], rng: &mut R) -> io::Result<PF>
    where
        PF: PrimeField,
        R: Rng,
    {
        unimplemented!();
    }
}

struct TranscriptReader<'a>(&'a mut Transcript);

impl<'a> io::Read for TranscriptReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.0.challenge_bytes(b"read", buf);
        Ok(())
    }
}
