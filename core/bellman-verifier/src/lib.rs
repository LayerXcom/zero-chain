#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
mod std {
    pub use crate::alloc::borrow;
    pub use crate::alloc::boxed;
    pub use crate::alloc::string;
    pub use crate::alloc::vec;
    pub use ::core::*;
}

#[cfg(not(feature = "std"))]
use crate::std::vec::Vec;
#[cfg(feature = "std")]
use ::std::vec::Vec;
use pairing::{io, CurveAffine, EncodedPoint, Engine, RW};
use parity_codec::{Decode, Encode, Input};
#[cfg(feature = "std")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "std")]
use substrate_primitives::bytes;

#[cfg(test)]
pub mod tests;

mod verifier;
pub use self::verifier::*;

#[derive(Clone, Debug)]
pub struct Proof<E: Engine> {
    pub a: E::G1Affine,
    pub b: E::G2Affine,
    pub c: E::G1Affine,
}

impl<E: Engine> PartialEq for Proof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b && self.c == other.c
    }
}

impl<E: Engine> Proof<E> {
    pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write(self.a.into_compressed().as_ref())?;
        writer.write(self.b.into_compressed().as_ref())?;
        writer.write(self.c.into_compressed().as_ref())?;

        Ok(())
    }

    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut g1_repr = <E::G1Affine as CurveAffine>::Compressed::empty();
        let mut g2_repr = <E::G2Affine as CurveAffine>::Compressed::empty();

        reader.read(g1_repr.as_mut())?;
        let a = g1_repr
            .into_affine()
            .map_err(|_| io::Error::InvalidData)
            .and_then(|e| {
                if e.is_zero() {
                    Err(io::Error::PointInfinity)
                } else {
                    Ok(e)
                }
            })?;

        reader.read(g2_repr.as_mut())?;
        let b = g2_repr
            .into_affine()
            .map_err(|_| io::Error::InvalidData)
            .and_then(|e| {
                if e.is_zero() {
                    Err(io::Error::PointInfinity)
                } else {
                    Ok(e)
                }
            })?;

        reader.read(g1_repr.as_mut())?;
        let c = g1_repr
            .into_affine()
            .map_err(|_| io::Error::InvalidData)
            .and_then(|e| {
                if e.is_zero() {
                    Err(io::Error::PointInfinity)
                } else {
                    Ok(e)
                }
            })?;

        Ok(Proof { a: a, b: b, c: c })
    }
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, PartialEq)]
pub struct PreparedVerifyingKey<E: Engine> {
    /// Pairing result of alpha*beta
    alpha_g1_beta_g2: E::Fqk,
    /// -gamma in G2
    neg_gamma_g2: <E::G2Affine as CurveAffine>::Prepared,
    /// -delta in G2
    neg_delta_g2: <E::G2Affine as CurveAffine>::Prepared,
    /// Copy of IC from `VerifiyingKey`.
    ic: Vec<E::G1Affine>,
}

#[cfg(feature = "std")]
impl<E: Engine> Serialize for PreparedVerifyingKey<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut writer = vec![];
        self.write(&mut &mut writer[..])
            .expect("Faild to serialize PreparedVerifyingKey.");
        bytes::serialize(&writer[..], serializer)
    }
}

#[cfg(feature = "std")]
impl<'de, E: Engine> Deserialize<'de> for PreparedVerifyingKey<E> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Never called
        unimplemented!();
    }
}

impl<E: Engine> Encode for PreparedVerifyingKey<E> {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        let mut writer = vec![];

        #[cfg(feature = "std")]
        self.write(&mut &mut writer)
            .expect("Faild to write PreparedVerifyingKey");
        #[cfg(not(feature = "std"))]
        self.write(&mut &mut writer[..])
            .expect("Faild to write PreparedVerifyingKey");

        writer.using_encoded(f)
    }
}

impl<E: Engine> Decode for PreparedVerifyingKey<E> {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        <Vec<u8> as Decode>::decode(input).map(|b| {
            PreparedVerifyingKey::<E>::read(&mut &b[..])
                .expect("Faild to read PreparedVerifyingKey")
        })
    }
}

impl<E: Engine> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        PreparedVerifyingKey::<E>::read(&mut &vec![0u8][..])
            .expect("Faild to read PreparedVerifyingKey")
    }
}

impl<E: Engine> PreparedVerifyingKey<E> {
    pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        use byteorder::{BigEndian, ByteOrder};

        self.alpha_g1_beta_g2.write(writer)?;
        self.neg_gamma_g2.write(writer)?;
        self.neg_delta_g2.write(writer)?;

        let mut buf = [0u8; 4];

        BigEndian::write_u32(&mut buf, self.ic.len() as u32);
        writer.write(&buf)?;

        for ic in &self.ic {
            writer.write(ic.into_uncompressed().as_ref())?;
        }

        Ok(())
    }

    pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        use byteorder::{BigEndian, ByteOrder};

        let mut g1_repr = <E::G1Affine as CurveAffine>::Uncompressed::empty();
        let alpha_g1_beta_g2 = E::Fqk::read(reader)?;

        let neg_gamma_g2 = <E::G2Affine as CurveAffine>::Prepared::read(reader)?;
        let neg_delta_g2 = <E::G2Affine as CurveAffine>::Prepared::read(reader)?;

        let mut buf = [0u8; 4];
        reader.read(&mut buf)?;

        let ic_len = BigEndian::read_u32(&buf) as usize;

        let mut ic = vec![];

        for _ in 0..ic_len {
            reader.read(g1_repr.as_mut())?;
            let g1 = g1_repr
                .into_affine()
                .map_err(|_| io::Error::InvalidData)
                .and_then(|e| {
                    if e.is_zero() {
                        Err(io::Error::PointInfinity)
                    } else {
                        Ok(e)
                    }
                })?;
            ic.push(g1);
        }

        Ok(PreparedVerifyingKey {
            alpha_g1_beta_g2: alpha_g1_beta_g2,
            neg_gamma_g2: neg_gamma_g2,
            neg_delta_g2: neg_delta_g2,
            ic: ic,
        })
    }
}

#[derive(Clone)]
pub struct VerifyingKey<E: Engine> {
    // alpha in g1 for verifying and for creating A/C elements of
    // proof. Never the point at infinity.
    pub alpha_g1: E::G1Affine,

    // beta in g1 and g2 for verifying and for creating B/C elements
    // of proof. Never the point at infinity.
    pub beta_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,

    // gamma in g2 for verifying. Never the point at infinity.
    pub gamma_g2: E::G2Affine,

    // delta in g1/g2 for verifying and proving, essentially the magic
    // trapdoor that forces the prover to evaluate the C element of the
    // proof with only components from the CRS. Never the point at
    // infinity.
    pub delta_g1: E::G1Affine,
    pub delta_g2: E::G2Affine,

    // Elements of the form (beta * u_i(tau) + alpha v_i(tau) + w_i(tau)) / gamma
    // for all public inputs. Because all public inputs have a dummy constraint,
    // this is the same size as the number of inputs, and never contains points
    // at infinity.
    pub ic: Vec<E::G1Affine>,
}

impl<E: Engine> PartialEq for VerifyingKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.alpha_g1 == other.alpha_g1
            && self.beta_g1 == other.beta_g1
            && self.beta_g2 == other.beta_g2
            && self.gamma_g2 == other.gamma_g2
            && self.delta_g1 == other.delta_g1
            && self.delta_g2 == other.delta_g2
            && self.ic == other.ic
    }
}

// impl<E: Engine> VerifyingKey<E> {
//     pub fn write<W: io::Write>(
//         &self,
//         writer: &mut W
//     ) -> io::Result<()>
//     {
//         use byteorder::BigEndian;

//         writer.write(self.alpha_g1.into_uncompressed().as_ref())?;
//         writer.write(self.beta_g1.into_uncompressed().as_ref())?;
//         writer.write(self.beta_g2.into_uncompressed().as_ref())?;
//         writer.write(self.gamma_g2.into_uncompressed().as_ref())?;
//         writer.write(self.delta_g1.into_uncompressed().as_ref())?;
//         writer.write(self.delta_g2.into_uncompressed().as_ref())?;
//         BigEndian::write_u32(writer, self.ic.len() as u32)?;
//         for ic in &self.ic {
//             writer.write(ic.into_uncompressed().as_ref())?;
//         }

//         Ok(())
//     }

//     pub fn read<R: io::Read>(
//         reader: &mut R
//     ) -> io::Result<Self>
//     {
//         let mut g1_repr = <E::G1Affine as CurveAffine>::Uncompressed::empty();
//         let mut g2_repr = <E::G2Affine as CurveAffine>::Uncompressed::empty();

//         reader.read(g1_repr.as_mut())?;
//         let alpha_g1 = g1_repr.into_affine().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

//         reader.read(g1_repr.as_mut())?;
//         let beta_g1 = g1_repr.into_affine().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

//         reader.read(g2_repr.as_mut())?;
//         let beta_g2 = g2_repr.into_affine().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

//         reader.read(g2_repr.as_mut())?;
//         let gamma_g2 = g2_repr.into_affine().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

//         reader.read(g1_repr.as_mut())?;
//         let delta_g1 = g1_repr.into_affine().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

//         reader.read(g2_repr.as_mut())?;
//         let delta_g2 = g2_repr.into_affine().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

//         let ic_len = reader.read_u32::<BigEndian>()? as usize;

//         let mut ic = vec![];

//         for _ in 0..ic_len {
//             reader.read(g1_repr.as_mut())?;
//             let g1 = g1_repr
//                      .into_affine()
//                      .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
//                      .and_then(|e| if e.is_zero() {
//                          Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
//                      } else {
//                          Ok(e)
//                      })?;

//             ic.push(g1);
//         }

//         Ok(VerifyingKey {
//             alpha_g1: alpha_g1,
//             beta_g1: beta_g1,
//             beta_g2: beta_g2,
//             gamma_g2: gamma_g2,
//             delta_g1: delta_g1,
//             delta_g2: delta_g2,
//             ic: ic
//         })
//     }
// }

/// This is an error that could occur during circuit synthesis contexts,
/// such as CRS generation, proving or verification.
#[derive(Debug)]
pub enum SynthesisError {
    /// During synthesis, we lacked knowledge of a variable assignment.
    AssignmentMissing,
    /// During synthesis, we divided by zero.
    DivisionByZero,
    /// During synthesis, we constructed an unsatisfiable constraint system.
    Unsatisfiable,
    /// During synthesis, our polynomials ended up being too high of degree
    PolynomialDegreeTooLarge,
    /// During proof generation, we encountered an identity in the CRS
    UnexpectedIdentity,
    /// During proof generation, we encountered an I/O error with the CRS
    IoError(io::Error),
    /// During verification, our verifying key was malformed.
    MalformedVerifyingKey,
    /// During CRS generation, we observed an unconstrained auxillary variable
    UnconstrainedVariable,
}

impl From<io::Error> for SynthesisError {
    fn from(e: io::Error) -> SynthesisError {
        SynthesisError::IoError(e)
    }
}

#[cfg(test)]
mod test_proof_write_read {
    use super::*;
    use pairing::bls12_381::{Bls12, Fq, Fq2, FqRepr, G1Affine, G2Affine};

    #[test]
    fn byte_cast() {
        let proof = Proof::<Bls12> {
            a: G1Affine {
                x: Fq(FqRepr([
                    16739797345307447054,
                    8770073581945912782,
                    2136235734558249053,
                    15708693206467346864,
                    8490922573673252286,
                    1579948179538746271,
                ])),
                y: Fq(FqRepr([
                    6020268861830312380,
                    12879642226817054130,
                    17904268384441769431,
                    15221266273771162992,
                    5384025118770475327,
                    1217424206270675696,
                ])),
                infinity: false,
            },
            b: G2Affine {
                x: Fq2 {
                    c0: Fq(FqRepr([
                        1955900693533848923,
                        1207270260807916624,
                        10030599496790334806,
                        13310839817113796132,
                        7335494448760471336,
                        1520001478562200471,
                    ])),
                    c1: Fq(FqRepr([
                        10867545881237734656,
                        11292327308906943064,
                        4286427264655280722,
                        5033346395315998832,
                        9316987264960049565,
                        1093242448245841130,
                    ])),
                },
                y: Fq2 {
                    c0: Fq(FqRepr([
                        6242954237310667968,
                        4585560269108097072,
                        5517602464819718440,
                        11574556308726901230,
                        9576729709326690239,
                        433440758793164942,
                    ])),
                    c1: Fq(FqRepr([
                        11180820212476238720,
                        13504112200989036594,
                        2176986271111729977,
                        4481942420924131750,
                        16599268505710547724,
                        922146901424495142,
                    ])),
                },
                infinity: false,
            },
            c: G1Affine {
                x: Fq(FqRepr([
                    16362720867114782945,
                    14827736289902972547,
                    7987695302896742039,
                    14289613131851611182,
                    7162884718192410854,
                    605698044002088945,
                ])),
                y: Fq(FqRepr([
                    3093450141616622888,
                    7767002491037351418,
                    5972324121568597438,
                    2377138492074911281,
                    701452421528324862,
                    1373508511228186748,
                ])),
                infinity: false,
            },
        };

        let mut v = vec![];
        proof.write(&mut v).unwrap();

        assert_eq!(v.len(), 192);

        let de_proof = Proof::read(&v[..]).unwrap();
        assert!(proof == de_proof);
    }

    #[test]
    fn prepared_vk_read_write() {
        use std::fs::File;
        use std::io::{BufReader, Read};
        use std::path::Path;

        let vk_path = Path::new("./src/tests/verification.params");
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        let prepared_vk_a = PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..]).unwrap();

        let mut buf = vec![];
        prepared_vk_a.write(&mut &mut buf).unwrap();

        let prepared_vk_b = PreparedVerifyingKey::<Bls12>::read(&mut &buf[..]).unwrap();

        assert!(prepared_vk_a == prepared_vk_b);
    }
}
