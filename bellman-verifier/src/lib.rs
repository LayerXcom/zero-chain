#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
mod std {
    pub use core::*;
    pub use alloc::vec;
    pub use alloc::string;
    pub use alloc::boxed;
    pub use alloc::borrow;
}

use std::string::String;
// use byteorder::ByteOrder;

use pairing::{
    Engine,
    CurveAffine,
    EncodedPoint,
    io
};

#[cfg(test)]
mod tests;

mod verifier;
pub use self::verifier::*;

#[derive(Clone)]
pub struct Proof<E: Engine> {
    pub a: E::G1Affine,
    pub b: E::G2Affine,
    pub c: E::G1Affine
}

impl<E: Engine> PartialEq for Proof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a &&
        self.b == other.b &&
        self.c == other.c
    }
}

impl<E: Engine> Proof<E> {
    pub fn write<W: io::Write>(
        &self,
        writer: &mut W
    ) -> io::Result<()>
    {
        writer.write(self.a.into_compressed().as_ref())?;
        writer.write(self.b.into_compressed().as_ref())?;
        writer.write(self.c.into_compressed().as_ref())?;

        Ok(())
    }

    pub fn read<R: io::Read>(
        mut reader: R
    ) -> io::Result<Self>
    {
        let mut g1_repr = <E::G1Affine as CurveAffine>::Compressed::empty();
        let mut g2_repr = <E::G2Affine as CurveAffine>::Compressed::empty();

        reader.read(g1_repr.as_mut())?;
        let a = g1_repr
                .into_affine()
                .map_err(|_| io::Error::InvalidData)
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::PointInfinity)
                } else {
                    Ok(e)
                })?;

        reader.read(g2_repr.as_mut())?;
        let b = g2_repr
                .into_affine()
                .map_err(|_| io::Error::InvalidData)
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::PointInfinity)
                } else {
                    Ok(e)
                })?;

        reader.read(g1_repr.as_mut())?;
        let c = g1_repr
                .into_affine()
                .map_err(|_| io::Error::InvalidData)
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::PointInfinity)
                } else {
                    Ok(e)
                })?;

        Ok(Proof {
            a: a,
            b: b,
            c: c
        })
    }
}

pub struct PreparedVerifyingKey<E: Engine> {
    /// Pairing result of alpha*beta
    alpha_g1_beta_g2: E::Fqk,
    /// -gamma in G2
    neg_gamma_g2: <E::G2Affine as CurveAffine>::Prepared,
    /// -delta in G2
    neg_delta_g2: <E::G2Affine as CurveAffine>::Prepared,
    /// Copy of IC from `VerifiyingKey`.
    ic: Vec<E::G1Affine>
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
    pub ic: Vec<E::G1Affine>
}

impl<E: Engine> PartialEq for VerifyingKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.alpha_g1 == other.alpha_g1 &&
        self.beta_g1 == other.beta_g1 &&
        self.beta_g2 == other.beta_g2 &&
        self.gamma_g2 == other.gamma_g2 &&
        self.delta_g1 == other.delta_g1 &&
        self.delta_g2 == other.delta_g2 &&
        self.ic == other.ic
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
    UnconstrainedVariable
}

impl From<io::Error> for SynthesisError {
    fn from(e: io::Error) -> SynthesisError {
        SynthesisError::IoError(e)
    }
}

#[cfg(test)]
mod test_proof_write_read {
    use super::*;    

    use rand::{Rand, thread_rng};
    use pairing::{Field};
    use pairing::bls12_381::{G1Affine, G2Affine, Fq, FqRepr, Fq2, Fr, Bls12};

    #[test]
    fn byte_cast() {        
        let proof = Proof::<Bls12> { 
            a: G1Affine { 
                x: Fq(FqRepr([16739797345307447054, 8770073581945912782, 2136235734558249053, 15708693206467346864, 8490922573673252286, 1579948179538746271])), 
                y: Fq(FqRepr([6020268861830312380, 12879642226817054130, 17904268384441769431, 15221266273771162992, 5384025118770475327, 1217424206270675696])), 
                infinity: false 
            }, 
            b: G2Affine { 
                x: Fq2 { 
                    c0: Fq(FqRepr([1955900693533848923, 1207270260807916624, 10030599496790334806, 13310839817113796132, 7335494448760471336, 1520001478562200471])), 
                    c1: Fq(FqRepr([10867545881237734656, 11292327308906943064, 4286427264655280722, 5033346395315998832, 9316987264960049565, 1093242448245841130])) 
                }, 
                y: Fq2 { 
                    c0: Fq(FqRepr([6242954237310667968, 4585560269108097072, 5517602464819718440, 11574556308726901230, 9576729709326690239, 433440758793164942])), 
                    c1: Fq(FqRepr([11180820212476238720, 13504112200989036594, 2176986271111729977, 4481942420924131750, 16599268505710547724, 922146901424495142])) 
                }, 
                infinity: false 
            }, 
            c: G1Affine { 
                x: Fq(FqRepr([16362720867114782945, 14827736289902972547, 7987695302896742039, 14289613131851611182, 7162884718192410854, 605698044002088945])), 
                y: Fq(FqRepr([3093450141616622888, 7767002491037351418, 5972324121568597438, 2377138492074911281, 701452421528324862, 1373508511228186748])), 
                infinity: false 
            } 
        };

        let mut v = vec![];
        proof.write(&mut v).unwrap();

        assert_eq!(v.len(), 192);

        let de_proof = Proof::read(&v[..]).unwrap();
        assert!(proof == de_proof);      
    }
}
