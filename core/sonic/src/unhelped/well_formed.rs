use pairing::{Engine, Field, PrimeField, CurveAffine, CurveProjective};
use crate::srs::SRS;
use crate::utils::*;

// Nested vec because of \sum\limits_{j=1}^M, for now.
#[derive(Clone)]
pub struct WellformednessArg<E: Engine> (Vec<Vec<E::Fr>>);

#[derive(Clone)]
pub struct WellformednessProof<E: Engine> {
    l: E::G1Affine,
    r: E::G1Affine,
}

impl<E: Engine> WellformednessArg<E> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn new(polys: Vec<Vec<E::Fr>>) -> Self {
        assert!(!polys.is_empty());
    }

    pub fn commit(&self, srs: &SRS<E>) -> Vec<E::G1Affine> {
        let mut res = vec![];

        let n = self.0[0].len();

        for poly in self.0.iter() {
            let c = multiexp(
                srs.g_pos_x_alpha[..n].iter(),
                poly.iter()
                ).into_affine();

            res.push(c);
        }

        res
    }

    /// The prover sends a well-formedness proof to the verifier.
    pub fn prove(&self, challenges: Vec<E::Fr>, srs: &SRS<E>) -> WellformednessProof<E> {
        let m = self.len();
        let n = self.0.len();
        let d = srs.d;

        assert_eq!(m, challenges.len());
        assert!(n < d);

        let mut acc = vec![];

        // Batching well-formedness arguments
        for j in 0..m {
            mul_add_poly(&mut acc[..], &self.0[j][..], challenges[j])
        }

        // g^{x^{-d} * f(x)}, where f(x) is well-formed, meaning dont't have negative powers and constant term.
        // so larget negative power is -(d - 1), smallest negative power is -(d-n)
        let l = multiexp(
            srs.g_neg_x[(d - n)..d].iter().rev(),
            self.0[0].iter()
        ).into_affine();

        // g^{x^{d-n} * f(x)}, where f(x) is well-formed.
        // largest positive power is d, smallet positive power is d - n + 1
        let r = multiexp(
            srs.g_pos_x[(d - n + 1)..].iter(),
            self.0[0].iter()
        ).into_affine();

        WellformednessProof {
            l,
            r,
        }
    }

    pub fn verify(
        n: usize,
        challenges: &Vec<E::Fr>,
        commitments: &Vec<E::G1Affine>,
        proof: &WellformednessProof<E>,
        srs: &SRS<E>
    ) -> bool
    {
        unimplemented!();
    }
}

