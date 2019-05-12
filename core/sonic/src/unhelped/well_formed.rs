/// Defined in appendix B.3 Well-formedness Argument
use pairing::{Engine, Field, CurveAffine, CurveProjective};
use crate::srs::SRS;
use crate::utils::*;

// Nested vec because of \sum\limits_{j=1}^M, for now.
#[derive(Clone)]
pub struct WellformedArg<E: Engine>(Vec<Vec<E::Fr>>);

#[derive(Clone)]
pub struct WellformedComm<E: Engine>(Vec<E::G1Affine>);

impl<E: Engine> WellformedArg<E> {
    /// The number of polynomials for well-formed argument
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The degree of each polynomials for well-formed argument
    pub fn len_poly(&self) -> usize {
        self.0[0].len()
    }

    pub fn new(polys: Vec<Vec<E::Fr>>) -> Self {
        assert!(!polys.is_empty());
        let len_poly = polys[0].len();

        // Ensure all of the polynomials have the same degree.
        assert!(polys.iter().all(|p| p.len() == len_poly));

        WellformedArg(polys)
    }

    pub fn commit(&self, srs: &SRS<E>) -> WellformedComm<E> {
        let mut res = vec![];
        let n = self.len_poly();

        for poly in self.0.iter() {
            let c = multiexp(
                srs.g_pos_x_alpha[..n].iter(),
                poly.iter()
                ).into_affine();

            res.push(c);
        }

        WellformedComm::<E>(res)
    }

    /// The prover sends a well-formedness proof to the verifier.
    pub fn prove(&self, challenges: &[E::Fr], srs: &SRS<E>) -> WellformedProof<E> {
        let m = self.len();
        let n = self.len_poly();
        let d = srs.d;

        assert_eq!(m, challenges.len());
        assert!(n < d);

        let mut acc: Vec<E::Fr> = vec![E::Fr::zero(); n];

        // Batching well-formedness arguments
        for j in 0..m {
            mul_add_poly::<E>(&mut acc[..], &self.0[j][..], challenges[j])
        }

        // g^{x^{-d} * f(x)} where f(x) is well-formed, meaning don't have terms of negative degree and constant term.
        // so larget negative power is -(d - 1), smallest negative power is -(d-n)
        let l = multiexp(
            srs.g_neg_x[(d - n)..d].iter().rev(),
            acc.iter()
        ).into_affine();

        // g^{x^{d-n} * f(x)} where f(x) is well-formed.
        // largest positive power is d, smallet positive power is d - n + 1
        let r = multiexp(
            srs.g_pos_x[(d - n + 1)..].iter(),
            acc.iter()
        ).into_affine();

        WellformedProof {
            l,
            r,
        }
    }
}

/// A proof of Well-formedness Argument
#[derive(Clone)]
pub struct WellformedProof<E: Engine> {
    l: E::G1Affine,
    r: E::G1Affine,
}

impl<E: Engine> WellformedProof<E> {
    /// The verifier can check with the pairings
    /// e(g^{alpha * f(x)}, h) = e(proof.l, h^{alpha * x^{d}})
    /// e(g^{alpha * f(x)}, h) = e(proof.r, h^{alpha * x^{n-d}})
    pub fn verify(
        &self,
        n: usize,
        challenges: &[E::Fr],
        commitments: &WellformedComm<E>,
        srs: &SRS<E>
    ) -> bool
    {
        let d = srs.d;
        let alpha_x_d_prep = srs.h_pos_x_alpha[d].prepare();
        let alpha_x_n_minus_d_prep = srs.h_neg_x_alpha[d - n].prepare();

        let mut h = srs.h_pos_x[0];
        h.negate();
        let h_prep = h.prepare();

        let alpha_f = multiexp(
            commitments.0.iter(),
            challenges.iter()
        ).into_affine();
        let alpha_f_prep = alpha_f.prepare();

        let is_valid_l = E::final_exponentiation(&E::miller_loop(&[
            (&alpha_f_prep, &h_prep),
            (&self.l.prepare(), &alpha_x_d_prep)
        ])).unwrap() == E::Fqk::one();

        let is_valid_r = E::final_exponentiation(&E::miller_loop(&[
            (&alpha_f_prep, &h_prep),
            (&self.r.prepare(), &alpha_x_n_minus_d_prep)
        ])).unwrap() == E::Fqk::one();

        is_valid_l && is_valid_r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::PrimeField;
    use rand::{XorShiftRng, SeedableRng, Rand};

    #[test]
    fn wellformedness_1_arg_correctness() {
        let srs_x = Fr::from_str("432").unwrap();
        let srs_alpha = Fr::from_str("9876").unwrap();
        let srs = SRS::<Bls12>::dummy(824562, srs_x, srs_alpha);

        let n: usize = 1 << 16;
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let coeffs = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let arg = WellformedArg::new(vec![coeffs]);
        let challenges = (0..1).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let commitments = arg.commit(&srs);
        let proof = arg.prove(&challenges[..], &srs);
        let valid = proof.verify(n, &challenges, &commitments, &srs);

        assert!(valid);
    }

    #[test]
    fn wellformedness_3_args_correctness() {
        let srs_x = Fr::from_str("432").unwrap();
        let srs_alpha = Fr::from_str("9876").unwrap();
        let srs = SRS::<Bls12>::dummy(824562, srs_x, srs_alpha);

        let n: usize = 1 << 16;
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let coeffs = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let arg = WellformedArg::new(vec![coeffs; 3]);
        let challenges = (0..3).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let commitments = arg.commit(&srs);
        let proof = arg.prove(&challenges[..], &srs);
        let valid = proof.verify(n, &challenges, &commitments, &srs);

        assert!(valid);
    }

    #[test]
    fn wellformedness_3_args_soundness() {
        let srs_x = Fr::from_str("432").unwrap();
        let srs_alpha = Fr::from_str("9876").unwrap();
        let srs = SRS::<Bls12>::dummy(824562, srs_x, srs_alpha);

        let n: usize = 1 << 16;
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let coeffs_1 = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let arg_1 = WellformedArg::new(vec![coeffs_1; 3]);
        let commitments_1 = arg_1.commit(&srs);

        let coeffs_2 = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let arg_2 = WellformedArg::new(vec![coeffs_2; 3]);
        let challenges_2 = (0..3).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let proof = arg_2.prove(&challenges_2[..], &srs);
        let valid = proof.verify(n, &challenges_2, &commitments_1, &srs);

        assert!(!valid);
    }
}
