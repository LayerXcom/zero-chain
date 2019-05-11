/// Defined in appendix B.3 Well-formedness Argument
use pairing::{Engine, Field, CurveAffine, CurveProjective};
use crate::srs::SRS;
use crate::utils::*;

// Nested vec because of \sum\limits_{j=1}^M, for now.
#[derive(Clone)]
pub struct WellformednessArg<E: Engine> (Vec<Vec<E::Fr>>);

/// A proof of Well-formedness Argument
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

        WellformednessArg(polys)
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
        let n = self.0[0].len();
        let d = srs.d;

        assert_eq!(m, challenges.len());
        assert!(n < d);

        let mut acc: Vec<E::Fr> = vec![E::Fr::zero(); n];

        // Batching well-formedness arguments
        for j in 0..m {
            mul_add_poly::<E>(&mut acc[..], &self.0[j][..], challenges[j])
        }

        // g^{x^{-d} * f(x)} where f(x) is well-formed, meaning dont't have negative powers and constant term.
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

        WellformednessProof {
            l,
            r,
        }
    }

    /// The verifier can check with the pairings
    /// e(g^{alpha * f(x)}, h) = e(proof.l, h^{alpha * x^{d}})
    /// e(g^{alpha * f(x)}, h) = e(proof.r, h^{alpha * x^{n-d}})
    pub fn verify(
        n: usize,
        challenges: &Vec<E::Fr>,
        commitments: &Vec<E::G1Affine>,
        proof: &WellformednessProof<E>,
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
            commitments.iter(),
            challenges.iter()
        ).into_affine();
        let alpha_f_prep = alpha_f.prepare();

        let valid_1 = E::final_exponentiation(&E::miller_loop(&[
            (&alpha_f_prep, &h_prep),
            (&proof.l.prepare(), &alpha_x_d_prep)
        ])).unwrap() == E::Fqk::one();

        let valid_2 = E::final_exponentiation(&E::miller_loop(&[
            (&alpha_f_prep, &h_prep),
            (&proof.r.prepare(), &alpha_x_n_minus_d_prep)
        ])).unwrap() == E::Fqk::one();

        valid_1 && valid_2
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

        let arg = WellformednessArg::new(vec![coeffs]);
        let challenges = (0..1).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let commitments = arg.commit(&srs);
        let proof = arg.prove(challenges.clone(), &srs);
        let valid = WellformednessArg::verify(n, &challenges, &commitments, &proof, &srs);

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

        let arg = WellformednessArg::new(vec![coeffs; 3]);
        let challenges = (0..3).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let commitments = arg.commit(&srs);
        let proof = arg.prove(challenges.clone(), &srs);
        let valid = WellformednessArg::verify(n, &challenges, &commitments, &proof, &srs);

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

        let arg_1 = WellformednessArg::new(vec![coeffs_1; 3]);
        let commitments_1 = arg_1.commit(&srs);

        let coeffs_2 = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let arg_2 = WellformednessArg::new(vec![coeffs_2; 3]);
        let challenges_2 = (0..3).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let proof = arg_2.prove(challenges_2.clone(), &srs);
        let valid = WellformednessArg::verify(n, &challenges_2, &commitments_1, &proof, &srs);

        assert!(!valid);
    }
}
