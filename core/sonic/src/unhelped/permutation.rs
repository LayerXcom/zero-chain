use pairing::{Engine, Field, PrimeField, CurveAffine, CurveProjective};
use crate::srs::SRS;
use crate::utils::*;

pub struct PermutationArgument<E: Engine> {
    n: usize,
    non_permuted_coeffs: Vec<Vec<E::Fr>>,
}

/// An additional elements in our shared information
pub struct SrsPerm<E: Engine> {
    n: usize,
    p_1: E::G1Affine,
    p_2: Vec<E::G1Affine>,
    p_3: E::G1Affine,
    p_4: Vec<E::G1Affine>,
}

impl<E: Engine> SrsPerm<E> {
    pub fn gen_from_coeffs(
        non_permuted_coeffs: &Vec<Vec<E::Fr>>,
        perms: &Vec<Vec<usize>>,
        srs: &SRS<E>,
    ) -> Self
    {
        assert!(!non_permuted_coeffs.is_empty());
        assert!(non_permuted_coeffs.len() == perms.len());

        let n = non_permuted_coeffs[0].len();

        // A commitment to the powers of x which is the srs's randomness
        let p_1 = multiexp(srs.g_pos_x_alpha[..n].iter(), vec![E::Fr::one(); n].iter()).into_affine();

        // let p_3 = multiexp(srs.g_pos_x_alpha[..n], (1..=n).map(|e| E::Fr::from_str("e"))).into_affine();

        // let mut p_2 = vec![];
        // let mut p_4 = vec![];

        unimplemented!();
    }
}

pub struct ProofSigOfCorrectComp<E: Engine> {
    j: usize,
    s_opening: E::G1Affine,
    s_zy: E::G1Affine,
}

impl<E: Engine> PermutationArgument<E> {
    pub fn commit(&mut self, y: E::Fr, srs: &SRS<E>) -> Vec<(E::G1Affine, E::G1Affine)> {
        unimplemented!();
    }

    pub fn gen_perm_arg(
        &self,
        beta: E::Fr,
        gamma: E::Fr,
        srs: &SRS<E>,
        y: E::Fr,
        z: E::Fr,
        srs_perm: &SrsPerm<E>,
    ) -> ProofSigOfCorrectComp<E>
    {
        unimplemented!();
    }
}

fn permute<E: Engine>(coeffs: &[E::Fr], perm: &[usize]) -> Vec<E::Fr> {
    assert_eq!(coeffs.len(), perm.len());
    let mut res = vec![E::Fr::zero(); coeffs.len()];

    for (i, j) in perm.iter().enumerate() {
        res[*j - 1] = coeffs[i];
    }
    res
}
