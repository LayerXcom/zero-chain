use pairing::{Engine, Field, CurveAffine, CurveProjective};
use crate::srs::SRS;
use crate::utils::*;

pub struct PermutationArgument<E: Engine> {
    n: usize,
}


pub struct SrsPerm<E: Engine> {
    n: usize,
}

impl<E: Engine> SrsPerm<E> {
    pub fn gen_srs_for_perm(
        non_permuted_coeffs: &Vec<Vec<E::Fr>>,
        perms: &Vec<Vec<usize>>,
        srs: &SRS<E>,
    ) -> Self
    {
        unimplemented!();
    }
}

pub struct ProofSigOfCorrectComp<E: Engine> {
    s_opening: E::G1Affine,
    s_zy: E::G1Affine,
}

impl<E: Engine> PermutationArgument {
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
    let mut res = Vec<E::Fr> = vec![E::Fr::zero(); coeff.len()];

    for (i, j) in perm.iter().enumerate() {
        res[*j - 1] = coeffs[i];
    }
    res
}
