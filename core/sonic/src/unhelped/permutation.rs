use pairing::{Engine, Field, PrimeField, CurveAffine, CurveProjective};
use crate::srs::SRS;
use crate::utils::*;

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
        let p_1 = multiexp(
            srs.g_pos_x_alpha[..n].iter(),
            vec![E::Fr::one(); n].iter()
        ).into_affine();

        let p_3 = {
                let vals: Vec<E::Fr> = (1..=n).map(|e| {
                let mut repr = <<E as Engine>::Fr as PrimeField>::Repr::default();
                repr.as_mut()[0] = e as u64;
                let re = E::Fr::from_repr(repr).unwrap();

                re
            }).collect();

            multiexp(
                srs.g_pos_x_alpha[0..n].iter(),
                vals.iter()
            ).into_affine()
        };

        let mut p_2 = vec![];
        let mut p_4 = vec![];

        for (coeff, perm) in non_permuted_coeffs.iter().zip(perms.iter()) {
            assert_eq!(coeff.len(), perm.len());

            let p2_el = multiexp(
                srs.g_pos_x_alpha[..n].iter(),
                coeff.iter()
            ).into_affine();
            p_2.push(p2_el);

            let vals: Vec<E::Fr> = perm.iter().map(|e| {
                let mut repr = <<E as Engine>::Fr as PrimeField>::Repr::default();
                repr.as_mut()[0] = *e as u64;
                let re = E::Fr::from_repr(repr).unwrap();

                re
            }).collect();

            let p4_el = multiexp(
                srs.g_pos_x_alpha[..n].iter(),
                vals.iter()
            ).into_affine();
            p_4.push(p4_el);
        }

        SrsPerm {
            n,
            p_1,
            p_2,
            p_3,
            p_4,
        }
    }
}

pub struct ProofSCC<E: Engine> {
    j: usize,
    s_opening: E::G1Affine,
    s_zy: E::G1Affine,
}

pub struct PermutationArgument<E: Engine> {
    n: usize,
    non_permuted_coeffs: Vec<Vec<E::Fr>>,
    permutated_coeffs: Vec<Vec<E::Fr>>,
    permutated_y_coeffs: Vec<Vec<E::Fr>>,
    perms: Vec<Vec<usize>>,
}

impl<E: Engine> PermutationArgument<E> {
    pub fn new(coeffs: Vec<Vec<E::Fr>>, perms: Vec<Vec<usize>>) -> Self {
        assert!(!coeffs.is_empty());
        assert_eq!(coeffs.len(), perms.len());


        unimplemented!();
    }

    pub fn commit(&mut self, y: E::Fr, srs: &SRS<E>) -> Vec<(E::G1Affine, E::G1Affine)> {
        let acc = vec![];
        let mut permutated_coeffs = vec![];
        let mut permutated_y_coeffs = vec![];

        for (coeffs, perm) for self.non_permuted_coeffs.iter().zip(self.perms.iter()) {

            eval_bivar_poly(coeffs: &mut [E::Fr], first_power: E::Fr, base: E::Fr)
        }

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
    ) -> ProofSCC<E>
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
