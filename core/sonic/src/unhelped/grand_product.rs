/// Defined in appendix B: THE GRAND PRODUCT ARGUMENT
use pairing::{Engine, Field, CurveAffine, CurveProjective};
use crate::{traits, transcript};
use crate::srs::SRS;
use crate::utils::*;

#[derive(Clone)]
pub struct GrandProductArg<E: Engine> {
    /// the coeffientis of two commitments U and V,
    /// where U and V are fully well-formed commitments to n-degree polynomials.
    /// U = g^{alpha * \sum\limits_{i=1}^n a_i x^i, V = g^{alpha * \sum\limits_{i=1}^n a_{i+n+1} x^i,
    a_polys: Vec<Vec<E::Fr>>,

    /// g^{alpha * \sum\limits_{i=1}^{2n+1} c_i x^i
    /// Following the requirements.
    /// (1) a \cdot b = c
    /// (2) b = (1, c_1, ..., c_{2n+1})
    /// (3) c_{n+1} = 1
    /// (4) c_{2n+1} = c_n
    c_polys: Vec<Vec<E::Fr>>,

    t_polys: Option<Vec<E::Fr>>,

    c_minus: Vec<E::Fr>,

    n: usize,
}

impl<E: Engine> GrandProductArg<E> {
    /// Create the Grand product arguments from the given two polynomials
    pub fn gen_a_c(polys: Vec<(Vec<E::Fr>, Vec<E::Fr>)>) -> Self {
        assert!(!polys.is_empty());
        let n = polys[0].0.len();
        let mut a_polys = vec![];
        let mut c_polys = vec![];
        let mut c_minus = vec![];

        for poly in polys.into_iter() {
            let (u_poly, v_poly) = poly;
            assert!(u_poly.len() == v_poly.len());
            assert!(u_poly.len() == n);

            let mut c_poly = Vec::with_capacity(2 * n + 1);
            let mut a_poly = Vec::with_capacity(2 * n + 1);
            let mut c_coeff = E::Fr::one();

            // c_1 = a_1 * b_1(=1)
            // c_2 = a_2 * b_2(=c_1) = a_2 * a_1 * 1
            // c_3 = a_3 * b_3(=c_2) = a_3 * a_2 * a_1 * 1
            // ...
            // c_n = a_n + c_{n-1} = \prod a_i
            for a in u_poly.iter() {
                c_coeff.mul_assign(a);
                c_poly.push(c_coeff);
            }

            // v = a_{n+1} = c_{n}^-1
            let v = c_poly[n - 1].inverse().unwrap();

            let mut c_coeff = E::Fr::one(); // re-set to one
            // (3) c_{n+1} = 1
            c_poly.push(c_coeff);

            for b in v_poly.iter() {
                c_coeff.mul_assign(b);
                c_poly.push(c_coeff);
            }

            assert_eq!(c_poly.len(), 2 * n + 1);
            // (4) c_{2n+1} == c_{n}
            assert_eq!(c_poly[2 * n], c_poly[n - 1]);

            // Define the a_i arguments
            // a_1, a_2, ..., a_n from U
            a_poly.extend(u_poly);
            // a_{n+1} = 0
            a_poly.push(E::Fr::zero());
            // a_{n+2}, a_{n+3}, ..., a_{2n+1} from V
            a_poly.extend(v_poly);

            a_polys.push(a_poly);
            c_polys.push(c_poly);
            c_minus.push(v);
        }

        GrandProductArg {
            a_polys,
            c_polys,
            c_minus,
            t_polys: None,
            n,
        }
    }

    pub fn commit_c_poly(&self, srs: &SRS<E>) -> Vec<(E::G1Affine, E::Fr)> {
        let mut acc = vec![];
        let n = self.c_polys[0].len();

        for (poly, v) in self.c_polys.iter().zip(self.c_minus.iter()) {
            let c = multiexp(
                srs.g_pos_x_alpha[0..n].iter(),
                poly.iter()
            ).into_affine();

            acc.push((c, *v));
        }

        acc
    }

    pub fn commit_t_poly(&mut self, challenges: &Vec<E::Fr>, y: E::Fr, srs: &SRS<E>) -> E::G1Affine {
        assert_eq!(self.a_polys.len(), challenges.len());
        let mut t_poly: Option<Vec<E::Fr>> = None;

        for (((a_poly, c_poly), v), challenge) in self.a_polys.iter()
                                                .zip(self.c_polys.iter())
                                                .zip(self.c_minus.iter())
                                                .zip(challenges.iter())
        {
            // let mut a_xy = a_poly.clone();
            // let mut c_xy = c_poly.clone();
            // let v = *v;

            let r_xy = {
                // U * V^{x}^{n+1}
                let mut tmp = y;
                tmp.square();
                eval_bivar_poly(&mut a_poly[..], tmp, y);

                let tmp = y.pow(&[(self.n+2) as u64]);
                let mut
            };
        }
        unimplemented!();
    }

    pub fn prove(&self, srs: &SRS<E>) -> GrandProductProof<E> {

        // gprodP_1


        // gprodV -> groudP:


        // gprodP_2(y) -> T:


        // gprodV -> gprodP:

        // gprod_3(z) -> T:

        unimplemented!();
    }

}

// #[derive(Clone)]
// pub struct CPoly<E: Engine>(Vec<Vec<E::Fr>>);

// impl<E: Engine> CPoly<E> {
//     pub fn new(polys: Vec<(Vec<E::Fr>, Vec<E::Fr>)>) -> Self {

//         unimplemented!();
//     }

//     pub fn commit(&self, srs: &SRS<E>) -> CPolyComm<E> {
//         let mut res = vec![];
//         let n = self.0.len();

//         for ()
//         unimplemented!();
//     }
// }

#[derive(Clone)]
pub struct CPolyComm<E: Engine>(Vec<(E::G1Affine, E::Fr)>);

#[derive(Clone)]
pub struct GrandProductProof<E: Engine> {
    a_yz: E::Fr,
    a_opening: E::G1Affine,
    c_z_inv: E::Fr,
    c_opening: E::G1Affine,
    k_y: E::Fr,
    k_opening: E::G1Affine,
    t_opening: E::G1Affine,
}

impl<E: Engine> GrandProductProof<E> {
    pub fn verify(
        &self,
        n: usize,
        randomness: &Vec<E::Fr>,
        t_commitment: E::G1Affine,
        c_commitments: &Vec<(E::G1Affine, E::Fr)>,
        y: E::Fr,
        z: E::Fr,
        srs: &SRS<E>
    ) -> bool {

        // Re-calculate t(z, y)

        //

        unimplemented!();
    }
}
