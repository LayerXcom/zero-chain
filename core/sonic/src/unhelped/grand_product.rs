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
    /// Following the constraint system
    /// (1) a \cdot b = c
    /// (2) b = (1, c_1, ..., c_{2n+1})
    /// (3) c_{n+1} = 1
    /// (4) c_{2n+1} = c_n
    c_polys: Vec<Vec<E::Fr>>,

    t_polys: Option<Vec<E::Fr>>,

    v_elements: Vec<E::Fr>,

    n: usize,
}

impl<E: Engine> GrandProductArg<E> {
    /// Initialize the Grand product arguments from the given two polynomials
    pub fn new(polys: Vec<(Vec<E::Fr>, Vec<E::Fr>)>) -> Self {
        assert!(!polys.is_empty());
        let n = polys[0].0.len();
        let mut a_polys = vec![];
        let mut c_polys = vec![];
        let mut v_elements = vec![];

        for poly in polys.into_iter() {
            let (u_poly, v_poly) = poly;
            assert!(u_poly.len() == v_poly.len());
            assert!(u_poly.len() == n);

            let mut c_poly = Vec::with_capacity(2 * n + 1);
            let mut a_poly = Vec::with_capacity(2 * n + 1);
            let mut c_coeff = E::Fr::one();

            for a in u_poly.iter() {
                c_coeff.mul_assign(a);
                c_poly.push(c_coeff);
            }
            assert_eq!(c_poly.len(), n);
            a_poly.extend(u_poly);

            // v = a_{n+1} = c_{n}^-1
            let v = c_poly[n - 1].inverse().unwrap();

            a_poly.push(E::Fr::zero()); // n + 1
            let mut c_coeff = E::Fr::one(); //re-set to one
            c_poly.push(c_coeff); // n + 1

            for b in v_poly.iter() {
                c_coeff.mul_assign(b);
                c_poly.push(c_coeff);
            }

            assert_eq!(c_poly.len(), 2 * n + 1);
            a_poly.extend(v_poly); // a_poly = u_poly || v_poly // 2n

            assert_eq!(c_poly[n - 1], c_poly[2 * n]); // c_{n} == c_{2n+1}

            a_polys.push(a_poly);
            c_polys.push(c_poly);
            v_elements.push(v);
        }

        GrandProductArg {
            a_polys,
            c_polys,
            v_elements,
            t_polys: None,
            n,
        }
    }

    pub fn commit_c_poly(&self, srs: &SRS<E>) -> Vec<(E::G1Affine, E::Fr)> {
        let mut acc = vec![];
        let n = self.c_polys[0].len();

        for (poly, v) in self.c_polys.iter().zip(self.v_elements.iter()) {
            let c = multiexp(
                srs.g_pos_x_alpha[0..n].iter(),
                poly.iter()
            ).into_affine();

            acc.push((c, *v));
        }

        acc
    }

    pub fn commit_t_poly(&mut self, challenges: &Vec<E::Fr>, y: E::Fr, srs: &SRS<E>) -> E::G1Affine {

        for (((a_poly, c_poly, v), challenge) in self.a_polys.iter()
                                                .zip(self.c_polys.iter())
                                                .zip(self.v_elements.iter())
                                                .zip(challenges.iter())
        {
            let r_xy = {

            };
        }
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
