use pairing::{Engine, Wnaf, CurveAffine, CurveProjective, Field, PrimeField};

/// Defined in Section 4.3: Structured Reference String
/// Pre-processing exponents
#[derive(Clone, Eq, PartialEq)]
pub struct SRS<E: Engine> {
    pub d: usize,

    /// g^{x^0}, g^{x^{1}}, g^{x^{2}}, ..., g^{x^{d}}
    pub g_pos_x: Vec<E::G1Affine>,

    /// g^{x^{0}}, g^{x^{-1}}, g^{x^{-2}}, ..., g^{x^{-d}}
    pub g_neg_x: Vec<E::G1Affine>,

    /// alpha*(g^{x^{1}}, g^{x^{2}}, ..., g^{x^{d}})
    pub g_pos_x_alpha: Vec<E::G1Affine>,

    /// alpha*(g^{x^{-1}}, g^{x^{-2}}, ..., g^{x^{-d}})
    pub g_neg_x_alpha: Vec<E::G1Affine>,

    /// h^{x^0}, h^{x^{1}}, h^{x^{2}}, ..., h^{x^{d}}
    pub h_pos_x: Vec<E::G2Affine>,

    /// h^{x^0}, h^{x^{-1}}, h^{x^{-2}}, ..., h^{x^{-d}}
    pub h_neg_x: Vec<E::G2Affine>,

    /// alpha*(h^{x^0}, h^{x^{1}}, h^{x^{2}}, ..., h^{x^{d}})
    pub h_pos_x_alpha: Vec<E::G2Affine>,

    /// alpha*(h^{x^0}, h^{x^{-1}}, h^{x^{-2}}, ..., h^{x^{-d}})
    pub h_neg_x_alpha: Vec<E::G2Affine>,
}


impl<E: Engine> SRS<E> {
    pub fn new(d: usize, x: E::Fr, alpha: E::Fr) -> Self {
        let mut g1 = Wnaf::new();
        let mut g1 = g1.base(E::G1::one(), d * 4);
        let mut g2 = Wnaf::new();
        let mut g2 = g2.base(E::G2::one(), d * 4);

        // Generate the Affine point Vec to get SRS elements.
        fn table<C: CurveAffine>(
            mut cur: C::Scalar,
            step: C::Scalar,
            num: usize,
            // W-ary Non-Adjacent Form
            table: &mut Wnaf<usize, &[C::Projective], &mut Vec<i64>>,
        ) -> Vec<C> {
            let mut v = vec![];
            for _ in 0..num {
                // Push x^i to v as a wnaf(the base is Projective representation)
                v.push(table.scalar(cur.into_repr()));
                cur.mul_assign(&step);
            }
            // Normalizes a slice of projective elements so that conversion to affine is cheap
            C::Projective::batch_normalization(&mut v);
            v.into_iter().map(|e| e.into_affine()).collect()
        }

        // Get parameters to construct SRS
        let x_inv = x.inverse().unwrap();
        let mut x_alpha = x;
        x_alpha.mul_assign(&alpha);

        let mut inv_x_alpha = x_inv;
        inv_x_alpha.mul_assign(&alpha);

        SRS {
            d: d,
            g_pos_x: table(E::Fr::one(), x, d + 1, &mut g1),
            g_neg_x: table(E::Fr::one(), x_inv, d + 1, &mut g1),
            g_pos_x_alpha: table(E::Fr::one(), x_alpha, d, &mut g1),
            g_neg_x_alpha: table(E::Fr::one(), inv_x_alpha, d, &mut g1),
            h_pos_x: table(E::Fr::one(), x, d + 1, &mut g2),
            h_neg_x: table(E::Fr::one(), x_inv, d + 1, &mut g2),
            h_pos_x_alpha: table(E::Fr::one(), x_alpha, d + 1, &mut g2),
            h_neg_x_alpha: table(E::Fr::one(), inv_x_alpha, d + 1, &mut g2),
        }
    }

    pub fn dummy(d: usize, _x: E::Fr, _alpha: E::Fr) -> Self {
        SRS {
            d: d,
            g_pos_x: vec![E::G1Affine::one(); d + 1],
            g_neg_x: vec![E::G1Affine::one(); d + 1],

            g_pos_x_alpha: vec![E::G1Affine::one(); d],
            g_neg_x_alpha: vec![E::G1Affine::one(); d],

            h_pos_x: vec![E::G2Affine::one(); d + 1],
            h_neg_x: vec![E::G2Affine::one(); d + 1],

            h_pos_x_alpha: vec![E::G2Affine::one(); d + 1],
            h_neg_x_alpha: vec![E::G2Affine::one(); d + 1],
        }
    }
}
