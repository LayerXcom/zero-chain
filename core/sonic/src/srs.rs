use pairing::{Engine, Wnaf, CurveAffine};

/// Defined in $4.3: Structured Reference String
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
        let mut g1 = g1.base(E:G1::one(), d * 4);

        fn table<C: CurveAffine>(
            mut cur: C::Scalar,
            step: C::Scalar,
            num: usize,
            // W-ary Non-Adjacent Form
            table:
        )

    }
}