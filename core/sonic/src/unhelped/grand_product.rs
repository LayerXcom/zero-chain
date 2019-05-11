use pairing::{Engine, Field, CurveAffine};

// #[derive(Clone)]
// pub struct GrandProductArg<E: Engine> {
//     a_polys: Vec<Vec<E::Fr>>,
//     c_
// }

#[derive(Clone)]
pub struct GrandProductProof<E: Engine> {


    t_opening: E::G1Affine,
}

// impl<E: Engine> GrandProductArg<E> {

// }
