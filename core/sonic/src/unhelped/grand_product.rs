use pairing::{Engine, Field, CurveAffine};
use crate::{traits, transcript};

#[derive(Clone)]
pub struct GrandProductArg<E: Engine> {
    a_polys: Vec<Vec<E::Fr>>,
    c_polys: Vec<Vec<E::Fr>>,
    t_polys: Vec<Vec<E::Fr>>,
    v_elements: Vec<E::Fr>,
    n: usize,
}

impl<E: Engine> GrandProductArg<E> {
    pub fn new(polys: Vec<(Vec<E::Fr>, Vec<E::Fr>)>) -> Self {
        assert!(!polys.is_empty());

        let n = polys[0].0.len();
        // let mut a_polys = vec![];
        // let mut c_polys = vec![];
        // let mut v_elements = vec![];

        for poly in polys.into_iter() {

        }
        unimplemented!();
    }

    pub fn prove(&self) -> GrandProductProof<E> {
        unimplemented!();
    }
}

#[derive(Clone)]
pub struct CPoly<E: Engine>(Vec<Vec<E::Fr>>);

impl<E: Engine> CPoly<E> {
    pub fn new() -> Self {
        unimplemented!();
    }

    pub fn commit(&self) -> CPolyComm<E> {
        unimplemented!();
    }
}

#[derive(Clone)]
pub struct CPolyComm<E: Engine>(Vec<(E::G1Affine, E::Fr)>);


#[derive(Clone)]
pub struct GrandProductProof<E: Engine> {
    t_opening: E::G1Affine,
}

impl<E: Engine> GrandProductProof<E> {
    pub fn verify(&self) -> bool {
        unimplemented!();
    }
}
