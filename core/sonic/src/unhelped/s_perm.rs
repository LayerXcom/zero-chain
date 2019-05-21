use pairing::{Engine, Field};
use crate::cs::{Backend, Variable, Coeff};

pub struct SxPerm<E: Engine> {
    y: E::Fr,

    /// Current value of y^{q+n}
    yq: E::Fr,

    u: Vec<E::Fr>,

    v: Vec<E::Fr>,

    w: Vec<E::Fr>,
}

impl<'a, E: Engine> Backend<E> for &'a mut SxPerm<E> {
    fn new_linear_constraint(&mut self) {
        self.yq.mul_assign(&self.y);
    }

    fn insert_coefficient(&mut self, var: Variable, coeff: Coeff<E>) {
        unimplemented!();
    }
}