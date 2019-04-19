use pairing::Engine;
pub mod commitment;
pub mod s_eval;
pub mod operations;

pub struct Polynomial<E: Engine>(Vec<E::Fr>);
