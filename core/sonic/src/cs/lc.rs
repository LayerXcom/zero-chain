
#[derive(Copy, Clone, Debug)]
pub enum Variable {
    A(usize),
    B(usize),
    C(usize),
}

#[derive(Debug)]
pub enum Coeff<E: Engine> {
    Zero,
    One,
    NegativeOne,
    Full(E::Fr),
}
