use pairing::{Engine, Field};
// use bellman::multicore::Worker;
use crossbeam::channel::unbounded;

/// Basically used for polynomials represented as separeted iterator
/// (like positive and negative powers).
/// It can be used nested chains.
pub trait ChainExt: Iterator {
    fn chain_ext<U>(self, other: U) -> Chain<Self, U::IntoIter>
        where
            Self: Sized,
            U: IntoIterator<Item = Self::Item>,
    {
        Chain {
            t: self,
            u: other.into_iter(),
        }
    }
}

impl<I: Iterator> ChainExt for I {}

#[derive(Clone)]
pub struct Chain<T, U> {
    t: T,
    u: U
}

impl<T, U> Iterator for Chain<T, U>
    where T: Iterator, U: Iterator<Item = T::Item>
{
    type Item = T::Item;

    fn next(&mut self) -> Option<T::Item> {
        match self.t.next() {
            Some(v) => Some(v),
            None => match self.u.next() {
                Some(v) => Some(v),
                None => None,
            }
        }
    }
}

impl<T, U> ExactSizeIterator for Chain<T, U>
    where
        T: Iterator + ExactSizeIterator,
        U: Iterator<Item = T::Item> + ExactSizeIterator,
{
    fn len(&self) -> usize {
        self.t.len() + self.u.len()
    }
}

impl<T, U> DoubleEndedIterator for Chain<T, U>
    where
        T: Iterator + DoubleEndedIterator,
        U: Iterator<Item = T::Item> + DoubleEndedIterator,
{
    fn next_back(&mut self) -> Option<T::Item> {
        match self.u.next_back() {
            Some(v) => Some(v),
            None => match self.t.next_back() {
                Some(v) => Some(v),
                None => None,
            }
        }
    }
}

/// Multiply each coefficient by some power of the base in a form
/// `first_power * base^{i}`
/// This would be sparse, consecutive multiplication based on non-zero coefficients.
/// Basically, it is for the evaluation of one of the variables of bivariate polynomials.
/// For example, r(X, Y) at y.
pub fn eval_bivar_poly<'a, E: Engine> (
    coeffs: &mut [E::Fr],
    first_power: E::Fr,
    base: E::Fr
) {
    use bellman::multicore::Worker;
    let worker = Worker::new();

    worker.scope(coeffs.len(), |scope, chunk| {
        for (i, coeffs_chunk) in coeffs.chunks_mut(chunk).enumerate() {
            scope.spawn(move |_| {
                let mut current_power = base.pow(&[(i * chunk) as u64]);
                current_power.mul_assign(&first_power);

                for mut p in coeffs_chunk {
                    p.mul_assign(&current_power);

                    current_power.mul_assign(&base);
                }
            });
        }
    });
}

/// It is for the evaluation of univariate polynomials. For example, r(X, y) at z.
pub fn eval_univar_poly<'a, E: Engine> (
    coeffs: &[E::Fr],
    first_power: E::Fr,
    base: E::Fr
) -> E::Fr
{
    use bellman::multicore::Worker;
    let (tx, rx) = unbounded();
    let worker = Worker::new();

    worker.scope(coeffs.len(), |scope, chunk| {
        for (i, coeffs) in coeffs.chunks(chunk).enumerate() {
            let tx = tx.clone();

            scope.spawn(move |_| {
                let mut current_power = base.pow(&[(i * chunk) as u64]);
                current_power.mul_assign(&first_power);

                let mut acc = E::Fr::zero();

                for p in coeffs {
                    let mut tmp = *p;
                    tmp.mul_assign(&current_power);
                    acc.add_assign(&tmp);

                    current_power.mul_assign(&base);
                }

                tx.send(acc).expect("must send");
            });
        }
    });

    // The sender is dropped, disconnect the channel.
    drop(tx);

    let mut res = E::Fr::zero();

    loop {
        if rx.is_empty() {
            break;
        }

        let val = rx.recv().expect("must not be empty");
        res.add_assign(&val);
    }

    res
}

/// Batching polynomial commitment, Defined in appendix C.1.
/// Elementwise add coeffs of one polynomial with coeffs of other, that are
/// first multiplied by a scalar
pub fn mul_add_poly<E: Engine>(a: &mut [E::Fr], b: &[E::Fr], c: E::Fr) {
    use bellman::multicore::Worker;
    let worker = Worker::new();
    assert_eq!(a.len(), b.len());

    worker.scope(a.len(), |scope, chunk| {
        for (a, b) in a.chunks_mut(chunk).zip(b.chunks(chunk)) {
            scope.spawn(move |_| {
                for (a, b) in a.iter_mut().zip(b.iter()) {
                    let mut r = *b;
                    r.mul_assign(&c);
                    a.add_assign(&r);
                }
            });
        }
    });
}
