use pairing::Field;

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
pub fn mul_powers<'a, F: Field> (
    coeffs: &mut [F],
    first_power: F,
    base: F
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
