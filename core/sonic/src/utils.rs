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
