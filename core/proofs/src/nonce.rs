use scrypto::jubjub::{edwards, PrimeOrder, JubjubEngine};

#[derive(Clone, Debug)]
pub struct Nonce<E: JubjubEngine>(edwards::Point<E, PrimeOrder>);

impl<E: JubjubEngine> Nonce<E> {
    pub fn new(point: edwards::Point<E, PrimeOrder>) -> Self {
        Nonce(point)
    }
}

#[derive(Clone, Debug)]
pub struct GEpoch<E: JubjubEngine>(edwards::Point<E, PrimeOrder>);

impl<E: JubjubEngine> GEpoch<E> {
    pub fn new(point: edwards::Point<E, PrimeOrder>) -> Self {
        GEpoch(point)
    }
}
