use rstd::prelude::*;
use scrypto::jubjub::{edwards, JubjubEngine, PrimeOrder, Unknown};

#[derive(Encode, Decode, Default)]
// #[cfg_attr(feature = "std", derive(Debug))]
pub struct CommittedBalanceMap<E: JubjubEngine> (
    pub edwards::Point<E, Unknown>
);

#[derive(Encode, Decode, Default)]
// #[cfg_attr(feature = "std", derive(Debug))]
pub struct TxoMap(
    pub Vec<[u8; 32]>
);
