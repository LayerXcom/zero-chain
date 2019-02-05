use rstd::prelude::*;
use scrypto::jubjub::{edwards, JubjubEngine, PrimeOrder, Unknown};
use zcrypto::constants;
use zprimitives::cm_encryption::Ciphertext;

#[derive(Encode, Decode, Default)]
// #[cfg_attr(feature = "std", derive(Debug))]
pub struct CommittedBalanceMap<E: JubjubEngine> (
    pub edwards::Point<E, Unknown>
);

#[derive(Encode, Decode, Default)]
// #[cfg_attr(feature = "std", derive(Debug))]
pub struct TxoMap<E: JubjubEngine>(
    pub Vec<Ciphertext<E>>
);
