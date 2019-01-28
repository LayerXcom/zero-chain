
use proofs::{
    ValueCommitment,
}

use scrypto::jubjub::{
    JubjubEngine,
    FixedGenerators
};

use blake2_rfc::blake2s::Blake2s;

pub const DEFAULT_SEED: &'static [u8; 4] = b"mimc";
pub const DEFAULT_ROUND: u64 = 97;
pub const DEFAULT_EXPONENT: u64 = 7;

pub fn mimc_constants<E>(
    seed: &str,
    scalar_field: E::Fs,
    rounds: u64 
) -> &[u8; DEFAULT_ROUND]
    where E: JubjubEngine
{
    let mut res;
    let mut h = Blake2s::with_params(32, &[], &[], constants::MIMC_PERSONALIZATION)
    for i in 0..rounds {
        
    }
}