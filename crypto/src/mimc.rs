use scrypto::jubjub::{
    JubjubEngine,
    ToUniform
};

use blake2_rfc::blake2s::Blake2s;

use super::constants::{DEFAULT_ROUND, DEFAULT_SEED, MIMC_PERSONALIZATION};

pub fn mimc_constants<'a, E>(
    seed: &'a[u8],
    scalar_field: E::Fs,
    rounds: u64 
) -> Vec<E::Fs>
    where E: JubjubEngine
{
    let mut res = Vec::with_capacity(DEFAULT_ROUND);
    let mut preimage = seed;        

    // let mut h = Blake2s::with_params(32, &[], &[], MIMC_PERSONALIZATION);
    // h.update(&preimage);
    // let mut tmp = &mut *(h.finalize().as_bytes());
    // res.push(tmp);
    
    for _ in 0..rounds {
        let mut h = Blake2s::with_params(32, &[], &[], MIMC_PERSONALIZATION);    
        // tmp = &mut *tmp;
        h.update(preimage);                     
        preimage = h.finalize(); 
        
        res.push(E::Fs::to_uniform(preimage.as_ref()));    
    }

    assert_eq!(res.len(), 91);
    res
}
