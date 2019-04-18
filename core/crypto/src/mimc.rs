// use jubjub::curve::{
//     JubjubEngine,
//     ToUniform,
//     fs::Fs,
// };

// use pairing::{
//     PrimeField,
//     PrimeFieldRepr,
//     Field,
//     bls12_381::{Bls12},
// };

// use blake2_rfc::blake2s::Blake2s;

// use rand::{thread_rng, Rng, Rand};

// use super::constants::{DEFAULT_MIMC_ROUND, DEFAULT_MIMC_SEED, MIMC_PERSONALIZATION};

// pub fn mimc_constants<'a, E>(
//     seed: &'a[u8],
//     scalar_field: E::Fs,
//     rounds: u64
// ) -> Vec<E::Fs>
//     where E: JubjubEngine
// {
//     let mut res = Vec::with_capacity(DEFAULT_MIMC_ROUND);
//     let mut preimage = seed;

//     // let mut h = Blake2s::with_params(32, &[], &[], MIMC_PERSONALIZATION);
//     // h.update(&preimage);
//     // let mut tmp = &mut *(h.finalize().as_bytes());
//     // res.push(tmp);

//     for _ in 0..rounds {
//         let mut h = Blake2s::with_params(32, &[], &[], MIMC_PERSONALIZATION);
//         // tmp = &mut *tmp;
//         h.update(preimage);
//         preimage = h.finalize();

//         res.push(E::Fs::to_uniform(preimage.as_ref()));
//     }

//     assert_eq!(res.len(), 91);
//     res
// }

// This is an implementation of MiMC.
// See http://eprint.iacr.org/2016/492 for more
// information about this construction.
// pub fn mimc<E: JubjubEngine>(
//     mut x: E::Fs,
//     k: E::Fs,
//     constants: Vec<E::Fs>
// ) -> E::Fs
// {
//     assert_eq!(constants.len(), DEFAULT_MIMC_ROUND);

//     for i in 0..DEFAULT_MIMC_ROUND {
//         let mut tmp1 = x;
//         tmp1.add_assign(&k);
//         tmp1.add_assign(&constants[i]);
//         let tmp2 = tmp1;
//         tmp1.square();
//         tmp1.square();
//         tmp1.square();

//         tmp1.mul_assign(&tmp2);
//         x = tmp1;
//     }
//     x.add_assign(&k);
//     x
// }

// #[test]
// fn test_mimc() {
//     let mut rng = &mut thread_rng();
//     let constants: Vec<Fs> = (0..DEFAULT_MIMC_ROUND)
//         .map(|_| rng.gen())
//         .collect::<Vec<Fs>>();

//     let x: Fs = Fs::rand(&mut rng);
//     let k: Fs = Fs::rand(&mut rng);

//     let cipher_text: Fs = mimc::<Bls12>(x, k, constants.clone());
//     let plain_text: Fs = mimc::<Bls12>(cipher_text, k, constants);
//     assert_eq!(x, plain_text);
// }
