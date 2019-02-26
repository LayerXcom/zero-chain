// use jubjub::curve::{
//         JubjubEngine,
//         JubjubParams,
//         edwards,
//         PrimeOrder,
//         FixedGenerators,
//         ToUniform,
// }

// #[derive(Clone, PartialEq)]
// pub struct Ciphertext<E: JubjubEngine> {
//     gamma: edwards::Point<E, PrimeOrder>,
//     delta: edwards::Point<E, PrimeOrder>,
// }

// impl<E: JubjubEngine> Ciphertext<E> {
//     pub fn encrypt(
//         message: &[u8], // 32-bits
//         public_key: &edwards::Point<E, PrimeOrder>
//     ) -> Result<Self, &'static str> 
//     {

//     }
// }