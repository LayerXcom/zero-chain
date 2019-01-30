#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

extern crate shasper_crypto as scrypto;
extern crate parity_crypto as pcrypto;
extern crate zero_chain_proofs as proofs;
extern crate bellman;
extern crate pairing;
