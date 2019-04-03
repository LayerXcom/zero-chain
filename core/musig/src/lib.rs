// This file is based on https://github.com/w3f/schnorrkel/blob/master/src/musig.rs

use jubjub::{
    curve::{
        FixedGenerators,
        JubjubEngine,
        JubjubParams,
        Unknown,
        PrimeOrder,
        edwards::Point
        },
    redjubjub::{
        PrivateKey,
        PublicKey,
        Signature,
    }
};
use std::collections::BTreeMap;
use merlin::Transcript;

pub trait TranscriptProtocol {}
impl TranscriptProtocol for Transcript {}

const COMMITMENT_SIZE: usize = 32;

pub struct Commitment(pub [u8; COMMITMENT_SIZE]);

impl Commitment {
    fn for_r() -> Commitment {
        unimplemented!();
    }
}

pub struct KeyPair<E: JubjubEngine> {
    pub secret: PrivateKey<E>,
    pub public: PublicKey<E>,
}

enum CoR<E: JubjubEngine> {
    Commit(Commitment),                 // H(R_i)
    Reveal{ R: Point<E, PrimeOrder>},   // R_i
    Cosigned { s: E::Fs },              // s_i extracted from Cosignature type
    Collect { R: Point<E, PrimeOrder>, s: E::Fs },
}

impl<E: JubjubEngine> CoR<E> {
    fn set_revealsed(&mut self) {
        unimplemented!();
    }

    fn set_cosigned(&mut self, s: E::Fs) -> Result<(), &'static str> {
        unimplemented!();
    }
}

/// Schnorr multi-signature (MuSig) container generic over its session types
pub struct MuSig<T: TranscriptProtocol, S, E: JubjubEngine> {
    t: T,
    Rs: BTreeMap<PublicKey<E>, CoR<E>>,
    stage: S
}

impl<T: TranscriptProtocol, S, E: JubjubEngine> MuSig<T, S, E> {

}

/// Commitment stage for cosigner's `R` values
pub struct CommitStage<'k, E: JubjubEngine> {
    keypair: &'k KeyPair<E>,
    r_me: E::Fs,
    R_me: Point<E, PrimeOrder>,
}

impl<'k, T: TranscriptProtocol, E: JubjubEngine> MuSig<T, CommitStage<'k, E>, E> {
    /// Our commitment to our `R` to send to all other cosigners
    pub fn our_commitment(&self) -> Commitment {
        unimplemented!();
    }

    /// Add a new cosigner's public key and associated `R` bypassing our commiement phase.
    pub fn add_thier_commitment(&mut self, them: PublicKey<E>, theirs: Commitment) -> Result<(), &'static str> {
        unimplemented!();
    }

    /// Commit to reveal phase transition.
    pub fn reveal_stage(self) -> MuSig<T, RevealStage<'k, E>, E> {
        unimplemented!();
    }
}

/// Reveal stage for cosigner's `R` values
pub struct RevealStage<'k, E: JubjubEngine> {
    keypair: &'k KeyPair<E>,
    r_me: E::Fs,
    R_me: Point<E, PrimeOrder>,
}

/// Revealed `R_i` values shared between cosigners during signing
pub struct Reveal(pub [u8; 32]);

impl<'k, T: TranscriptProtocol, E: JubjubEngine> MuSig<T, RevealStage<'k, E>, E> {
    /// Reveal our `R` contribution to send to all other cosigners
    pub fn our_reveal(&self) -> Reveal {
        unimplemented!();
    }
}

/// Final cosining stage collection
pub struct CosignStage<E: JubjubEngine> {
    /// Collective `R` value
    R: Point<E, PrimeOrder>,
    /// Our `s` contribution
    s_me: E::Fs,
}

/// Cosignatures shared between cosigners
pub  struct Cosignature(pub [u8; 32]);

impl<T: TranscriptProtocol, E: JubjubEngine> MuSig<T, CosignStage<E>, E> {
    /// Reveals our signature contribution
    pub fn our_cosignature(&self) -> Cosignature {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_sig() {

    }
}
