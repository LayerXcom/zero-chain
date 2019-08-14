use scrypto::jubjub::{JubjubEngine, FixedGenerators};
use crate::elgamal::Ciphertext;
use crate::EncryptionKey;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct Confidential;
#[derive(Clone, Debug)]
pub struct Anonymous;

pub trait PrivacyConfing { }

impl PrivacyConfing for Confidential { }
impl PrivacyConfing for Anonymous { }

#[derive(Clone, Debug)]
pub struct MultiCiphertexts<E: JubjubEngine, PC: PrivacyConfing> {
    sender: Ciphertext<E>,
    recipient: Ciphertext<E>,
    decoys: Option<Vec<Ciphertext<E>>>,
    fee: Ciphertext<E>,
    _marker: PhantomData<PC>,
}

impl<E: JubjubEngine, PC: PrivacyConfing> MultiCiphertexts<E, PC> {
    pub fn get_sender(&self) -> &Ciphertext<E> {
        &self.sender
    }

    pub fn get_recipient(&self) -> &Ciphertext<E> {
        &self.recipient
    }

    pub fn get_fee(&self) -> &Ciphertext<E> {
        &self.fee
    }
}

pub trait CiphertextTrait<E: JubjubEngine> {
    type PC: PrivacyConfing;

    fn encrypt(
        amount: u32,
        fee: u32,
        enc_key_sender: &EncryptionKey<E>,
        enc_keys: &MultiEncKeys<E, Self::PC>,
        randomness: &E::Fs,
        params: &E::Params,
    ) -> Self;
}

impl<E: JubjubEngine> CiphertextTrait<E> for MultiCiphertexts<E, Confidential> {
    type PC = Confidential;

    fn encrypt(
        amount: u32,
        fee: u32,
        enc_key_sender: &EncryptionKey<E>,
        enc_keys: &MultiEncKeys<E, Self::PC>,
        randomness: &E::Fs,
        params: &E::Params,
    ) -> Self {
        let p_g = FixedGenerators::NoteCommitmentRandomness;

        let cipher_sender = Ciphertext::encrypt(
            amount,
            randomness,
            enc_key_sender,
            p_g,
            params
        );

        let cipher_recipient = Ciphertext::encrypt(
            amount,
            randomness,
            &enc_keys.get_recipient(),
            p_g,
            params
        );

        let cipher_fee = Ciphertext::encrypt(
            fee,
            randomness,
            enc_key_sender,
            p_g,
            params
        );

        MultiCiphertexts::<E, Self::PC>::new(
            cipher_sender,
            cipher_recipient,
            cipher_fee
        )
    }
}

impl<E: JubjubEngine> MultiCiphertexts<E, Confidential> {
    fn new(
        sender: Ciphertext<E>,
        recipient: Ciphertext<E>,
        fee: Ciphertext<E>,
    ) -> Self {
        MultiCiphertexts {
            sender,
            recipient,
            decoys: None,
            fee,
            _marker: PhantomData,
        }
    }
}

impl<E: JubjubEngine> MultiCiphertexts<E, Anonymous> {
    fn new(
        sender: Ciphertext<E>,
        recipient: Ciphertext<E>,
        decoys: Vec<Ciphertext<E>>,
        fee: Ciphertext<E>,
    ) -> Self {
        MultiCiphertexts {
            sender,
            recipient,
            decoys: Some(decoys),
            fee,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MultiEncKeys<E: JubjubEngine, PC> {
    recipient: EncryptionKey<E>,
    decoys: Option<Vec<EncryptionKey<E>>>,
    _marker: PhantomData<PC>
}

impl<E: JubjubEngine, PC> MultiEncKeys<E, PC> {
    pub fn get_recipient(&self) -> &EncryptionKey<E> {
        &self.recipient
    }
}

impl<E: JubjubEngine> MultiEncKeys<E, Confidential> {
    pub fn new(recipient: EncryptionKey<E>) -> Self {
        MultiEncKeys {
            recipient,
            decoys: None,
            _marker: PhantomData,
        }
    }
}

impl<E: JubjubEngine> MultiEncKeys<E, Anonymous> {
    pub fn new(
        recipient: EncryptionKey<E>,
        decoys: Vec<EncryptionKey<E>>,
    ) -> Self {
        MultiEncKeys {
            recipient,
            decoys: Some(decoys),
            _marker: PhantomData,
        }
    }
}
