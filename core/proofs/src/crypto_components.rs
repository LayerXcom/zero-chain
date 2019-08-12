use scrypto::jubjub::JubjubEngine;
use crate::elgamal::Ciphertext;
use crate::EncryptionKey;

#[derive(Clone)]
pub struct MultiCiphertexts<E: JubjubEngine> {
    sender: Ciphertext<E>,
    recipient: Ciphertext<E>,
    decoys: Option<Vec<Ciphertext<E>>>,
    fee: Ciphertext<E>,
}

impl<E: JubjubEngine> MultiCiphertexts<E> {
    pub fn new_for_confidential(
        sender: Ciphertext<E>,
        recipient: Ciphertext<E>,
        fee: Ciphertext<E>,
    ) -> Self {
        MultiCiphertexts {
            sender,
            recipient,
            decoys: None,
            fee,
        }
    }

    pub fn new_for_anonymous(
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
        }
    }
}

#[derive(Clone)]
pub struct MultiEncKeys<E: JubjubEngine> {
    recipient: EncryptionKey<E>,
    decoys: Option<Vec<EncryptionKey<E>>>,
}

impl<E: JubjubEngine> MultiEncKeys<E> {
    pub fn new_for_confidential(recipient: EncryptionKey<E>) -> Self {
        MultiEncKeys {
            recipient,
            decoys: None,
        }
    }

    pub fn new_for_anonymous(
        recipient: EncryptionKey<E>,
        decoys: Vec<EncryptionKey<E>>,
    ) -> Self {
        MultiEncKeys {
            recipient,
            decoys: Some(decoys),
        }
    }

    pub fn get_recipient(&self) -> EncryptionKey<E> {
        self.recipient
    }
}
