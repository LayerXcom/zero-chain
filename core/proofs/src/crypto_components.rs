use bellman::{
        groth16::{
            Parameters,
            PreparedVerifyingKey,
            Proof,
        },
        SynthesisError,
};
use rand::Rng;
use scrypto::{
    jubjub::{
        JubjubEngine,
        FixedGenerators,
        edwards,
        PrimeOrder,
    },
    redjubjub::PublicKey,
};
use polkadot_rs::Api;
use crate::{
    elgamal::Ciphertext,
    EncryptionKey,
    SpendingKey,
};
use std::{
    io::{self, BufReader, Read},
    path::Path,
    fs::File,
    marker::PhantomData,
};

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
    fee: Option<Ciphertext<E>>,
    _marker: PhantomData<PC>,
}

impl<E: JubjubEngine, PC: PrivacyConfing> MultiCiphertexts<E, PC> {
    pub fn get_sender(&self) -> &Ciphertext<E> {
        &self.sender
    }

    pub fn get_recipient(&self) -> &Ciphertext<E> {
        &self.recipient
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
            cipher_fee,
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
            fee: Some(fee),
            _marker: PhantomData,
        }
    }

    pub fn get_fee(&self) -> &Ciphertext<E> {
        &self.fee.as_ref().expect("should have fee")
    }
}

impl<E: JubjubEngine> MultiCiphertexts<E, Anonymous> {
    fn new(
        sender: Ciphertext<E>,
        recipient: Ciphertext<E>,
        decoys: Vec<Ciphertext<E>>,
    ) -> Self {
        MultiCiphertexts {
            sender,
            recipient,
            decoys: Some(decoys),
            fee: None,
            _marker: PhantomData,
        }
    }

    pub fn get_decoys_left(&self) -> Vec<edwards::Point<E, PrimeOrder>> {
        self.decoys.as_ref().expect("should have decoys enckeys").iter()
            .map(|c| c.left.clone()).collect::<Vec<edwards::Point<E, PrimeOrder>>>()
    }
}

impl<E: JubjubEngine> CiphertextTrait<E> for MultiCiphertexts<E, Anonymous> {
    type PC = Anonymous;

    fn encrypt(
        amount: u32,
        _fee: u32,
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

        let mut acc_d = vec![];
        for d in enc_keys.get_decoys() {
            let cipher_decoys = Ciphertext::encrypt(
                0,
                randomness,
                &d,
                p_g,
                params
            );
            acc_d.push(cipher_decoys);
        }

        MultiCiphertexts::<E, Self::PC>::new(
            cipher_sender,
            cipher_recipient,
            acc_d,
        )
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

    pub fn get_decoys(&self) -> &[EncryptionKey<E>] {
        &self.decoys.as_ref().expect("should have decoys enckeys")[..]
    }
}

pub enum Calls {
    BalanceTransfer,
    AssetIssue,
    AssetTransfer(u32),
    AssetBurn(u32),
    AnonymousTransfer,
}

pub trait Submitter {
    fn submit<R: Rng>(&self, calls: Calls, api: &Api, rng: &mut R);
}

pub trait ProofBuilder<E: JubjubEngine, PC: PrivacyConfing>: Sized {
    type Submitter: Submitter;

    fn setup<R: Rng>(rng: &mut R) -> Self;

    fn write_to_file<P: AsRef<Path>>(&self, pk_path: P, vk_path: P) -> io::Result<()>;

    fn read_from_path<P: AsRef<Path>>(pk_path: P, vk_path: P) -> io::Result<Self>;

    fn gen_proof<R: Rng>(
        &self,
        amount: u32,
        fee: u32,
        remaining_balance: u32,
        spending_key: &SpendingKey<E>,
        enc_keys: MultiEncKeys<E, PC>,
        enc_balances: &[Ciphertext<E>],
        g_epoch: edwards::Point<E, PrimeOrder>,
        rng: &mut R,
        params: &E::Params,
    ) -> Result<Self::Submitter, SynthesisError>;
}

pub struct KeyContext<E: JubjubEngine, PC: PrivacyConfing> {
    pub proving_key: Parameters<E>,
    pub prepared_vk: PreparedVerifyingKey<E>,
    _marker: PhantomData<PC>,
}

impl<E: JubjubEngine, PC: PrivacyConfing> KeyContext<E, PC> {
    pub fn new(proving_key: Parameters<E>, prepared_vk: PreparedVerifyingKey<E>) -> Self {
        KeyContext {
            proving_key,
            prepared_vk,
            _marker: PhantomData,
        }
    }

    pub fn pk(&self) -> &Parameters<E> {
        &self.proving_key
    }

    pub fn vk(&self) -> &PreparedVerifyingKey<E> {
        &self.prepared_vk
    }

    pub(crate) fn inner_read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
        let file = File::open(&path)?;

        let mut reader = BufReader::new(file);
        let mut buffer = vec![];
        reader.read_to_end(&mut buffer)?;

        Ok(buffer)
    }
}

pub(crate) struct Unchecked;
pub(crate) struct Checked;
pub(crate) trait ProofChecking { }

impl ProofChecking for Unchecked { }
impl ProofChecking for Checked { }

#[derive(Clone)]
pub(crate) struct ProofContext<E: JubjubEngine, IsChecked, PC: PrivacyConfing> {
    pub(crate) proof: Proof<E>,
    pub(crate) rvk: PublicKey<E>, // re-randomization sig-verifying key
    pub(crate) enc_key_sender: EncryptionKey<E>,
    pub(crate) enc_keys: MultiEncKeys<E, PC>,
    pub(crate) multi_ciphertexts: MultiCiphertexts<E, PC>,
    pub(crate) enc_balances: Vec<Ciphertext<E>>,
    pub(crate) g_epoch: edwards::Point<E, PrimeOrder>,
    pub(crate) nonce: edwards::Point<E, PrimeOrder>,
    pub(crate) _marker: PhantomData<IsChecked>,
}

impl<E: JubjubEngine, IsChecked, PC: PrivacyConfing> ProofContext<E, IsChecked, PC> {
    pub(crate) fn left_amount_sender(&self) -> &edwards::Point<E, PrimeOrder> {
        &self.multi_ciphertexts.get_sender().left
    }

    pub(crate) fn left_amount_recipient(&self) -> &edwards::Point<E, PrimeOrder> {
        &self.multi_ciphertexts.get_recipient().left
    }

    pub(crate) fn recipient(&self) -> &EncryptionKey<E> {
        self.enc_keys.get_recipient()
    }

    pub(crate) fn right_randomness(&self) -> &edwards::Point<E, PrimeOrder> {
        let sender_right = &self.multi_ciphertexts.get_sender().right;
        let recipient_right = &self.multi_ciphertexts.get_recipient().right;

        assert!(sender_right == recipient_right);

        &sender_right
    }
}

pub(crate) fn convert_to_checked<E: JubjubEngine, C1, C2, PC: PrivacyConfing>(
    from: ProofContext<E, C1, PC>,
) -> ProofContext<E, C2, PC> {
    ProofContext {
        proof: from.proof,
        rvk: from.rvk,
        enc_key_sender: from.enc_key_sender,
        enc_keys: from.enc_keys,
        multi_ciphertexts: from.multi_ciphertexts,
        enc_balances: from.enc_balances,
        g_epoch: from.g_epoch,
        nonce: from.nonce,
        _marker: PhantomData,
    }
}
