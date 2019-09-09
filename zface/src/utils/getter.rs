// All this code will be refactored once polkadot{.rs} is updated.

use keys::EncryptionKey as zEncryptionKey;
use rand::Rng;
use pairing::bls12_381::Bls12;
use zprimitives::{EncKey, GEpoch};
use zcrypto::elgamal as zelgamal;
use polkadot_rs::{Api, hexstr_to_vec, hexstr_to_u64};
use parity_codec::Encode;
use proofs::{PARAMS, elgamal};
use zprimitives::PARAMS as ZPARAMS;
use zjubjub::curve::FixedGenerators as zFixedGenerators;
use proofs::{EncryptionKey, DecryptionKey, constants::DECOY_SIZE};
use zpairing::bls12_381::Bls12 as zBls12;
use scrypto::jubjub::{edwards, PrimeOrder};
use crate::error::Result;
use std::convert::TryFrom;

pub fn get_enc_balances(api: &Api, enc_keys: &[EncryptionKey<Bls12>]) -> Result<Vec<elgamal::Ciphertext<Bls12>>> {
    let mut acc = vec![];
    for e in enc_keys {
        let mut encrypted_balance_str = api.get_storage(
            "AnonymousBalances",
            "EncryptedBalance",
            Some(EncKey::try_from(no_std_e(e)?)?.encode())
        )?;

        let mut pending_transfer_str = api.get_storage(
            "AnonymousBalances",
            "PendingTransfer",
            Some(EncKey::try_from(no_std_e(e)?)?.encode())
        )?;

        let mut ciphertext = None;
        let mut p_ciphertext = None;

        if encrypted_balance_str.as_str() != "0x00" {
            // TODO: remove unnecessary prefix. If it returns `0x00`, it will be panic.
            for _ in 0..4 {
                encrypted_balance_str.remove(2);
            }

            let encrypted_balance = hexstr_to_vec(encrypted_balance_str.clone());
            ciphertext = Some(zelgamal::Ciphertext::<zBls12>::read(&mut &encrypted_balance[..], &ZPARAMS)?);
        }

        if pending_transfer_str.as_str() != "0x00" {
            // TODO: remove unnecessary prefix. If it returns `0x00`, it will be panic.
            for _ in 0..4 {
                pending_transfer_str.remove(2);
            }

            let pending_transfer = hexstr_to_vec(pending_transfer_str.clone());
            p_ciphertext = Some(zelgamal::Ciphertext::<zBls12>::read(&mut &pending_transfer[..], &ZPARAMS)?);
        }

        let zero = zelgamal::Ciphertext::<zBls12>::zero();
        let enc_total = ciphertext.unwrap_or(zero.clone()).add(&p_ciphertext.unwrap_or(zero), &*ZPARAMS);
        let mut buf = vec![0u8; 64];
        enc_total.write(&mut buf[..])?;
        let tmp = elgamal::Ciphertext::<Bls12>::read(&mut &buf[..], &*PARAMS)?;
        acc.push(tmp);
    }

    Ok(acc)
}

pub struct BalanceQuery {
    pub decrypted_balance: u32,
    pub encrypted_balance: Vec<u8>, // total of encrypted balance and pending transfer
    pub encrypted_balance_str: String,
    pub pending_transfer_str: String,
}

// Temporary code.
impl BalanceQuery {
    /// Get encrypted and decrypted balance for the decryption key
    pub fn get_encrypted_balance(dec_key: &DecryptionKey<Bls12>, api: Api) -> Result<Self> {
        let encryption_key = zEncryptionKey::from_decryption_key(&no_std(&dec_key)?, &*ZPARAMS);
        let account_id = EncKey::try_from(encryption_key)?;

        let encrypted_balance_str = api.get_storage(
            "EncryptedBalances",
            "EncryptedBalance",
            Some(account_id.encode())
        )?;

        let pending_transfer_str = api.get_storage(
            "EncryptedBalances",
            "PendingTransfer",
            Some(account_id.encode())
        )?;

        Self::get_balance_from_decryption_key(encrypted_balance_str, pending_transfer_str, dec_key)
    }

    pub fn get_encrypted_asset(asset_id: u32, dec_key: &DecryptionKey<Bls12>, api: Api) -> Result<Self> {
        let encryption_key = zEncryptionKey::from_decryption_key(&no_std(&dec_key)?, &*ZPARAMS);
        let account_id = EncKey::try_from(encryption_key)?;

        let encrypted_asset_str = api.get_storage(
            "EncryptedAssets",
            "EncryptedBalance",
            Some((asset_id, account_id).encode())
        )?;

        let pending_transfer_str = api.get_storage(
            "EncryptedAssets",
            "PendingTransfer",
            Some((asset_id, account_id).encode())
        )?;

        Self::get_balance_from_decryption_key(encrypted_asset_str, pending_transfer_str, dec_key)
    }

    pub fn get_anonymous_balance(dec_key: &DecryptionKey<Bls12>, api: Api) -> Result<Self> {
        let encryption_key = zEncryptionKey::from_decryption_key(&no_std(&dec_key)?, &*ZPARAMS);
        let account_id = EncKey::try_from(encryption_key)?;

        let encrypted_balance_str = api.get_storage(
            "AnonymousBalances",
            "EncryptedBalance",
            Some(account_id.encode())
        )?;

        let pending_transfer_str = api.get_storage(
            "AnonymousBalances",
            "PendingTransfer",
            Some(account_id.encode())
        )?;

        Self::get_balance_from_decryption_key(encrypted_balance_str, pending_transfer_str, dec_key)
    }

    fn get_balance_from_decryption_key(
        mut encrypted_balance_str: String,
        mut pending_transfer_str: String,
        dec_key: &DecryptionKey<Bls12>
    ) -> Result<Self> {
        let p_g = zFixedGenerators::Diversifier; // 1
        let decrypted_balance;
        let p_decrypted_balance;
        let mut ciphertext = None;
        let mut p_ciphertext = None;

        // TODO: redundant code
        if encrypted_balance_str.as_str() != "0x00" {
            // TODO: remove unnecessary prefix. If it returns `0x00`, it will be panic.
            for _ in 0..4 {
                encrypted_balance_str.remove(2);
            }

            let encrypted_balance = hexstr_to_vec(encrypted_balance_str.clone());
            ciphertext = Some(zelgamal::Ciphertext::<zBls12>::read(&mut &encrypted_balance[..], &ZPARAMS)?);
            decrypted_balance = ciphertext.clone().unwrap().decrypt(&no_std(&dec_key)?, p_g, &ZPARAMS).unwrap();
        } else {
            decrypted_balance = 0;
        }

        if pending_transfer_str.as_str() != "0x00" {
            // TODO: remove unnecessary prefix. If it returns `0x00`, it will be panic.
            for _ in 0..4 {
                pending_transfer_str.remove(2);
            }

            let pending_transfer = hexstr_to_vec(pending_transfer_str.clone());
            p_ciphertext = Some(zelgamal::Ciphertext::<zBls12>::read(&mut &pending_transfer[..], &ZPARAMS)?);
            p_decrypted_balance = p_ciphertext.clone().unwrap().decrypt(&no_std(&dec_key)?, p_g, &ZPARAMS).unwrap();
        } else {
            p_decrypted_balance = 0;
        }

        let zero = zelgamal::Ciphertext::<zBls12>::zero();
        let enc_total = ciphertext.unwrap_or(zero.clone()).add(&p_ciphertext.unwrap_or(zero), &*ZPARAMS);
        let mut buf = vec![0u8; 64];
        enc_total.write(&mut buf[..])?;

        Ok(BalanceQuery {
            decrypted_balance: decrypted_balance + p_decrypted_balance,
            encrypted_balance: buf,
            encrypted_balance_str,
            pending_transfer_str,
        })
    }
}

pub fn address(seed: &[u8]) -> Result<Vec<u8>> {
    let address = EncryptionKey::<Bls12>::from_seed(seed, &PARAMS)?;

    let mut address_bytes = vec![];
    address.write(&mut address_bytes)?;

    Ok(address_bytes)
}

pub fn g_epoch(api: &Api) -> Result<edwards::Point<Bls12, PrimeOrder>> {
    let current_height_str = api.get_latest_height()?;
    let epoch_length_str = api.get_storage("ZkSystem", "EpochLength", None)?;
    let current_epoch = hexstr_to_u64(current_height_str) / hexstr_to_u64(epoch_length_str);
    let g_epoch = GEpoch::group_hash(current_epoch as u32)?; // TODO

    let point = edwards::Point::<Bls12, _>::read(&mut g_epoch.as_ref(), &PARAMS)?
            .as_prime_order(&PARAMS)
            .unwrap();    

    Ok(point)
}

// Get set fee amount as `TransactionBaseFee` in encrypyed-balances module.
pub fn fee(api: &Api) -> Result<u32> {
    let fee_str = api.get_storage("EncryptedBalances", "TransactionBaseFee", None)?;
    Ok(hexstr_to_u64(fee_str) as u32)
}

fn no_std(dec_key: &DecryptionKey<Bls12>) -> Result<keys::DecryptionKey<zBls12>> {
    let mut dec_key_vec = vec![];
    dec_key.write(&mut dec_key_vec)?;
    let key = keys::DecryptionKey::read(&mut &dec_key_vec[..])?;

    Ok(key)
}

fn no_std_e(enc_key: &EncryptionKey<Bls12>) -> Result<keys::EncryptionKey<zBls12>> {
    let mut enc_key_vec = vec![];
    enc_key.write(&mut enc_key_vec)?;
    let key = keys::EncryptionKey::read(&mut &enc_key_vec[..], &*ZPARAMS)?;
    Ok(key)
}

pub fn get_enc_keys<R: Rng>(api: &Api, rng: &mut R) -> Result<Vec<EncryptionKey<Bls12>>> {
    let mut enc_keys_str = api.get_storage("AnonymousBalances", "EncKeySet", None)?;
    // TODO: remove unnecessary prefix. If it returns `0x00`, it will be panic.
    for _ in 0..4 {
        enc_keys_str.remove(2);
    }
    let mut enc_keys_vec = hexstr_to_vec(enc_keys_str);

    assert!(enc_keys_vec.len() % 32 == 0);
    let mut tmp_acc = vec![];
    while !enc_keys_vec.is_empty() {
        let tmp = enc_keys_vec.drain(..32).collect::<Vec<u8>>();
        tmp_acc.push(EncryptionKey::<Bls12>::read(&mut &tmp[..], &PARAMS)?)
    }
    let mut acc = vec![];
    for _ in 0..DECOY_SIZE {
        let random_i = rng.gen_range(0, tmp_acc.len());
        acc.push(tmp_acc[random_i].clone());
    }

    Ok(acc)
}
