#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
mod std {
    pub use ::core::*;
    pub use crate::alloc::vec;
    pub use crate::alloc::string;
    pub use crate::alloc::boxed;
    pub use crate::alloc::borrow;
}

#[cfg(feature = "std")]
#[macro_use]
extern crate serde_derive;

macro_rules! impl_fixed_hash_codec {
    ($name:ident, $size:expr) => {
        #[cfg(feature = "std")]
        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                ::substrate_primitives::bytes::serialize(&self.0, serializer)
            }
        }

        #[cfg(feature = "std")]
        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                ::substrate_primitives::bytes::deserialize_check_len(
                    deserializer,
                    ::substrate_primitives::bytes::ExpectedLen::Exact($size),
                )
                .map(|bytes| $name::from_slice(&bytes))
            }
        }

        impl ::parity_codec::Encode for $name {
            fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
                self.0.using_encoded(f)
            }
        }

        impl ::parity_codec::Decode for $name {
            fn decode<I: ::parity_codec::Input>(input: &mut I) -> Option<Self> {
                <[u8; $size] as ::parity_codec::Decode>::decode(input)
                    .map(|bytes| $name(bytes))
            }
        }

        #[cfg(feature = "std")]
        impl ::substrate_primitives::hexdisplay::AsBytesRef for $name {
            fn as_bytes_ref(&self) -> &[u8] {
                self.as_ref()
            }
        }

        impl ::core::convert::TryFrom<&[u8]> for $name {
            type Error = ::pairing::io::Error;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                if bytes.len() != $size {
                    return Err(::pairing::io::Error::InvalidData);
                }
                Ok($name::from_slice(bytes))
            }
        }
    };
}

macro_rules! impl_edwards_point_conversions {
    ($name:ident, $size:expr) => {
        impl ::core::convert::TryFrom<
            ::jubjub::curve::edwards::Point<
                ::pairing::bls12_381::Bls12,
                ::jubjub::curve::PrimeOrder
            >
        > for $name {
            type Error = ::pairing::io::Error;

            fn try_from(
                point: ::jubjub::curve::edwards::Point<
                    ::pairing::bls12_381::Bls12,
                    ::jubjub::curve::PrimeOrder
                >
            ) -> Result<Self, Self::Error> {
                let mut writer = [0u8; $size];
                point.write(&mut &mut writer[..])?;
                Ok($name::from_slice(&writer[..]))
            }
        }

        impl ::core::convert::TryFrom<$name> for ::jubjub::curve::edwards::Point<
            ::pairing::bls12_381::Bls12,
            ::jubjub::curve::PrimeOrder
        > {
            type Error = ::pairing::io::Error;

            fn try_from(value: $name) -> Result<Self, Self::Error> {
                let mut bytes = value.as_bytes();
                ::jubjub::curve::edwards::Point::<
                    ::pairing::bls12_381::Bls12,
                    ::jubjub::curve::Unknown
                >::read(&mut bytes, &crate::PARAMS)?
                    .as_prime_order(&crate::PARAMS)
                    .ok_or(::pairing::io::Error::NotInField)
            }
        }

        impl ::core::convert::TryFrom<&$name> for ::jubjub::curve::edwards::Point<
            ::pairing::bls12_381::Bls12,
            ::jubjub::curve::PrimeOrder
        > {
            type Error = ::pairing::io::Error;

            fn try_from(value: &$name) -> Result<Self, Self::Error> {
                let mut bytes = value.as_bytes();
                ::jubjub::curve::edwards::Point::<
                    ::pairing::bls12_381::Bls12,
                    ::jubjub::curve::Unknown
                >::read(&mut bytes, &crate::PARAMS)?
                    .as_prime_order(&crate::PARAMS)
                    .ok_or(::pairing::io::Error::NotInField)
            }
        }

        impl crate::IntoXY<::pairing::bls12_381::Bls12> for $name {
            fn into_xy(
                &self,
            ) -> Result<
                (::pairing::bls12_381::Fr, ::pairing::bls12_381::Fr),
                ::pairing::io::Error
            > {
                let point = <::jubjub::curve::edwards::Point<
                    ::pairing::bls12_381::Bls12,
                    ::jubjub::curve::PrimeOrder
                > as ::core::convert::TryFrom<&$name>>::try_from(self)?;
                Ok(point.into_xy())
            }
        }

        impl crate::IntoXY<::pairing::bls12_381::Bls12> for &$name {
            fn into_xy(
                &self,
            ) -> Result<
                (::pairing::bls12_381::Fr, ::pairing::bls12_381::Fr),
                ::pairing::io::Error
            > {
                (**self).into_xy()
            }
        }
    };
}

macro_rules! impl_ciphertext_component_conversion {
    ($name:ident, $field:ident, $size:expr) => {
        impl ::core::convert::TryFrom<
            ::zcrypto::elgamal::Ciphertext<::pairing::bls12_381::Bls12>
        > for $name {
            type Error = ::pairing::io::Error;

            fn try_from(
                ciphertext: ::zcrypto::elgamal::Ciphertext<::pairing::bls12_381::Bls12>
            ) -> Result<Self, Self::Error> {
                let mut writer = [0u8; $size];
                ciphertext.$field.write(&mut &mut writer[..])?;
                Ok($name::from_slice(&writer[..]))
            }
        }
    };
}

pub mod enc_key;
pub mod signature;
pub mod ciphertext;
pub mod proof;
pub mod sig_vk;
pub mod nonce;
pub mod g_epoch;
pub mod right_ciphertext;
pub mod left_ciphertext;

pub use self::enc_key::EncKey;
pub use self::signature::RedjubjubSignature;
pub use self::ciphertext::Ciphertext;
pub use self::proof::Proof;
pub use self::sig_vk::{SigVerificationKey, SigVk};
pub use self::nonce::Nonce;
pub use self::g_epoch::GEpoch;
pub use self::right_ciphertext::RightCiphertext;
pub use self::left_ciphertext::LeftCiphertext;

use lazy_static::lazy_static;
use jubjub::curve::{JubjubBls12, JubjubEngine};
use pairing::io;

lazy_static! {
    pub static ref PARAMS: JubjubBls12 = JubjubBls12::new();
}

pub trait IntoXY<E: JubjubEngine> {
    fn into_xy(&self) -> Result<(E::Fr, E::Fr), io::Error>;
}

// just for test utility
impl<E: JubjubEngine> IntoXY<E> for u64 {
    fn into_xy(&self) -> Result<(E::Fr, E::Fr), io::Error> {
        unimplemented!();
    }
}
