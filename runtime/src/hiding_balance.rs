#![cfg_attr(not(feature = "std"), no_std)]



decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        
    }
}