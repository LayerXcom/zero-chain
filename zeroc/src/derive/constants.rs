pub const EKFP_PERSONALIZATION: &'static [u8; 16] = b"ZerochainEFinger";
pub const MASTER_PERSONALIZATION: &'static [u8; 16] = b"Zerochain_Master";
pub const CHAIN_CODE_LENGTH: usize = 32;
pub const FINGER_PRINT_LENGTH: usize = 32;
pub const TAG_LENGTH: usize = 4;
/// depth_length + tag_length +child_index_length + chain_code_length + spending_key_length = 73
pub const EXTENDED_SPENDING_KEY_LENGATH: usize = 1 + TAG_LENGTH + 4 + CHAIN_CODE_LENGTH + 32;
