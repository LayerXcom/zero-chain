use primitives::H256;
use runtime_primitives::traits::{Extrinsic as ExtrinsicT};

#[derive(Decode, Encode, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub enum UncheckedExtrinsic {
	// encrypted_sender_note(),
    // encrypted_receiver_note(),
    // old_note(H256),
    // sender_new_note(H256),
    // destination_new_note(H256),
    // zk_proof(),
    // ephemeral_verification_key(),
    // Sig(),

	// Attestation(AttestationRecord)
}
