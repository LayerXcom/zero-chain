use bellman::groth16::{Parameters, Proof, PreparedVerifyingKey};
use bellman_verifier::Proof as zProof;

use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    Field, PrimeField, PrimeFieldRepr,
};
use zpairing::{
		bls12_381::{Bls12 as zBls12, 
					Fr as zFr, 
					FrRepr as zFrRepr,
		},
    	Field as zField, 
		PrimeField as zPrimeField, 
		PrimeFieldRepr as zPrimeFieldRepr,	
		io,	
};

use scrypto::{    
    jubjub::{FixedGenerators, PrimeOrder, JubjubBls12, fs, ToUniform},    
    redjubjub::{PrivateKey, PublicKey, Signature},
};
use zjubjub::{
	curve::{JubjubBls12 as zJubjubBls12, fs as zfs},
	redjubjub::{PrivateKey as zPrivateKey, PublicKey as zPublicKey, Signature as zSignature},
};

use proofs::{
    self,
	primitives::{
		self,
		PaymentAddress, 
		ProofGenerationKey, 
		ExpandedSpendingKey,		
		},
	prover::TransferProof,
	elgamal::Ciphertext,   
};

use blake2_rfc::blake2b::Blake2b;
use zcrypto::{constants, elgamal::Ciphertext as zCiphertext};
use rand::{OsRng, Rand, Rng};

use zprimitives::{
		ciphertext::Ciphertext as pCiphertext,
		pkd_address::PkdAddress,
		proof::Proof as pProof,
		sig_vk::{SigVerificationKey as pSigVerificationKey},
		signature::RedjubjubSignature as pRedjubjubSignature,
		keys::PaymentAddress as zPaymentAddress,
	};
use parity_codec::{Encode, Decode, Input, Output};
use byteorder::{BigEndian, ByteOrder};

#[derive(Eq, PartialEq, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct Transaction{
    pub sig: pRedjubjubSignature,          // 64 bytes    
    pub rk: pSigVerificationKey,           // 32 bytes
    pub proof: pProof,                     // 192 bytes
    pub address_sender: PkdAddress,        // 43 bytes
    pub address_recipient: PkdAddress,     // 43 bytes
    pub enc_val_recipient: pCiphertext,    // 64 bytes
	pub enc_val_sender: pCiphertext,       // 64 bytes
	pub enc_bal_sender: pCiphertext,       // 64 bytes	
}

impl Transaction {
    pub fn gen_tx(
        value: u32,
        remaining_balance: u32,
        alpha: fs::Fs,
        proving_key: &Parameters<Bls12>,
		prepared_vk: &PreparedVerifyingKey<Bls12>,		
		address_recipient: &PaymentAddress<Bls12>,		
		sk: &[u8],
        ciphertext_balance: proofs::elgamal::Ciphertext<Bls12>,
		nonce: u64
    ) -> Result<Self, io::Error>
	{
		let rng = &mut OsRng::new().expect("OsRng::new() error.");

		// The pramaters from std environment
		let params = JubjubBls12::new();
		// The pramaters from no_std environment
		let zparams = zJubjubBls12::new();

		let expsk = ExpandedSpendingKey::<Bls12>::from_spending_key(sk);
		let proof_generation_key = expsk.into_proof_generation_key(&params);

		// Generate the zk proof
		let proof_output = TransferProof::gen_proof(
			value,
			remaining_balance,        
			alpha,			
			proving_key, 
			prepared_vk,
			proof_generation_key,
			address_recipient.clone(),			
            ciphertext_balance.clone(),
			&params,
		);
		
		let sk = fs::Fs::to_uniform(primitives::prf_extend_wo_t(sk).as_bytes());

		// Generate the re-randomized sign key
		let rsk: PrivateKey<Bls12> = PrivateKey(sk).randomize(alpha);		
				
		
		let mut rk_bytes = [0u8; 32];
		proof_output.rk.write(&mut rk_bytes[..]).map_err(|_| io::Error::InvalidData)?;
		// Read Publickey as a no_std type
		let zrk = zPublicKey::read(&mut &rk_bytes[..], &zparams)?;
		let rk = pSigVerificationKey::from_verification_key(&zrk);

		let mut proof_bytes = [0u8; 192];
		proof_output.proof.write(&mut proof_bytes[..]).map_err(|_| io::Error::InvalidData)?;
		// Read Proof as a no_std type
		let zproof = zProof::read(&proof_bytes[..])?;	
		let mut proof = pProof::from_proof(&zproof);

		let mut z_addr_sb = [0u8; 32];
		proof_output.address_sender.write(&mut z_addr_sb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the sender address as a no_std type
		let zaddress_sender = zPaymentAddress::read(&mut &z_addr_sb[..], &zparams)?;
		let address_sender = PkdAddress::from_payment_address(&zaddress_sender);

		let mut z_addr_rb = [0u8; 32];
		proof_output.address_recipient.write(&mut z_addr_rb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the recipient address as a no_std type
		let zaddress_recipient = zPaymentAddress::read(&mut &z_addr_rb[..], &zparams)?;
		let address_recipient = PkdAddress::from_payment_address(&zaddress_recipient);

		let mut env_val_rb = [0u8; 64];
		proof_output.cipher_val_r.write(&mut env_val_rb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the sending value encrypted by the recipient key as a no_std type
		let zenc_val_recipient = zCiphertext::read(&mut &env_val_rb[..], &zparams)?;
		let enc_val_recipient = pCiphertext::from_ciphertext(&zenc_val_recipient);

		let mut env_val_sb = [0u8; 64];
		proof_output.cipher_val_s.write(&mut env_val_sb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the sending value encrypted by the sender key as a no_std type
		let zenc_val_sender = zCiphertext::read(&mut &env_val_sb[..], &zparams)?;
		let enc_val_sender = pCiphertext::from_ciphertext(&zenc_val_sender);

		let mut env_bal_sb = [0u8; 64];
		ciphertext_balance.write(&mut env_bal_sb[..]).map_err(|_| io::Error::InvalidData)?;
		// Read the sender's balance encrypted by the sender key as a no_std type
		let zenc_bal_sender = zCiphertext::read(&mut &env_bal_sb[..], &zparams)?;
		let enc_bal_sender = pCiphertext::from_ciphertext(&zenc_bal_sender);				

	
		let mut msg = vec![];

		BigEndian::write_u64(&mut msg[..], nonce);
		// The index of confidential transfer module is fixed at 0x00
		msg.push(0);
		msg.push(0);

		// The index of confidential_transfer function in the module is fixed at 0x00
		msg.push(0);
		msg.push(0);

		// The arugments
		msg.append(&mut proof.0);		
		msg.append(&mut address_sender.as_bytes().to_vec());
		msg.append(&mut address_recipient.as_bytes().to_vec());		
		msg.append(&mut enc_val_sender.as_bytes().to_vec());
		msg.append(&mut enc_val_recipient.as_bytes().to_vec());
		msg.append(&mut enc_bal_sender.as_bytes().to_vec());
		msg.append(&mut rk.as_bytes().to_vec());  // TODO: Temporally added to use rk explicitly.


		// let mut h = Blake2b::with_params(32, &[], &[], constants::SIGHASH_PERSONALIZATION);		
		// h.update(&msg);
		// let sighash_value = h.finalize().as_ref().to_vec();
				
		let p_g = FixedGenerators::SpendingKeyGenerator;
		let sig = rsk.sign(&msg, rng, p_g, &params);	

		let mut sig_bytes = [0u8; 64];
		sig.write(&mut sig_bytes[..]).map_err(|_| io::Error::InvalidData)?;		
		// Read Signature as a no_std type		
		let zsig = zSignature::read(&sig_bytes[..])?;	
		let sig = pRedjubjubSignature::from_signature(&zsig);

		let tx = Transaction {		
			proof,		           			 
			rk,  			      
			address_sender,        
			address_recipient,
			enc_val_recipient,
			enc_val_sender,
			enc_bal_sender,
			sig, 							
		};

		Ok(tx)
	}
}

