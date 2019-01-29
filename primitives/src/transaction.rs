


pub struct Transaction {
    Length of the rest of the extrinsic, // 1-5 bytes
 	Version information, // 1 byte
 	nonce,
 	sig, // 64 bytes
 	sig_verifying_key, // 32bytes
 	proof, // 192 bytes
 	balance_commitment: ValueCommiement<Bls12>, // 32 bytes
 	transfer_commitment(input), // 32bytes
 	epk(input), // 32 bytes
 	payment_address_s, // 11 + 32 bytes
 	payment_address_r, // 11 + 32 bytes
 	Enc(r'', -v'') // 32 bytes?
}


impl Transaction {
	pub 
}