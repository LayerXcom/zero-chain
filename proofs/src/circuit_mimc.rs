// For randomness (during paramgen and proof generation)
use rand::{thread_rng, Rng};

// Bring in some tools for using pairing-friendly curves
// use pairing::{
//     Engine,
//     Field
// };

// We're going to use the BLS12-381 pairing-friendly elliptic curve.
// use pairing::bls12_381::{
//     Bls12
// };

use pairing::{
    PrimeField,
    PrimeFieldRepr,
    Field,    
};

// We'll use these interfaces to construct our circuit.
use bellman::{
    Circuit,
    ConstraintSystem,
    SynthesisError
};

use scrypto::jubjub::{
    JubjubEngine,
    FixedGenerators
};

use primitives::{
    ValueCommitment,
    ProofGenerationKey,
    PaymentAddress
};

// We're going to use the Groth16 proving system.
use bellman::groth16::{
    Proof,
    generate_random_parameters,
    prepare_verifying_key,
    create_random_proof,
    verify_proof,
};

use zcrypto::constants::DEFAULT_MIMC_ROUND;

/// This is an implementation of MiMC.
/// See http://eprint.iacr.org/2016/492 for more 
/// information about this construction.
fn mimc<E: JubjubEngine>(
    mut x: E::Fr,
    k: E::Fr,
    constants: &[E::Fr]
) -> E::Fr
{
    assert_eq!(constants.len(), DEFAULT_MIMC_ROUND);

    for i in 0..DEFAULT_MIMC_ROUND {
        let mut tmp1 = x;
        tmp1.add_assign(&k);
        tmp1.add_assign(&constants[i]);    
        let mut tmp2 = tmp1;
        tmp1.square();
        tmp1.square();
        tmp1.square();
        
        tmp1.mul_assign(&tmp2);                        
        x = tmp1;
    }
    x.add_assign(&k);
    x
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
struct MiMC<'a, E: JubjubEngine> {
    x: Option<E::Fr>, // plaintext
    k: Option<E::Fr>, // key
    constants: &'a [E::Fr]
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: JubjubEngine> Circuit<E> for MiMC<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        assert_eq!(self.constants.len(), DEFAULT_MIMC_ROUND);

        // Allocate the first component of the plaintext.
        let mut x_value = self.x;
        let mut x = cs.alloc(|| "plaintext x", || {
            x_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the second component of the preimage.
        let k_value = self.k;
        let k = cs.alloc(|| "key k", || {
            k_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for i in 0..DEFAULT_MIMC_ROUND {
            // x, k := (x + k + Ci)^7
            let cs = &mut cs.namespace(|| format!("round {}", i));

            // tmp2 = (x + k + Ci)^2
            let mut tmp2_value = x_value.map(|mut e| {
                e.add_assign(&k_value.unwrap());
                e.add_assign(&self.constants[i]);
                e.square();
                e
            });
            let mut tmp2 = cs.alloc(|| "tmp2", || {
                tmp2_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce(
                || "tmp2 = (x + k + Ci)^2",
                |lc| lc + x + k + (self.constants[i], CS::one()),
                |lc| lc + x + k + (self.constants[i], CS::one()),
                |lc| lc + tmp2
            );

            // tmp4 = (x + k + Ci)^4
            let mut tmp4_value = tmp2_value.map(|mut e| {
                e.square();
                e
            }); 

            let mut tmp4 = cs.alloc(|| "tmp4", || {
                tmp4_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce(
                || "tmp4 = (x + k + Ci)^4",
                |lc| lc + tmp2,
                |lc| lc + tmp2,
                |lc| lc + tmp4
            );

            // tmp6 = (x + k + Ci)^6
            let mut tmp6_value = tmp4_value.map(|mut e| {
                e.mul_assign(&tmp2_value.unwrap());
                e
            });

            let mut tmp6 = cs.alloc(|| "tmp6", || {
                tmp6_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce(
                || "tmp6 = (x + k + Ci)^6",
                |lc| lc + tmp4,
                |lc| lc + tmp2,
                |lc| lc + tmp6
            );

            let mut tmp1_value = x_value.map(|mut e| {
                e.add_assign(&k_value.unwrap());
                e.add_assign(&self.constants[i]);
                e
            });

            let mut tmp1 = cs.alloc(|| "tmp1", || {
                tmp1_value.ok_or(SynthesisError::AssignmentMissing)
            })?;            

            // tmp7 = (x + k + Ci)^7
            let mut tmp7_value = tmp6_value.map(|mut e| {
                e.mul_assign(&tmp1_value.unwrap());
                e
            });

            let mut tmp7 = cs.alloc(|| "tmp7", || {
                tmp7_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce(
                || "tmp7 = (x + k + Ci)^7",
                |lc| lc + tmp6,
                |lc| lc + x + k + (self.constants[i], CS::one()),
                |lc| lc + tmp7
            );      

            if i == DEFAULT_MIMC_ROUND - 1 {
                let mut res_value = tmp7_value.map(|mut e| {
                    e.add_assign(&k_value.unwrap());
                    e
                });

                let mut res = cs.alloc_input(|| "res", || {
                    res_value.ok_or(SynthesisError::AssignmentMissing)
                })?;
                
                cs.enforce(
                    || "res = k + tmp7",
                    |lc| lc + tmp7,
                    |lc| lc + CS::one(),
                    |lc| lc + res - k
                );    
            } else {
                x = tmp7;
                x_value = tmp7_value;
            }            
        }           

        Ok(())
    }
}

#[cfg(test)]
    use pairing::bls12_381::*;
    // use rand::{SeedableRng, Rng, XorShiftRng};    
    use super::circuit_test::TestConstraintSystem;
    use scrypto::jubjub::{JubjubBls12, fs, edwards};    
    

    #[test]
    fn test_mimc() {
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut thread_rng();

        // Generate the MiMC round constants
        let constants = (0..DEFAULT_MIMC_ROUND).map(|_| rng.gen()).collect::<Vec<_>>();

        println!("Creating parameters...");

        // Create parameters for our circuit
        let params = {
            let c = MiMC::<Bls12> {
                x: None,
                k: None,
                constants: &constants
            };

            generate_random_parameters(c, rng).unwrap()
        };

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params.vk);

        println!("Creating proofs...");
       

        // Just a place to put the proof data, so we can
        // benchmark deserialization.
        // let mut proof_vec = vec![];
        
        // Generate a random preimage and compute the image
        let x = rng.gen();
        let k = rng.gen();
        let image = mimc::<Bls12>(x, k, &constants);        

        let c = MiMC {
            x: Some(x),
            k: Some(k),
            constants: &constants
        };

        let mut cs = TestConstraintSystem::<Bls12>::new();

        c.synthesize(&mut cs).unwrap();
        assert!(cs.is_satisfied());
        println!("{:?}", cs.num_constraints());


        //     let start = Instant::now();
        //     {
        //         // Create an instance of our circuit (with the
        //         // witness)
        //         let c = MiMCDemo {
        //             xl: Some(xl),
        //             xr: Some(xr),
        //             constants: &constants
        //         };

        //         // Create a groth16 proof with our parameters.
        //         let proof = create_random_proof(c, &params, rng).unwrap();

        //         proof.write(&mut proof_vec).unwrap();
        //     }

        //     total_proving += start.elapsed();

        //     let start = Instant::now();
        //     let proof = Proof::read(&proof_vec[..]).unwrap();
        //     // Check the proof
        //     assert!(verify_proof(
        //         &pvk,
        //         &proof,
        //         &[image]
        //     ).unwrap());
        //     total_verifying += start.elapsed();
        // }
        // let proving_avg = total_proving / SAMPLES;
        // let proving_avg = proving_avg.subsec_nanos() as f64 / 1_000_000_000f64
        //                   + (proving_avg.as_secs() as f64);

        // let verifying_avg = total_verifying / SAMPLES;
        // let verifying_avg = verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64
        //                   + (verifying_avg.as_secs() as f64);

        // println!("Average proving time: {:?} seconds", proving_avg);
        // println!("Average verifying time: {:?} seconds", verifying_avg);
    }
