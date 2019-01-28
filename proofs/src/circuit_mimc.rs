// For randomness (during paramgen and proof generation)
use rand::{thread_rng, Rng};

// For benchmarking
use std::time::{Duration, Instant};

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

use scrypto::constants;

use scrypto::primitives::{
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

const MIMC_ROUNDS: usize = 322;

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3` for BLS12-381.
/// See http://eprint.iacr.org/2016/492 for more 
/// information about this construction.
///
/// ```
/// function LongsightF322p3(xL ⦂ Fp, xR ⦂ Fp) {
///     for i from 0 up to 321 {
///         xL, xR := xR + (xL + Ci)^3, xL
///     }
///     return xL
/// }
/// ```
fn mimc<E: JubjubEngine>(
    mut xl: E::Fr,
    mut xr: E::Fr,
    constants: &[E::Fr]
) -> E::Fr
{
    assert_eq!(constants.len(), MIMC_ROUNDS);

    for i in 0..MIMC_ROUNDS {
        let mut tmp1 = xl;
        tmp1.add_assign(&constants[i]);
        let mut tmp2 = tmp1;
        tmp2.square();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
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
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the plaintext.
        let mut x_value = self.x;
        let mut x = cs.alloc(|| "plaintext x", || {
            x_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the second component of the preimage.
        let mut k_value = self.k;
        let mut k = cs.alloc(|| "key k", || {
            k_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for i in 0..MIMC_ROUNDS {
            // x, k := (x + k + Ci)^7
            let cs = &mut cs.namespace(|| format!("round {}", i));

            // tmp2 = (x + k + Ci)^2
            let mut tmp2_value = x_value.map(|mut e| {
                e.add_assign(k_value);
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
                e.mul_assign(tmp2_value);
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

            // tmp7 = (x + k + Ci)^7
            let mut tmp7_value = tmp6_value.map(|mut e| {
                e.mul_assign(x_value.add_assign(k_value).add_assign(&self.constants[i]));
                e
            })

            let mut tmp7 = cs.alloc(|| "tmp7", || {
                tmp7_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce(
                || "tmp7 = (x + k + Ci)^7",
                |lc| lc + tmp6,
                |lc| lc + x + k + (self.constants[i], CS::one()),
                |lc| lc + tmp7
            );


            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let mut new_xl_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            });

            let mut new_xl = if i == (MIMC_ROUNDS-1) {
                // This is the last round, xL is our image and so
                // we allocate a public input.
                cs.alloc_input(|| "image", || {
                    new_xl_value.ok_or(SynthesisError::AssignmentMissing)
                })?
            } else {
                cs.alloc(|| "new_xl", || {
                    new_xl_value.ok_or(SynthesisError::AssignmentMissing)
                })?
            };

            cs.enforce(
                || "new_xL = xR + (xL + Ci)^3",
                |lc| lc + tmp,
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + new_xl - xr
            );

            // xR = xL
            xr = xl;
            xr_value = xl_value;

            // xL = new_xL
            xl = new_xl;
            xl_value = new_xl_value;
        }



        Ok(())
    }
}

#[cfg(test)]
    use pairing::bls12_381::*;
    // use rand::{SeedableRng, Rng, XorShiftRng};    
    use super::circuit_test::TestConstraintSystem;
    use scrypto::jubjub::{JubjubBls12, fs, edwards};
    use scrypto::primitives::Diversifier;
    

    #[test]
    fn test_mimc() {
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut thread_rng();

        // Generate the MiMC round constants
        let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

        println!("Creating parameters...");

        // Create parameters for our circuit
        let params = {
            let c = MiMCDemo::<Bls12> {
                xl: None,
                xr: None,
                constants: &constants
            };

            generate_random_parameters(c, rng).unwrap()
        };

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params.vk);

        println!("Creating proofs...");

        // Let's benchmark stuff!
        const SAMPLES: u32 = 50;
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        // Just a place to put the proof data, so we can
        // benchmark deserialization.
        // let mut proof_vec = vec![];

        // for _ in 0..SAMPLES {
            // Generate a random preimage and compute the image
            let xl = rng.gen();
            let xr = rng.gen();
            let image = mimc::<Bls12>(xl, xr, &constants);

            // proof_vec.truncate(0);

            let c = MiMCDemo {
                xl: Some(xl),
                xr: Some(xr),
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
