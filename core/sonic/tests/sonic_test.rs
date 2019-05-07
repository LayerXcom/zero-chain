
use pairing::{Engine, Field, PrimeField, CurveAffine, CurveProjective};
use pairing::bls12_381::{Bls12, Fr};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
// use sonic::cs::{Circuit, ConstraintSystem};
use rand::{thread_rng, Rng};
// For benchmarking
use std::time::{Duration, Instant};
use sonic::srs::SRS;

pub const MIMC_ROUNDS: usize = 322;

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
pub fn mimc<E: Engine>(
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
pub struct MiMCDemo<'a, E: Engine> {
    xl: Option<E::Fr>,
    xr: Option<E::Fr>,
    constants: &'a [E::Fr]
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for MiMCDemo<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.
        let mut xl_value = self.xl;
        let mut xl = cs.alloc(|| "preimage xl", || {
            xl_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the second component of the preimage.
        let mut xr_value = self.xr;
        let mut xr = cs.alloc(|| "preimage xr", || {
            xr_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL
            let cs = &mut cs.namespace(|| format!("round {}", i));

            // tmp = (xL + Ci)^2
            let mut tmp_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square();
                e
            });
            let mut tmp = cs.alloc(|| "tmp", || {
                tmp_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce(
                || "tmp = (xL + Ci)^2",
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + tmp
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

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
#[derive(Clone)]
struct MiMCDemoNoInputs<'a, E: Engine> {
    xl: Option<E::Fr>,
    xr: Option<E::Fr>,
    image: Option<E::Fr>,
    constants: &'a [E::Fr]
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for MiMCDemoNoInputs<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.
        let mut xl_value = self.xl;
        let mut xl = cs.alloc(|| "preimage xl", || {
            xl_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the second component of the preimage.
        let mut xr_value = self.xr;
        let mut xr = cs.alloc(|| "preimage xr", || {
            xr_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL
            let cs = &mut cs.namespace(|| format!("round {}", i));

            // tmp = (xL + Ci)^2
            let tmp_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square();
                e
            });
            let tmp = cs.alloc(|| "tmp", || {
                tmp_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce(
                || "tmp = (xL + Ci)^2",
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + tmp
            );

            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let new_xl_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            });

            let new_xl = if i == (MIMC_ROUNDS-1) {
                // This is the last round, xL is our image and so
                // we use the image
                let image_value = self.image;
                cs.alloc(|| "image", || {
                    image_value.ok_or(SynthesisError::AssignmentMissing)
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

#[test]
fn bench_sonic_mimc() {
    let srs_x = Fr::from_str("23923").unwrap();
    let srs_alpha = Fr::from_str("23728792").unwrap();

    // let start = Instant::now();
    let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);
    // println!("Done in {:?}", start.elapsed());

    {
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut thread_rng();

        // Generate the MiMC round constants
        let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();
        let samples: usize = 100;

        let xl = rng.gen();
        let xr = rng.gen();
        let image = mimc::<Bls12>(xl, xr, &constants);

        // Create an instance of our circuit (with the
        // witness)
        let circuit = MiMCDemoNoInputs {
            xl: Some(xl),
            xr: Some(xr),
            image: Some(image),
            constants: &constants
        };

        use sonic::cs::Basic;
        use sonic::helped::adaptor::AdaptorCircuit;
        use sonic::helped::{Proof, MultiVerifier};
        // use sonic::helped::helper::{create_aggregate_on_srs};

        // println!("Creating proof");
        let start = Instant::now();
        let proof = Proof::<Bls12>::create_proof::< _, Basic>(&AdaptorCircuit(circuit.clone()), &srs).unwrap();
        println!("(Proving SONIC) Done in {:?}", start.elapsed());

        // println!("creating advice");
        // let start = Instant::now();
        // let advice = create_advice_on_srs::<Bls12, _, Basic>(&AdaptorCircuit(circuit.clone()), &proof, &srs).unwrap();
        // println!("done in {:?}", start.elapsed());

        // println!("creating aggregate for {} proofs", samples);
        // let start = Instant::now();
        // let proofs: Vec<_> = (0..samples).map(|_| (proof.clone(), advice.clone())).collect();
        // let aggregate = create_aggregate_on_srs::<Bls12, _, Basic>(&AdaptorCircuit(circuit.clone()), &proofs, &srs);
        // println!("done in {:?}", start.elapsed());

        {
            let rng = thread_rng();
            let mut verifier = MultiVerifier::<Bls12, _, Basic, _>::new(AdaptorCircuit(circuit.clone()), &srs, rng).unwrap();
            // println!("Verifying 1 proof without advice");
            let start = Instant::now();
            {
                for _ in 0..1 {
                    verifier.add_proof(&proof, &[], |_, _| None);
                }
                assert_eq!(verifier.check_all(), true);
            }
            println!("(Verifying SONIC) Done in {:?}", start.elapsed());
        }

        // {
        //     let rng = thread_rng();
        //     let mut verifier = MultiVerifier::<Bls12, _, Basic, _>::new(AdaptorCircuit(circuit.clone()), &srs, rng).unwrap();
        //     println!("verifying {} proofs without advice", samples);
        //     let start = Instant::now();
        //     {
        //         for _ in 0..samples {
        //             verifier.add_proof(&proof, &[], |_, _| None);
        //         }
        //         assert_eq!(verifier.check_all(), true);
        //     }
        //     println!("done in {:?}", start.elapsed());
        // }

        // {
        //     let rng = thread_rng();
        //     let mut verifier = MultiVerifier::<Bls12, _, Basic, _>::new(AdaptorCircuit(circuit.clone()), &srs, rng).unwrap();
        //     println!("verifying 100 proofs with advice");
        //     let start = Instant::now();
        //     {
        //         for (ref proof, ref advice) in &proofs {
        //             verifier.add_proof_with_advice(proof, &[], advice);
        //         }
        //         verifier.add_aggregate(&proofs, &aggregate);
        //         assert_eq!(verifier.check_all(), true);
        //     }
        //     println!("done in {:?}", start.elapsed());
        // }
    }
}

#[test]
fn bench_groth16_mimc() {
    use bellman::groth16::{generate_random_parameters, Proof, prepare_verifying_key, create_random_proof, verify_proof};

    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut thread_rng();

    // Generate the MiMC round constants
    let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

    // println!("Creating parameters...");

    let params = {
        let c = MiMCDemo::<Bls12> {
            xl: None,
            xr: None,
            constants: &constants
        };

        generate_random_parameters(c, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    let xl = rng.gen();
    let xr = rng.gen();
    let image = mimc::<Bls12>(xl, xr, &constants);

    let c = MiMCDemo {
        xl: Some(xl),
        xr: Some(xr),
        constants: &constants
    };

    // println!("Creating proofs...");
    let start = Instant::now();
    let proof = create_random_proof(c, &params, rng).unwrap();
    println!("(Proving Groth16) Done in {:?}", start.elapsed());

    // println!("Verifying proof");
    let start = Instant::now();
    // Check the proof
    verify_proof(
        &pvk,
        &proof,
        &[image]
    ).unwrap();
    println!("(Verifying Groth16) Done in {:?}", start.elapsed());
}
