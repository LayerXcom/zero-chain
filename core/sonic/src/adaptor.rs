//! This module contains an adaptor which translates circuits written in the form of
//! quadratic "rank-1 constraint systems"(R1CS) into the system of constraints natural to
//! sonic's proving system.
//! R1CS is a constraint system which is widely deployed NP language currently undergoing
//! standardisation.

use std::marker::PhantomData;
use pairing::{Engine, CurveProjective};

// pub struct Adaptor<'a, E: Engine, CS: SonicConstraintSystem<E> + 'a> {

// }