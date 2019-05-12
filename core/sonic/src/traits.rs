use pairing::{CurveAffine, Engine};
use std::fmt;

pub trait PolyEngine {
    type Commitment: Commitment<Point = <Self::Pairing as Engine>::G1Affine>;
    type Opening: Opening;
    type Pairing: Engine; // TODO: Make default generics of this trait
}

pub trait Commitment:
    Clone + Copy + Sized + Send + Sync + 'static
{
    type Point: CurveAffine;

    fn from_point(point: &Self::Point) -> Self;

    fn into_point(&self) -> Self::Point;

    fn into_bytes(&self) -> Vec<u8>;
}

pub trait Opening {}
