use pairing::{CurveAffine, Engine};
use std::fmt;

pub trait PolyEngine {
    type Commitment: Commitment<Point = <Self::Pairing as Engine>::G1Affine>;
    type Opening: Opening;
    type Pairing: Engine;
}

pub trait Commitment:
    Copy + Clone + Sized + Send + Sync + fmt::Debug + fmt::Display + PartialEq + Eq + 'static
{
    type Point: CurveAffine;

    fn from_point(point: &Self::Point) -> Self;

    fn into_point(&self) -> Self::Point;

    fn into_bytes(&self) -> &[u8];
}

pub trait Opening {}
