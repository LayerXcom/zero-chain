use pairing::{CurveAffine, Engine};

pub trait PolyEngine {
    type Commitment: Commitment<Point = <Self::Pairing as Engine>::G1Affine>;
    type Opening: Opening;
    type Pairing: Engine;
}

pub trait Commitment {
    type Point: CurveAffine;

    fn from_point(point: &Self::Point) -> Self;

    fn into_bytes(&self) -> &[u8];
}

pub trait Opening {}
