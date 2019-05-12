use pairing::{CurveAffine, Engine};

pub trait PolyEngine {
    type Commitment: Commitment<Point = Engine::G1Affine>;
    type Opening: Opening;
}

pub trait Commitment {
    type Point: CurveAffine;

    fn from_point(point: &Self::Point) -> Self;

    fn into_bytes(&self) -> &[u8];
}

pub trait Opening {}
