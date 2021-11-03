use jubjub::curve::{edwards::Point, FixedGenerators, JubjubEngine, JubjubParams, Unknown};
use jubjub::redjubjub::{h_star, read_scalar, Signature};

#[derive(Clone)]
pub struct MRPubkey<E: JubjubEngine>(Point<E, Unknown>);

impl<E: JubjubEngine> MRPubkey<E> {
    pub fn new(p: Point<E, Unknown>) -> Self {
        MRPubkey(p)
    }

    pub fn verify(
        &self,
        msg: &[u8],
        sig: &Signature,
        p_g: FixedGenerators,
        params: &E::Params,
    ) -> bool {
        let mut buf = [0u8; 64];
        self.0
            .write(&mut &mut buf[..])
            .expect("Should write to buf.");
        buf[32..].copy_from_slice(&sig.rbar[..]);

        // c = H*(Xbar || Rbar || M)
        let c = h_star::<E>(&buf[..], msg);

        // Signature checks:
        // R != invalid
        let r = match Point::read(&mut &sig.rbar[..], params) {
            Ok(r) => r,
            Err(_) => return false,
        };
        // S < order(G)
        // (E::Fs guarantees its representation is in the field)
        let s = match read_scalar::<E, &[u8]>(&sig.sbar[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // 0 = h_G(-S . P_G + R + c . vk)
        self.0
            .mul(c, params)
            .add(&r, params)
            .add(
                &params.generator(p_g).mul(s, params).negate().into(),
                params,
            )
            .mul_by_cofactor(params)
            .eq(&Point::zero())
    }
}
