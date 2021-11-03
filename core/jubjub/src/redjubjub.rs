//! Implementation of RedJubjub, a specialization of RedDSA to the Jubjub curve.
//! See section 5.4.6 of the Sapling protocol specification.

use pairing::{io, Field, PrimeField, PrimeFieldRepr};
use rand::{Rand, Rng};

use crate::curve::{edwards::Point, FixedGenerators, JubjubEngine, JubjubParams, Unknown};
use crate::util::hash_to_scalar;

pub fn read_scalar<E: JubjubEngine, R: io::Read>(mut reader: R) -> io::Result<E::Fs> {
    let mut s_repr = <E::Fs as PrimeField>::Repr::default();
    s_repr.read_le(&mut reader)?;

    match E::Fs::from_repr(s_repr) {
        Ok(s) => Ok(s),
        Err(_) => Err(io::Error::NotInField),
    }
}

pub fn write_scalar<E: JubjubEngine, W: io::Write>(s: &E::Fs, mut writer: W) -> io::Result<()> {
    s.into_repr().write_le(&mut writer)
}

pub fn h_star<E: JubjubEngine>(a: &[u8], b: &[u8]) -> E::Fs {
    hash_to_scalar::<E>(b"Zcash_RedJubjubH", a, b)
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Copy, Clone, PartialEq)]
pub struct Signature {
    pub rbar: [u8; 32],
    pub sbar: [u8; 32],
}

#[cfg_attr(feature = "std", derive(Debug))]
pub struct PrivateKey<E: JubjubEngine>(pub E::Fs);

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, PartialEq)]
pub struct PublicKey<E: JubjubEngine>(pub Point<E, Unknown>);

impl Signature {
    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut rbar = [0u8; 32];
        let mut sbar = [0u8; 32];
        reader.read(&mut rbar)?;
        reader.read(&mut sbar)?;
        Ok(Signature { rbar, sbar })
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write(&self.rbar)?;
        writer.write(&self.sbar)
    }
}

impl<E: JubjubEngine> PrivateKey<E> {
    pub fn randomize(&self, alpha: E::Fs) -> Self {
        let mut tmp = self.0;
        tmp.add_assign(&alpha);
        PrivateKey(tmp)
    }

    pub fn read<R: io::Read>(reader: R) -> io::Result<Self> {
        let pk = read_scalar::<E, R>(reader)?;
        Ok(PrivateKey(pk))
    }

    pub fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
        write_scalar::<E, W>(&self.0, writer)
    }

    pub fn sign<R: Rng>(
        &self,
        msg: &[u8],
        rng: &mut R,
        p_g: FixedGenerators,
        params: &E::Params,
    ) -> Signature {
        // T = (l_H + 128) bits of randomness
        // For H*, l_H = 512 bits
        let mut t = [0u8; 80];
        rng.fill_bytes(&mut t[..]);

        // r = H*(T || M)
        let r = h_star::<E>(&t[..], msg);

        // R = r . P_G
        let r_g = params.generator(p_g).mul(r, params);
        let mut rbar = [0u8; 32];
        r_g.write(&mut &mut rbar[..])
            .expect("Jubjub points should serialize to 32 bytes");

        // S = r + H*(Rbar || M) . sk
        let mut s = h_star::<E>(&rbar[..], msg);
        s.mul_assign(&self.0);
        s.add_assign(&r);
        let mut sbar = [0u8; 32];
        write_scalar::<E, &mut [u8]>(&s, &mut sbar[..])
            .expect("Jubjub scalars should serialize to 32 bytes");

        Signature { rbar, sbar }
    }
}

impl<E: JubjubEngine> PublicKey<E> {
    pub fn from_private(privkey: &PrivateKey<E>, p_g: FixedGenerators, params: &E::Params) -> Self {
        let res = params.generator(p_g).mul(privkey.0, params).into();
        PublicKey(res)
    }

    pub fn randomize(&self, alpha: E::Fs, p_g: FixedGenerators, params: &E::Params) -> Self {
        let res: Point<E, Unknown> = params.generator(p_g).mul(alpha, params).into();
        let res = res.add(&self.0, params);
        PublicKey(res)
    }

    pub fn read<R: io::Read>(reader: &mut R, params: &E::Params) -> io::Result<Self> {
        let p = Point::read(reader, params)?;
        Ok(PublicKey(p))
    }

    pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.0.write(writer)
    }

    pub fn verify(
        &self,
        msg: &[u8],
        sig: &Signature,
        p_g: FixedGenerators,
        params: &E::Params,
    ) -> bool {
        // c = H*(Rbar || M)
        let c = h_star::<E>(&sig.rbar[..], msg);

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

pub struct BatchEntry<'a, E: JubjubEngine> {
    vk: PublicKey<E>,
    msg: &'a [u8],
    sig: Signature,
}

// TODO: #82: This is a naive implementation currently,
// and doesn't use multiexp.
pub fn batch_verify<'a, E: JubjubEngine, R: Rng>(
    rng: &mut R,
    batch: &[BatchEntry<'a, E>],
    p_g: FixedGenerators,
    params: &E::Params,
) -> bool {
    let mut acc = Point::<E, Unknown>::zero();

    for entry in batch {
        let mut r = match Point::<E, Unknown>::read(&mut &entry.sig.rbar[..], params) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let mut s = match read_scalar::<E, &[u8]>(&entry.sig.sbar[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mut c = h_star::<E>(&entry.sig.rbar[..], entry.msg);

        let z = E::Fs::rand(rng);

        s.mul_assign(&z);
        s.negate();

        r = r.mul(z, params);

        c.mul_assign(&z);

        acc = acc.add(&r, params);
        acc = acc.add(&entry.vk.0.mul(c, params), params);
        acc = acc.add(&params.generator(p_g).mul(s, params).into(), params);
    }

    acc = acc.mul_by_cofactor(params).into();

    acc.eq(&Point::zero())
}

#[cfg(test)]
mod tests {
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::curve::{edwards, fs::Fs, JubjubBls12};

    use super::*;

    #[test]
    fn test_batch_verify() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::SpendingKeyGenerator;

        let sk1 = PrivateKey::<Bls12>(rng.gen());
        let vk1 = PublicKey::from_private(&sk1, p_g, params);
        let msg1 = b"Foo bar";
        let sig1 = sk1.sign(msg1, &mut rng, p_g, params);
        assert!(vk1.verify(msg1, &sig1, p_g, params));

        let sk2 = PrivateKey::<Bls12>(rng.gen());
        let vk2 = PublicKey::from_private(&sk2, p_g, params);
        let msg2 = b"Foo bar";
        let sig2 = sk2.sign(msg2, &mut rng, p_g, params);
        assert!(vk2.verify(msg2, &sig2, p_g, params));

        let mut batch = vec![
            BatchEntry {
                vk: vk1,
                msg: msg1,
                sig: sig1,
            },
            BatchEntry {
                vk: vk2,
                msg: msg2,
                sig: sig2,
            },
        ];

        assert!(batch_verify(&mut rng, &batch, p_g, params));

        batch[0].sig = sig2;

        assert!(!batch_verify(&mut rng, &batch, p_g, params));
    }

    #[test]
    fn cofactor_check() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let params = &JubjubBls12::new();
        let zero = edwards::Point::zero();
        let p_g = FixedGenerators::SpendingKeyGenerator;

        // Get a point of order 8
        let p8 = loop {
            let r = edwards::Point::<Bls12, _>::rand(&mut rng, params).mul(Fs::char(), params);

            let r2 = r.double(params);
            let r4 = r2.double(params);
            let r8 = r4.double(params);

            if r2 != zero && r4 != zero && r8 == zero {
                break r;
            }
        };

        let sk = PrivateKey::<Bls12>(rng.gen());
        let vk = PublicKey::from_private(&sk, p_g, params);

        // TODO: This test will need to change when #77 is fixed
        let msg = b"Foo bar";
        let sig = sk.sign(msg, &mut rng, p_g, params);
        assert!(vk.verify(msg, &sig, p_g, params));

        let vktorsion = PublicKey(vk.0.add(&p8, params));
        assert!(vktorsion.verify(msg, &sig, p_g, params));
    }

    #[test]
    fn round_trip_serialization() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let p_g = FixedGenerators::SpendingKeyGenerator;
        let params = &JubjubBls12::new();

        for _ in 0..1000 {
            let sk = PrivateKey::<Bls12>(rng.gen());
            let vk = PublicKey::from_private(&sk, p_g, params);
            let msg = b"Foo bar";
            let sig = sk.sign(msg, &mut rng, p_g, params);

            let mut sk_bytes = [0u8; 32];
            let mut vk_bytes = [0u8; 32];
            let mut sig_bytes = [0u8; 64];
            sk.write(&mut sk_bytes[..]).unwrap();
            vk.write(&mut &mut vk_bytes[..]).unwrap();
            sig.write(&mut sig_bytes[..]).unwrap();

            let sk_2 = PrivateKey::<Bls12>::read(&sk_bytes[..]).unwrap();
            let vk_2 = PublicKey::from_private(&sk_2, p_g, params);
            let mut vk_2_bytes = [0u8; 32];
            vk_2.write(&mut &mut vk_2_bytes[..]).unwrap();
            assert!(vk_bytes == vk_2_bytes);

            let vk_2 = PublicKey::<Bls12>::read(&mut &vk_bytes[..], params).unwrap();
            let sig_2 = Signature::read(&sig_bytes[..]).unwrap();
            assert!(vk.verify(msg, &sig_2, p_g, params));
            assert!(vk_2.verify(msg, &sig, p_g, params));
            assert!(vk_2.verify(msg, &sig_2, p_g, params));
        }
    }

    #[test]
    fn random_signatures() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let p_g = FixedGenerators::SpendingKeyGenerator;
        let params = &JubjubBls12::new();

        for _ in 0..1000 {
            let sk = PrivateKey::<Bls12>(rng.gen());
            let vk = PublicKey::from_private(&sk, p_g, params);

            let msg1 = b"Foo bar";
            let msg2 = b"Spam eggs";

            let sig1 = sk.sign(msg1, &mut rng, p_g, params);
            let sig2 = sk.sign(msg2, &mut rng, p_g, params);

            assert!(vk.verify(msg1, &sig1, p_g, params));
            assert!(vk.verify(msg2, &sig2, p_g, params));
            assert!(!vk.verify(msg1, &sig2, p_g, params));
            assert!(!vk.verify(msg2, &sig1, p_g, params));

            let alpha = rng.gen();
            let rsk = sk.randomize(alpha);
            let rvk = vk.randomize(alpha, p_g, params);

            let sig1 = rsk.sign(msg1, &mut rng, p_g, params);
            let sig2 = rsk.sign(msg2, &mut rng, p_g, params);

            assert!(rvk.verify(msg1, &sig1, p_g, params));
            assert!(rvk.verify(msg2, &sig2, p_g, params));
            assert!(!rvk.verify(msg1, &sig2, p_g, params));
            assert!(!rvk.verify(msg2, &sig1, p_g, params));
        }
    }
}
