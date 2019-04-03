

const COMMITMENT_SIZE: usize = 32;

pub struct Commitment(pub [u8; COMMITMENT_SIZE]);

impl Commitment {
    fn for_r() -> Commitment {
        unimplemented!();
    }
}

enum CoR {
    Commit(Commitment),
    Reveal{ R: }
}

impl CoR {
    fn set_revealsed(&mut self) {

    }


}

pub struct MuSig<T: SigningTranscript, S> {
    t: T,
    stage: S
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_sig() {
        
    }
}