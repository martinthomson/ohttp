use crate::{AeadId, err::Res};

pub trait Decrypt {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>>;
    #[allow(dead_code)] // Used by stream feature.
    fn alg(&self) -> AeadId;
}

pub trait Encrypt {
    fn seal(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>>;
    #[allow(dead_code)] // Used by stream feature.
    fn alg(&self) -> AeadId;
}
