use crate::{err::Res, AeadId};

pub trait Decrypt {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>>;
    fn alg(&self) -> AeadId;
}

pub trait Encrypt {
    #[allow(dead_code)] // TODO
    fn alg(&self) -> AeadId;
    fn seal(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>>;
}
