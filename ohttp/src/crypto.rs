use crate::err::Res;

pub trait Decrypt {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>>;
}

pub trait Encrypt {
    fn seal(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>>;
}
