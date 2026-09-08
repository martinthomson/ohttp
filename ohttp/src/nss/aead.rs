use nss_rs::SymKey;
pub use nss_rs::aead::{Mode, NONCE_LEN};

use crate::{
    AeadId,
    crypto::{Decrypt, Encrypt},
    err::Res,
};

pub struct Aead {
    inner: nss_rs::aead::Aead,
    algorithm: AeadId,
    decrypt_counter: nss_rs::aead::SequenceNumber,
}

impl Aead {
    fn map_alg(aead: AeadId) -> nss_rs::aead::AeadAlgorithms {
        match aead {
            AeadId::Aes128Gcm => nss_rs::aead::AeadAlgorithms::Aes128Gcm,
            AeadId::Aes256Gcm => nss_rs::aead::AeadAlgorithms::Aes256Gcm,
            AeadId::ChaCha20Poly1305 => nss_rs::aead::AeadAlgorithms::ChaCha20Poly1305,
        }
    }

    pub fn new(
        mode: Mode,
        algorithm: crate::AeadId,
        key: &SymKey,
        nonce_base: [u8; NONCE_LEN],
    ) -> Res<Self> {
        Ok(Self {
            inner: nss_rs::aead::Aead::new(mode, Self::map_alg(algorithm), key, nonce_base)?,
            algorithm,
            decrypt_counter: 0,
        })
    }
}

impl Decrypt for Aead {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> crate::err::Res<Vec<u8>> {
        let res = self.inner.decrypt(aad, self.decrypt_counter, ct);
        self.decrypt_counter += 1;
        Ok(res?)
    }

    fn alg(&self) -> AeadId {
        self.algorithm
    }
}

impl Encrypt for Aead {
    fn seal(&mut self, aad: &[u8], ct: &[u8]) -> crate::err::Res<Vec<u8>> {
        Ok(self.inner.encrypt(aad, ct)?)
    }

    fn alg(&self) -> AeadId {
        self.algorithm
    }
}
