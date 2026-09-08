use crate::{
    SymKey,
    err::Res,
    hpke::{Aead, Kdf},
};

pub enum KeyMechanism {
    Aead(Aead),
    Hkdf,
}

impl From<KeyMechanism> for nss_rs::hkdf::KeyMechanism {
    fn from(v: KeyMechanism) -> Self {
        match v {
            KeyMechanism::Aead(aead) => Self::Aead(
                nss_rs::aead::AeadAlgorithms::try_from(
                    nss_rs::hpke::AeadAlgorithm::try_from(u16::from(aead))
                        .expect("unsupported AEAD"),
                )
                .expect("unexpected AEAD"),
            ),
            KeyMechanism::Hkdf => Self::Hkdf,
        }
    }
}

pub struct Hkdf(nss_rs::hkdf::Hkdf);

impl Hkdf {
    pub fn new(kdf: Kdf) -> Self {
        Self(nss_rs::hkdf::Hkdf::new(
            nss_rs::hkdf::KdfAlgorithm::try_from(
                nss_rs::hpke::KdfAlgorithm::try_from(u16::from(kdf)).expect("unmapped KDF"),
            )
            .expect("unmapped KDF (nss_rs)"),
        ))
    }
    pub fn extract(&self, salt: &[u8], ikm: &SymKey) -> Res<SymKey> {
        Ok(self.0.extract(salt, ikm).map_err(nss_rs::Error::from)?)
    }
    pub fn expand_key(&self, prk: &SymKey, info: &[u8], key_mech: KeyMechanism) -> Res<SymKey> {
        Ok(self
            .0
            .expand_key(prk, info, nss_rs::hkdf::KeyMechanism::from(key_mech))
            .map_err(nss_rs::Error::from)?)
    }
    pub fn expand_data(&self, prk: &SymKey, info: &[u8], len: usize) -> Res<Vec<u8>> {
        Ok(self
            .0
            .expand_data(prk, info, len)
            .map_err(nss_rs::Error::from)?)
    }
}
