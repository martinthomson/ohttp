use nss_rs::{
    PrivateKey, PublicKey, SymKey,
    ec::{EcCurve, EcdhKeypair},
    hpke::Exporter as _,
};

use crate::{
    crypto::{Decrypt, Encrypt},
    err::Res,
    hpke::{Aead, Exporter, Kdf, Kem},
};

#[derive(Clone, Copy)]
pub struct Config {
    kem: Kem,
    kdf: Kdf,
    aead: Aead,
}

impl Config {
    pub fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Self {
        Self { kem, kdf, aead }
    }
}

impl Config {
    #[must_use]
    pub fn kem(self) -> Kem {
        self.kem
    }

    #[must_use]
    pub fn kdf(self) -> Kdf {
        self.kdf
    }

    #[must_use]
    pub fn aead(self) -> Aead {
        self.aead
    }

    fn to_nss(self) -> Res<nss_rs::hpke::Config> {
        Ok(nss_rs::hpke::Config::new(
            nss_rs::hpke::KemAlgorithm::try_from(u16::from(self.kem))?,
            nss_rs::hpke::KdfAlgorithm::try_from(u16::from(self.kdf))?,
            nss_rs::hpke::AeadAlgorithm::try_from(u16::from(self.aead))?,
        ))
    }

    #[must_use]
    pub fn supported(self) -> bool {
        self.to_nss().map_or(false, |cfg| cfg.supported())
    }
}

pub struct HpkeS {
    inner: nss_rs::hpke::HpkeS,
    config: Config,
}

impl HpkeS {
    pub fn new(config: Config, pk_r: &PublicKey, info: &[u8]) -> Res<Self> {
        let inner = nss_rs::hpke::HpkeS::new(config.to_nss()?, pk_r, info)?;
        Ok(Self { inner, config })
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn enc(&self) -> Res<Vec<u8>> {
        Ok(self.inner.enc()?)
    }
}

impl Encrypt for HpkeS {
    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        Ok(self.inner.seal(aad, pt)?)
    }

    fn alg(&self) -> Aead {
        self.config().aead()
    }
}

impl Exporter for HpkeS {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        Ok(self.inner.export(info, len)?)
    }
}

pub struct HpkeR {
    inner: nss_rs::hpke::HpkeR,
    config: Config,
}

impl HpkeR {
    #[allow(clippy::similar_names)]
    pub fn new(
        config: Config,
        pk_r: &PublicKey,
        sk_r: &PrivateKey,
        enc: &[u8],
        info: &[u8],
    ) -> Res<Self> {
        let inner = nss_rs::hpke::HpkeR::new(config.to_nss()?, pk_r, sk_r, enc, info)?;
        Ok(Self { inner, config })
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn decode_public_key(kem: Kem, k: &[u8]) -> Res<PublicKey> {
        let kem = nss_rs::hpke::KemAlgorithm::try_from(u16::from(kem))?;
        Ok(nss_rs::hpke::HpkeR::decode_public_key(kem, k)?)
    }
}

impl Decrypt for HpkeR {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        Ok(self.inner.open(aad, ct)?)
    }

    fn alg(&self) -> Aead {
        self.config().aead()
    }
}

impl Exporter for HpkeR {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        Ok(self.inner.export(info, len)?)
    }
}

pub fn generate_key_pair(kem: Kem) -> Res<(PrivateKey, PublicKey)> {
    let kem = nss_rs::hpke::KemAlgorithm::try_from(u16::from(kem))?;
    let EcdhKeypair { private, public } = nss_rs::ec::ecdh_keygen(EcCurve::try_from(kem)?)?;
    Ok((private, public))
}
