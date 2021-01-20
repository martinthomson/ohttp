use super::err::{Error, Res};
use super::p11::{sys, Item, PrivateKey, PublicKey, SymKey};
use super::secstatus_to_res;
use std::convert::TryFrom;
use std::os::raw::c_uint;
use std::ptr::{null, null_mut};

pub use sys::{HpkeAeadId as AeadId, HpkeContext, HpkeKdfId as KdfId, HpkeKemId as KemId};

/// Configuration for `Hpke`.
/// As there are relatively few options, use the builder pattern
/// with a sensible default.
#[derive(Clone)]
pub struct HpkeConfig {
    kem: KemId::Type,
    kdf: KdfId::Type,
    aead: AeadId::Type,
}

impl HpkeConfig {
    fn kem(mut self, kem: KemId::Type) -> Self {
        self.kem = kem;
        self
    }

    fn kdf(mut self, kdf: KdfId::Type) -> Self {
        self.kdf = kdf;
        self
    }

    fn aead(mut self, aead: AeadId::Type) -> Self {
        self.aead = aead;
        self
    }
}

impl Default for HpkeConfig {
    fn default() -> Self {
        Self {
            kem: KemId::HpkeDhKemX25519Sha256,
            kdf: KdfId::HpkeKdfHkdfSha256,
            aead: AeadId::HpkeAeadAes128Gcm,
        }
    }
}

unsafe fn destroy_hpke_context(cx: *mut HpkeContext) {
    sys::PK11_HPKE_DestroyContext(cx, sys::PRBool::from(true));
}

scoped_ptr!(Hpke, sys::HpkeContext, destroy_hpke_context);

impl Hpke {
    /// Create a new context that uses the KEM mode.
    /// This object is useless until `setup_s` or `setup_r` is called.
    pub fn new(cfg: &HpkeConfig) -> Res<Self> {
        let ptr =
            unsafe { sys::PK11_HPKE_NewContext(cfg.kem, cfg.kdf, cfg.aead, null_mut(), null()) };
        Hpke::from_ptr(ptr)
    }

    #[allow(clippy::similar_names)]
    pub fn setup_s(
        &mut self,
        pk_e: &PublicKey,
        sk_e: &mut PrivateKey,
        pk_r: &mut PublicKey,
        info: &[u8],
    ) -> Res<()> {
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_SetupS(**self, **pk_e, **sk_e, **pk_r, &Item::wrap(info))
        })
    }

    /// Get the encapsulated KEM secret.
    pub fn enc(&self) -> Res<Vec<u8>> {
        let v = unsafe { sys::PK11_HPKE_GetEncapPubKey(**self) };
        let r = unsafe { v.as_ref() }.ok_or_else(Error::internal)?;
        // This is just an alias, so we can't use `Item`.
        let len = usize::try_from(r.len).unwrap();
        let slc = unsafe { std::slice::from_raw_parts(r.data, len) };
        Ok(Vec::from(slc))
    }

    #[allow(clippy::similar_names)]
    pub fn setup_r(
        &mut self,
        pk_r: &PublicKey,
        sk_r: &mut PrivateKey,
        enc: &[u8],
        info: &[u8],
    ) -> Res<()> {
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_SetupR(**self, **pk_r, **sk_r, &Item::wrap(enc), &Item::wrap(info))
        })
    }

    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        let mut out: *mut sys::SECItem = null_mut();
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_Seal(**self, &Item::wrap(aad), &Item::wrap(pt), &mut out)
        })?;
        let v = Item::from_ptr(out as *mut _)?;
        Ok(unsafe { v.into_vec() })
    }

    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        let mut out: *mut sys::SECItem = null_mut();
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_Open(**self, &Item::wrap(aad), &Item::wrap(ct), &mut out)
        })?;
        let v = Item::from_ptr(out)?;
        Ok(unsafe { v.into_vec() })
    }

    pub fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        let mut out: *mut sys::PK11SymKey = null_mut();
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_ExportSecret(
                **self,
                &Item::wrap(info),
                c_uint::try_from(len).unwrap(),
                &mut out,
            )
        })?;
        SymKey::from_ptr(out)
    }
}

#[cfg(test)]
mod test {
    use super::super::{generate_key_pair, init};
    use super::{AeadId, Hpke, HpkeConfig};

    #[must_use]
    fn new_context() -> Hpke {
        init();
        Hpke::new(&HpkeConfig::default()).unwrap()
    }

    #[test]
    fn make_context() {
        let _ = new_context();
    }

    #[allow(clippy::similar_names)]
    fn seal_open(aead: AeadId::Type) {
        const INFO: &[u8] = b"info";
        const AAD: &[u8] = b"aad";
        const PT: &[u8] = b"message";

        // Setup
        init();
        let cfg = HpkeConfig::default().aead(aead);
        let (mut sk_s, pk_s) = generate_key_pair().unwrap();
        let (mut sk_r, mut pk_r) = generate_key_pair().unwrap();

        // Send
        let mut hpke_s = Hpke::new(&cfg).unwrap();
        hpke_s.setup_s(&pk_s, &mut sk_s, &mut pk_r, INFO).unwrap();
        let enc = hpke_s.enc().unwrap();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receive
        let mut hpke_r = Hpke::new(&cfg).unwrap();
        hpke_r.setup_r(&pk_r, &mut sk_r, &enc, INFO).unwrap();
        let pt = hpke_r.open(AAD, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn seal_open_gcm() {
        seal_open(AeadId::HpkeAeadAes128Gcm);
    }

    #[test]
    fn seal_open_chacha() {
        seal_open(AeadId::HpkeAeadChaCha20Poly1305);
    }
}
