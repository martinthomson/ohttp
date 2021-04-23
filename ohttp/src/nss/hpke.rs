use super::err::{sec::SEC_ERROR_INVALID_ARGS, Error, Res};
use super::p11::{sys, Item, PrivateKey, PublicKey, Slot, SymKey};
use super::secstatus_to_res;
use log::{log_enabled, trace};
use std::convert::TryFrom;
use std::ops::Deref;
use std::os::raw::c_uint;
use std::ptr::{null, null_mut};

pub use sys::{HpkeAeadId as AeadId, HpkeKdfId as KdfId, HpkeKemId as KemId};

/// Configuration for `Hpke`.
#[derive(Clone, Copy)]
pub struct HpkeConfig {
    kem: KemId::Type,
    kdf: KdfId::Type,
    aead: AeadId::Type,
}

impl HpkeConfig {
    pub fn new(kem: KemId::Type, kdf: KdfId::Type, aead: AeadId::Type) -> Self {
        Self { kem, kdf, aead }
    }

    pub fn kem(&self) -> KemId::Type {
        self.kem
    }

    pub fn kdf(&self) -> KdfId::Type {
        self.kdf
    }

    pub fn aead(&self) -> AeadId::Type {
        self.aead
    }

    pub fn supported(&self) -> bool {
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_ValidateParameters(self.kem, self.kdf, self.aead)
        })
        .is_ok()
    }

    pub fn n_enc(&self) -> usize {
        match self.kem {
            KemId::HpkeDhKemX25519Sha256 => 32,
            _ => unimplemented!(),
        }
    }

    pub fn n_pk(&self) -> usize {
        match self.kem {
            KemId::HpkeDhKemX25519Sha256 => 32,
            _ => unimplemented!(),
        }
    }

    pub fn n_k(&self) -> usize {
        match self.aead {
            AeadId::HpkeAeadAes128Gcm => 16,
            AeadId::HpkeAeadChaCha20Poly1305 => 32,
            _ => unimplemented!(),
        }
    }

    pub fn n_n(&self) -> usize {
        match self.aead {
            AeadId::HpkeAeadAes128Gcm | AeadId::HpkeAeadChaCha20Poly1305 => 12,
            _ => unimplemented!(),
        }
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

unsafe fn destroy_hpke_context(cx: *mut sys::HpkeContext) {
    sys::PK11_HPKE_DestroyContext(cx, sys::PRBool::from(true));
}

scoped_ptr!(HpkeContext, sys::HpkeContext, destroy_hpke_context);

pub struct Hpke {
    context: HpkeContext,
    config: HpkeConfig,
}

impl Hpke {
    /// Create a new context that uses the KEM mode.
    /// This object is useless until `setup_s` or `setup_r` is called.
    pub fn new(config: HpkeConfig) -> Res<Self> {
        let ptr = unsafe {
            sys::PK11_HPKE_NewContext(config.kem, config.kdf, config.aead, null_mut(), null())
        };
        Ok(Self {
            context: HpkeContext::from_ptr(ptr)?,
            config,
        })
    }

    pub fn config(&self) -> HpkeConfig {
        self.config
    }

    pub fn decode_public_key(&self, k: &[u8]) -> Res<PublicKey> {
        let mut ptr: *mut sys::SECKEYPublicKey = null_mut();
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_Deserialize(
                *self.context,
                k.as_ptr(),
                c_uint::try_from(k.len()).unwrap(),
                &mut ptr,
            )
        })?;
        PublicKey::from_ptr(ptr)
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
            sys::PK11_HPKE_SetupS(*self.context, **pk_e, **sk_e, **pk_r, &Item::wrap(info))
        })
    }

    /// Get the encapsulated KEM secret.
    /// Only works after calling `setup_s`, returns an error if this is a receiver.
    pub fn enc(&self) -> Res<Vec<u8>> {
        let v = unsafe { sys::PK11_HPKE_GetEncapPubKey(*self.context) };
        let r = unsafe { v.as_ref() }.ok_or_else(|| Error::from(SEC_ERROR_INVALID_ARGS))?;
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
            sys::PK11_HPKE_SetupR(
                *self.context,
                **pk_r,
                **sk_r,
                &Item::wrap(enc),
                &Item::wrap(info),
            )
        })
    }

    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        let mut out: *mut sys::SECItem = null_mut();
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_Seal(*self.context, &Item::wrap(aad), &Item::wrap(pt), &mut out)
        })?;
        let v = Item::from_ptr(out)?;
        Ok(unsafe { v.into_vec() })
    }

    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        let mut out: *mut sys::SECItem = null_mut();
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_Open(*self.context, &Item::wrap(aad), &Item::wrap(ct), &mut out)
        })?;
        let v = Item::from_ptr(out)?;
        Ok(unsafe { v.into_vec() })
    }

    pub fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        let mut out: *mut sys::PK11SymKey = null_mut();
        secstatus_to_res(unsafe {
            sys::PK11_HPKE_ExportSecret(
                *self.context,
                &Item::wrap(info),
                c_uint::try_from(len).unwrap(),
                &mut out,
            )
        })?;
        SymKey::from_ptr(out)
    }
}

impl Deref for Hpke {
    type Target = HpkeConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

/// Generate a key pair for the identified KEM.
pub fn generate_key_pair(kem: KemId::Type) -> Res<(PrivateKey, PublicKey)> {
    assert_eq!(kem, KemId::HpkeDhKemX25519Sha256);
    let slot = Slot::internal()?;

    let oid_data = unsafe { sys::SECOID_FindOIDByTag(sys::SECOidTag::SEC_OID_CURVE25519) };
    let oid = unsafe { oid_data.as_ref() }.ok_or_else(Error::internal)?;
    let oid_slc =
        unsafe { std::slice::from_raw_parts(oid.oid.data, usize::try_from(oid.oid.len).unwrap()) };
    let mut params: Vec<u8> = Vec::with_capacity(oid_slc.len() + 2);
    params.push(u8::try_from(sys::SEC_ASN1_OBJECT_ID).unwrap());
    params.push(u8::try_from(oid.oid.len).unwrap());
    params.extend_from_slice(oid_slc);

    let mut public_ptr: *mut sys::SECKEYPublicKey = null_mut();

    // Try to make an insensitive key so that we can read the key data for tracing.
    let insensitive_secret_ptr = if log_enabled!(log::Level::Trace) {
        unsafe {
            sys::PK11_GenerateKeyPairWithOpFlags(
                *slot,
                sys::CK_MECHANISM_TYPE::from(sys::CKM_EC_KEY_PAIR_GEN),
                (&mut Item::wrap(&params) as *mut sys::SECItem).cast(),
                &mut public_ptr,
                sys::PK11_ATTR_SESSION | sys::PK11_ATTR_INSENSITIVE | sys::PK11_ATTR_PUBLIC,
                sys::CK_FLAGS::from(sys::CKF_DERIVE),
                sys::CK_FLAGS::from(sys::CKF_DERIVE),
                null_mut(),
            )
        }
    } else {
        null_mut()
    };
    assert_eq!(insensitive_secret_ptr.is_null(), public_ptr.is_null());
    let secret_ptr = if insensitive_secret_ptr.is_null() {
        unsafe {
            sys::PK11_GenerateKeyPairWithOpFlags(
                *slot,
                sys::CK_MECHANISM_TYPE::from(sys::CKM_EC_KEY_PAIR_GEN),
                (&mut Item::wrap(&params) as *mut sys::SECItem).cast(),
                &mut public_ptr,
                sys::PK11_ATTR_SESSION | sys::PK11_ATTR_SENSITIVE | sys::PK11_ATTR_PRIVATE,
                sys::CK_FLAGS::from(sys::CKF_DERIVE),
                sys::CK_FLAGS::from(sys::CKF_DERIVE),
                null_mut(),
            )
        }
    } else {
        insensitive_secret_ptr
    };
    assert_eq!(secret_ptr.is_null(), public_ptr.is_null());
    let sk = PrivateKey::from_ptr(secret_ptr)?;
    let pk = PublicKey::from_ptr(public_ptr)?;
    trace!("Generated key pair: sk={:?} pk={:?}", sk, pk);
    Ok((sk, pk))
}

#[cfg(test)]
mod test {
    use super::{generate_key_pair, AeadId, Hpke, HpkeConfig};
    use crate::init;

    #[must_use]
    fn new_context() -> Hpke {
        init();
        Hpke::new(HpkeConfig::default()).unwrap()
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
        let cfg = HpkeConfig {
            aead,
            ..HpkeConfig::default()
        };
        assert!(cfg.supported());
        let mut hpke_s = Hpke::new(cfg).unwrap();
        let mut hpke_r = Hpke::new(cfg).unwrap();
        let (mut sk_s, pk_s) = generate_key_pair(cfg.kem()).unwrap();
        let (mut sk_r, mut pk_r) = generate_key_pair(cfg.kem()).unwrap();

        // Send
        hpke_s.setup_s(&pk_s, &mut sk_s, &mut pk_r, INFO).unwrap();
        let enc = hpke_s.enc().unwrap();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receive
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

    #[test]
    fn bogus_config() {
        assert!(!HpkeConfig {
            kem: 99_999,
            ..HpkeConfig::default()
        }
        .supported());
        assert!(!HpkeConfig {
            kdf: 99_999,
            ..HpkeConfig::default()
        }
        .supported());
        assert!(!HpkeConfig {
            aead: 99_999,
            ..HpkeConfig::default()
        }
        .supported());
    }
}
