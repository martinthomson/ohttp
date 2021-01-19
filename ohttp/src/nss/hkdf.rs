use super::err::{Error, Res};
use super::hpke::{AeadId, KdfId};
use super::p11::{
    Item, PK11_Derive, PK11_ExtractKeyValue, PK11_GetKeyData, SECItem, SymKey, CKA_DERIVE,
    CKF_HKDF_SALT_DATA, CKF_HKDF_SALT_NULL, CKM_AES_GCM, CKM_CHACHA20_POLY1305, CKM_HKDF_DATA,
    CKM_HKDF_DERIVE, CKM_SHA256, CK_BBOOL, CK_HKDF_PARAMS, CK_INVALID_HANDLE, CK_MECHANISM_TYPE,
    CK_OBJECT_HANDLE, CK_ULONG,
};
use super::secstatus_to_res;
use std::convert::TryFrom;
use std::os::raw::c_int;
use std::ptr::{null_mut, NonNull};

pub enum KeyMechanism {
    Aead(AeadId::Type),
    Hkdf,
}

impl KeyMechanism {
    fn mech(&self) -> CK_MECHANISM_TYPE {
        CK_MECHANISM_TYPE::from(match self {
            Self::Aead(AeadId::HpkeAeadAes128Gcm) => CKM_AES_GCM,
            Self::Aead(AeadId::HpkeAeadChaCha20Poly1305) => CKM_CHACHA20_POLY1305,
            Self::Hkdf => CKM_HKDF_DERIVE,
            _ => unimplemented!(),
        })
    }
    
    fn len(&self) -> usize {
        match self {
            Self::Aead(AeadId::HpkeAeadAes128Gcm) => 16,
            Self::Aead(AeadId::HpkeAeadChaCha20Poly1305) => 32,
            Self::Hkdf => 0, // Let the underlying module decide.
            _ => unimplemented!(),
        }
    }
}

pub struct Hkdf {
    kdf: KdfId::Type,
}

impl Hkdf {
    fn mech(&self) -> CK_MECHANISM_TYPE {
        CK_MECHANISM_TYPE::from(match self.kdf {
            KdfId::HpkeKdfHkdfSha256 => CKM_SHA256,
            _ => unimplemented!(),
        })
    }

    pub fn extract(&self, salt: &[u8], ikm: &SymKey) -> Res<SymKey> {
        let params = CK_HKDF_PARAMS {
            bExtract: CK_BBOOL::from(true),
            bExpand: CK_BBOOL::from(false),
            prfHashMechanism: self.mech(),
            ulSaltType: CK_ULONG::from(CKF_HKDF_SALT_DATA),
            pSalt: salt.as_ptr() as *mut _, // const-cast = bad API
            ulSaltLen: CK_ULONG::try_from(salt.len()).unwrap(),
            hSaltKey: CK_OBJECT_HANDLE::from(CK_INVALID_HANDLE),
            pInfo: null_mut(),
            ulInfoLen: 0,
        };
        let ptr = unsafe {
            PK11_Derive(
                **ikm,
                CK_MECHANISM_TYPE::from(CKM_HKDF_DERIVE),
                &mut Item::param_wrap(&params),
                CK_MECHANISM_TYPE::from(CKM_HKDF_DERIVE),
                CK_MECHANISM_TYPE::from(CKA_DERIVE),
                0,
            )
        };
        Ok(SymKey::from_ptr(
            NonNull::new(ptr).ok_or(Error::internal())?,
        ))
    }

    fn expand_params(&self, info: &[u8]) -> (SECItem, CK_HKDF_PARAMS) {
        let params = CK_HKDF_PARAMS {
            bExtract: CK_BBOOL::from(false),
            bExpand: CK_BBOOL::from(true),
            prfHashMechanism: self.mech(),
            ulSaltType: CK_ULONG::from(CKF_HKDF_SALT_NULL),
            pSalt: null_mut(),
            ulSaltLen: 0,
            hSaltKey: CK_OBJECT_HANDLE::from(CK_INVALID_HANDLE),
            pInfo: info.as_ptr() as *mut _, // const-cast = bad API
            ulInfoLen: CK_ULONG::try_from(info.len()).unwrap(),
        };
        (Item::param_wrap(&params), params)
    }

    pub fn expand_key(&self, prk: &SymKey, info: &[u8], key_mech: KeyMechanism) -> Res<SymKey> {
        let (mut item, _params) = self.expand_params(&info);
        let ptr = unsafe {
            PK11_Derive(
                **prk,
                CK_MECHANISM_TYPE::from(CKM_HKDF_DERIVE),
                &mut item,
                key_mech.mech(),
                CK_MECHANISM_TYPE::from(CKA_DERIVE),
                c_int::try_from(key_mech.len()).unwrap(),
            )
        };
        Ok(SymKey::from_ptr(
            NonNull::new(ptr).ok_or(Error::internal())?,
        ))
    }

    pub fn expand_data(&self, prk: &SymKey, info: &[u8], len: usize) -> Res<Vec<u8>> {
        let (mut item, _params) = self.expand_params(&info);
        let ptr = unsafe {
            PK11_Derive(
                **prk,
                CK_MECHANISM_TYPE::from(CKM_HKDF_DATA),
                &mut item,
                CK_MECHANISM_TYPE::from(CKM_HKDF_DERIVE),
                CK_MECHANISM_TYPE::from(CKA_DERIVE),
                c_int::try_from(len).unwrap(),
            )
        };
        let k = SymKey::from_ptr(NonNull::new(ptr).ok_or(Error::internal())?);
        secstatus_to_res(unsafe { PK11_ExtractKeyValue(*k) })?;
        let data_ptr = unsafe { PK11_GetKeyData(*k) };
        let data = unsafe { data_ptr.as_ref() }.ok_or(Error::internal())?;
        let slc =
            unsafe { std::slice::from_raw_parts(data.data, usize::try_from(data.len).unwrap()) };
        Ok(Vec::from(slc))
    }
}
