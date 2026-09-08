use std::ops::Deref;

use ::hpke as rust_hpke;
use ::hpke::inout::InOutBuf;
use hpke::kem::{DhP256HkdfSha256, DhP384HkdfSha384, DhP521HkdfSha512};
use log::trace;
use rust_hpke::{
    Deserializable, OpModeR, OpModeS, Serializable,
    aead::{AeadCtxR, AeadCtxS, AeadTag, AesGcm128, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::{Kem as KemTrait, X25519HkdfSha256, XWing},
    setup_receiver, setup_sender,
};

use super::SymKey;
use crate::{
    Error, Res,
    crypto::{Decrypt, Encrypt},
    hpke::{Aead, Exporter, Kdf, Kem},
};

/// Configuration for `Hpke`.
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

    pub fn kem(self) -> Kem {
        self.kem
    }

    pub fn kdf(self) -> Kdf {
        self.kdf
    }

    pub fn aead(self) -> Aead {
        self.aead
    }

    pub fn supported(self) -> bool {
        matches!(
            self.kem,
            Kem::X25519Sha256 | Kem::P256Sha256 | Kem::P384Sha384 | Kem::P521Sha512 | Kem::XWing
        ) && self.kdf == Kdf::HkdfSha256
            && matches!(self.aead, Aead::Aes128Gcm | Aead::ChaCha20Poly1305)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            kem: Kem::X25519Sha256,
            kdf: Kdf::HkdfSha256,
            aead: Aead::Aes128Gcm,
        }
    }
}

/// Generate the `PublicKey`/`PrivateKey` enums and the KEM-parameterized free
/// functions (`generate_key_pair`, `derive_key_pair`) plus `HpkeR::decode_public_key`
/// from a single list of the supported KEMs.  Each row is
/// `{ <ohttp Kem id>, <rust-hpke Kem type>, <enum variant> }`.
macro_rules! hpke_kems {
    { $( { $kem_id:path, $kem:path, $variant:ident } ),* $(,)? } => {
        #[allow(clippy::large_enum_variant)]
        #[derive(Clone)]
        pub enum PublicKey {
            $( $variant(<$kem as KemTrait>::PublicKey), )*
        }

        #[allow(clippy::large_enum_variant)]
        #[derive(Clone)]
        pub enum PrivateKey {
            $( $variant(<$kem as KemTrait>::PrivateKey), )*
        }

        impl PublicKey {
            #[allow(clippy::unnecessary_wraps)]
            pub fn key_data(&self) -> Res<Vec<u8>> {
                Ok(match self {
                    $( Self::$variant(k) => Vec::from(k.to_bytes().as_slice()), )*
                })
            }
        }

        impl PrivateKey {
            #[allow(clippy::unnecessary_wraps)]
            pub fn key_data(&self) -> Res<Vec<u8>> {
                Ok(match self {
                    $( Self::$variant(k) => Vec::from(k.to_bytes().as_slice()), )*
                })
            }
        }

        impl HpkeR {
            pub fn decode_public_key(kem: Kem, k: &[u8]) -> Res<PublicKey> {
                Ok(match kem {
                    $(
                        $kem_id => {
                            PublicKey::$variant(<$kem as KemTrait>::PublicKey::from_bytes(k)?)
                        }
                    )*
                })
            }
        }

        /// Generate a key pair for the identified KEM.
        #[allow(clippy::unnecessary_wraps)]
        pub fn generate_key_pair(kem: Kem) -> Res<(PrivateKey, PublicKey)> {
            let (sk, pk) = match kem {
                $(
                    $kem_id => {
                        let (sk, pk) = <$kem>::gen_keypair();
                        (PrivateKey::$variant(sk), PublicKey::$variant(pk))
                    }
                )*
            };
            trace!("Generated key pair: sk={sk:?} pk={pk:?}");
            Ok((sk, pk))
        }

        #[allow(clippy::unnecessary_wraps)]
        pub fn derive_key_pair(kem: Kem, ikm: &[u8]) -> Res<(PrivateKey, PublicKey)> {
            let (sk, pk) = match kem {
                $(
                    $kem_id => {
                        let (sk, pk) = <$kem>::derive_keypair(ikm);
                        (PrivateKey::$variant(sk), PublicKey::$variant(pk))
                    }
                )*
            };
            trace!("Derived key pair: sk={sk:?} pk={pk:?}");
            Ok((sk, pk))
        }
    };
}

hpke_kems! {
    { Kem::X25519Sha256, X25519HkdfSha256, X25519 },
    { Kem::P256Sha256, DhP256HkdfSha256, P256 },
    { Kem::P384Sha384, DhP384HkdfSha384, P384 },
    { Kem::P521Sha512, DhP521HkdfSha512, P521 },
    { Kem::XWing, XWing, XWing },
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(b) = self.key_data() {
            write!(f, "PublicKey {}", hex::encode(b))
        } else {
            write!(f, "Opaque PublicKey")
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if cfg!(feature = "unsafe-print-secrets") {
            if let Ok(b) = self.key_data() {
                return write!(f, "PrivateKey {}", hex::encode(b));
            }
        }
        write!(f, "Opaque PrivateKey")
    }
}

/// Generate the flat `SenderContext`/`ReceiverContext` enums (one variant per
/// supported KEM×AEAD combination; the KDF is always `HkdfSha256`), their
/// seal/open/export operations, and the `HpkeS::new`/`HpkeR::new` dispatch, all
/// from a single list.  Each row is
/// `{ <variant>, <ohttp Kem id>, <rust-hpke Kem type>, <ohttp Aead id>, <rust-hpke Aead type>, <PublicKey variant>, <PrivateKey variant> }`.
macro_rules! hpke_contexts {
    {
        $( {
            $variant:ident,
            $kem_id:path, $kem:path,
            $aead_id:path, $aead:path,
            $pk:path, $sk:path $(,)?
        } ),* $(,)?
    } => {
        enum SenderContext {
            $( $variant(Box<AeadCtxS<$aead, HkdfSha256, $kem>>), )*
        }

        impl SenderContext {
            fn seal(&mut self, plaintext: &mut [u8], aad: &[u8]) -> Res<Vec<u8>> {
                let buf = InOutBuf::from(plaintext);
                Ok(match self {
                    $(
                        Self::$variant(context) => {
                            let tag = context.seal_inout_detached(buf, aad)?;
                            Vec::from(tag.to_bytes().as_slice())
                        }
                    )*
                })
            }

            fn export(&self, info: &[u8], out_buf: &mut [u8]) -> Res<()> {
                match self {
                    $(
                        Self::$variant(context) => {
                            context.export(info, out_buf)?;
                        }
                    )*
                }
                Ok(())
            }
        }

        impl HpkeS {
            /// Create a new context that uses the KEM mode for sending.
            pub fn new(config: Config, pk_r: &PublicKey, info: &[u8]) -> Res<Self> {
                let (context, enc) = match (config, pk_r) {
                    $(
                        (
                            Config { kem: $kem_id, kdf: Kdf::HkdfSha256, aead: $aead_id },
                            $pk(pk_r),
                        ) => {
                            let (enc, context) =
                                setup_sender::<$aead, HkdfSha256, $kem>(&OpModeS::Base, pk_r, info)?;
                            (
                                SenderContext::$variant(Box::new(context)),
                                Vec::from(enc.to_bytes().as_slice()),
                            )
                        }
                    )*
                    _ => return Err(Error::InvalidKeyType),
                };
                Ok(Self {
                    context,
                    enc,
                    config,
                })
            }
        }

        enum ReceiverContext {
            $( $variant(Box<AeadCtxR<$aead, HkdfSha256, $kem>>), )*
        }

        impl ReceiverContext {
            fn open<'a>(&mut self, ciphertext: &'a mut [u8], aad: &[u8]) -> Res<&'a [u8]> {
                Ok(match self {
                    $(
                        Self::$variant(context) => {
                            if ciphertext.len() < AeadTag::<$aead>::size() {
                                return Err(Error::Truncated);
                            }
                            let (ct, tag_slice) = ciphertext
                                .split_at_mut(ciphertext.len() - AeadTag::<$aead>::size());
                            let mut ct = InOutBuf::from(ct);
                            let tag = AeadTag::<$aead>::from_bytes(tag_slice)?;
                            context.open_inout_detached(ct.reborrow(), aad, &tag)?;
                            ct.into_out()
                        }
                    )*
                })
            }

            fn export(&self, info: &[u8], out_buf: &mut [u8]) -> Res<()> {
                match self {
                    $(
                        Self::$variant(context) => {
                            context.export(info, out_buf)?;
                        }
                    )*
                }
                Ok(())
            }
        }

        impl HpkeR {
            /// Create a new context that uses the KEM mode for receiving.
            #[allow(clippy::similar_names)]
            pub fn new(
                config: Config,
                _pk_r: &PublicKey,
                sk_r: &PrivateKey,
                enc: &[u8],
                info: &[u8],
            ) -> Res<Self> {
                let context = match (config, sk_r) {
                    $(
                        (
                            Config { kem: $kem_id, kdf: Kdf::HkdfSha256, aead: $aead_id },
                            $sk(sk_r),
                        ) => {
                            let enc = <$kem as KemTrait>::EncappedKey::from_bytes(enc)?;
                            let context = setup_receiver::<$aead, HkdfSha256, $kem>(
                                &OpModeR::Base,
                                sk_r,
                                &enc,
                                info,
                            )?;
                            ReceiverContext::$variant(Box::new(context))
                        }
                    )*
                    _ => return Err(Error::InvalidKeyType),
                };
                Ok(Self { context, config })
            }
        }
    };
}

hpke_contexts! {
    { X25519Aes128, Kem::X25519Sha256, X25519HkdfSha256, Aead::Aes128Gcm, AesGcm128, PublicKey::X25519, PrivateKey::X25519 },
    { X25519ChaCha, Kem::X25519Sha256, X25519HkdfSha256, Aead::ChaCha20Poly1305, ChaCha20Poly1305, PublicKey::X25519, PrivateKey::X25519 },
    { P256Aes128, Kem::P256Sha256, DhP256HkdfSha256, Aead::Aes128Gcm, AesGcm128, PublicKey::P256, PrivateKey::P256 },
    { P256ChaCha, Kem::P256Sha256, DhP256HkdfSha256, Aead::ChaCha20Poly1305, ChaCha20Poly1305, PublicKey::P256, PrivateKey::P256 },
    { P384Aes128, Kem::P384Sha384, DhP384HkdfSha384, Aead::Aes128Gcm, AesGcm128, PublicKey::P384, PrivateKey::P384 },
    { P384ChaCha, Kem::P384Sha384, DhP384HkdfSha384, Aead::ChaCha20Poly1305, ChaCha20Poly1305, PublicKey::P384, PrivateKey::P384 },
    { P521Aes128, Kem::P521Sha512, DhP521HkdfSha512, Aead::Aes128Gcm, AesGcm128, PublicKey::P521, PrivateKey::P521 },
    { P521ChaCha, Kem::P521Sha512, DhP521HkdfSha512, Aead::ChaCha20Poly1305, ChaCha20Poly1305, PublicKey::P521, PrivateKey::P521 },
    { XWingAes128, Kem::XWing, XWing, Aead::Aes128Gcm, AesGcm128, PublicKey::XWing, PrivateKey::XWing },
    { XWingChaCha, Kem::XWing, XWing, Aead::ChaCha20Poly1305, ChaCha20Poly1305, PublicKey::XWing, PrivateKey::XWing },
}

#[allow(clippy::module_name_repetitions)]
pub struct HpkeS {
    context: SenderContext,
    enc: Vec<u8>,
    config: Config,
}

impl HpkeS {
    pub fn config(&self) -> Config {
        self.config
    }

    /// Get the encapsulated KEM secret.
    #[allow(clippy::unnecessary_wraps)]
    pub fn enc(&self) -> Res<Vec<u8>> {
        Ok(self.enc.clone())
    }
}

impl Encrypt for HpkeS {
    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        let mut buf = pt.to_owned();
        let mut tag = self.context.seal(&mut buf, aad)?;
        buf.append(&mut tag);
        Ok(buf)
    }

    fn alg(&self) -> Aead {
        self.config.aead()
    }
}

impl Exporter for HpkeS {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        let mut buf = vec![0; len];
        self.context.export(info, &mut buf)?;
        Ok(SymKey::from(buf))
    }
}

impl Deref for HpkeS {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct HpkeR {
    context: ReceiverContext,
    config: Config,
}

impl HpkeR {
    pub fn config(&self) -> Config {
        self.config
    }
}

impl Decrypt for HpkeR {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>> {
        let mut buf = ct.to_owned();
        let pt_len = self.context.open(&mut buf, aad)?.len();
        buf.truncate(pt_len);
        Ok(buf)
    }

    fn alg(&self) -> Aead {
        self.config.aead()
    }
}

impl Exporter for HpkeR {
    fn export(&self, info: &[u8], len: usize) -> Res<SymKey> {
        let mut buf = vec![0; len];
        self.context.export(info, &mut buf)?;
        Ok(SymKey::from(buf))
    }
}

impl Deref for HpkeR {
    type Target = Config;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[cfg(test)]
mod test {
    use super::{Config, HpkeR, HpkeS, generate_key_pair};
    use crate::{
        crypto::{Decrypt, Encrypt},
        hpke::{Aead, Kem},
        init,
    };

    const INFO: &[u8] = b"info";
    const AAD: &[u8] = b"aad";
    const PT: &[u8] = b"message";

    #[allow(clippy::similar_names)] // for sk_x and pk_x
    #[test]
    fn make() {
        init();
        let cfg = Config::default();
        let (sk_r, pk_r) = generate_key_pair(cfg.kem()).unwrap();
        let hpke_s = HpkeS::new(cfg, &pk_r, INFO).unwrap();
        let _hpke_r = HpkeR::new(cfg, &pk_r, &sk_r, &hpke_s.enc().unwrap(), INFO).unwrap();
    }

    #[allow(clippy::similar_names)] // for sk_x and pk_x
    fn seal_open(aead: Aead, kem: Kem) {
        // Setup
        init();
        let cfg = Config {
            kem,
            aead,
            ..Config::default()
        };
        assert!(cfg.supported());
        let (sk_r, pk_r) = generate_key_pair(cfg.kem()).unwrap();

        // Send
        let mut hpke_s = HpkeS::new(cfg, &pk_r, INFO).unwrap();
        let enc = hpke_s.enc().unwrap();
        let ct = hpke_s.seal(AAD, PT).unwrap();

        // Receive
        let mut hpke_r = HpkeR::new(cfg, &pk_r, &sk_r, &enc, INFO).unwrap();
        let pt = hpke_r.open(AAD, &ct).unwrap();
        assert_eq!(&pt[..], PT);
    }

    #[test]
    fn seal_open_gcm() {
        seal_open(Aead::Aes128Gcm, Kem::X25519Sha256);
    }

    #[test]
    fn seal_open_chacha() {
        seal_open(Aead::ChaCha20Poly1305, Kem::X25519Sha256);
    }

    #[test]
    fn seal_open_gcm_p256() {
        seal_open(Aead::Aes128Gcm, Kem::P256Sha256);
    }

    #[test]
    fn seal_open_chacha_p256() {
        seal_open(Aead::ChaCha20Poly1305, Kem::P256Sha256);
    }

    #[test]
    fn seal_open_gcm_p384() {
        seal_open(Aead::Aes128Gcm, Kem::P384Sha384);
    }

    #[test]
    fn seal_open_chacha_p384() {
        seal_open(Aead::ChaCha20Poly1305, Kem::P384Sha384);
    }

    #[test]
    fn seal_open_gcm_p521() {
        seal_open(Aead::Aes128Gcm, Kem::P521Sha512);
    }

    #[test]
    fn seal_open_chacha_p521() {
        seal_open(Aead::ChaCha20Poly1305, Kem::P521Sha512);
    }

    #[test]
    fn seal_open_gcm_xwing() {
        seal_open(Aead::Aes128Gcm, Kem::XWing);
    }

    #[test]
    fn seal_open_chacha_xwing() {
        seal_open(Aead::ChaCha20Poly1305, Kem::XWing);
    }
}
