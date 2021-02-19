#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)] // I'm too lazy

mod err;
mod nss;
mod rw;

pub use err::Error;
pub use nss::hpke::{AeadId, KdfId, KemId};

use err::Res;
use nss::aead::{Aead, Mode, NONCE_LEN};
use nss::hkdf::{Hkdf, KeyMechanism};
use nss::hpke::{Hpke, HpkeConfig};
use nss::{random, PrivateKey, PublicKey};
use rw::{read_uint, read_uvec, write_uint};
use std::cmp::max;
use std::convert::TryFrom;
use std::io::{BufReader, Read};
use std::mem::size_of;

const INFO_REQUEST: &[u8] = b"request";
const LABEL_RESPONSE: &[u8] = b"response";
const INFO_KEY: &[u8] = b"key";
const INFO_NONCE: &[u8] = b"nonce";

/// The type of a key identifier.
pub type KeyId = u8;

pub fn init() {
    nss::init();
    let _ = env_logger::try_init();
}

/// A tuple of KDF and AEAD identifiers.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymmetricSuite {
    kdf: KdfId::Type,
    aead: AeadId::Type,
}

impl SymmetricSuite {
    #[must_use]
    pub const fn new(kdf: KdfId::Type, aead: AeadId::Type) -> Self {
        Self { kdf, aead }
    }

    #[must_use]
    pub fn kdf(self) -> KdfId::Type {
        self.kdf
    }

    #[must_use]
    pub fn aead(self) -> AeadId::Type {
        self.aead
    }
}

/// The key configuration of a server.  This can be used by both client and server.
/// An important invariant of this structure is that it does not include
/// any combination of KEM, KDF, and AEAD that is not supported.
pub struct KeyConfig {
    key_id: KeyId,
    kem: KemId::Type,
    symmetric: Vec<SymmetricSuite>,
    sk: Option<PrivateKey>,
    pk: PublicKey,
}

impl KeyConfig {
    fn strip_unsupported(symmetric: &mut Vec<SymmetricSuite>, kem: KemId::Type) {
        symmetric.retain(|s| HpkeConfig::new(kem, s.kdf(), s.aead()).supported());
    }

    /// Construct a configuration for the server side.
    /// Panics if the configurations don't include a supported configuration.
    pub fn new(key_id: u8, kem: KemId::Type, mut symmetric: Vec<SymmetricSuite>) -> Res<Self> {
        Self::strip_unsupported(&mut symmetric, kem);
        assert!(!symmetric.is_empty());
        let cfg = HpkeConfig::new(kem, symmetric[0].kdf(), symmetric[0].aead());
        let (sk, pk) = Hpke::new(cfg)?.generate_key_pair()?;
        Ok(Self {
            key_id,
            kem,
            symmetric,
            sk: Some(sk),
            pk,
        })
    }

    /// Encode into a wire format.  This shares a format with the core of ECH:
    ///
    /// ```tls-format
    /// opaque HpkePublicKey[Npk];
    /// uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
    /// uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
    /// uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
    ///
    /// struct {
    ///   HpkeKdfId kdf_id;
    ///   HpkeAeadId aead_id;
    /// } ECHCipherSuite;
    ///
    /// struct {
    ///   uint8 key_id;
    ///   HpkeKemId kem_id;
    ///   HpkePublicKey public_key;
    ///   ECHCipherSuite cipher_suites<4..2^16-4>;
    /// } ECHKeyConfig;
    /// ```
    pub fn encode(&self) -> Res<Vec<u8>> {
        let mut buf = Vec::new();
        write_uint(size_of::<KeyId>(), self.key_id, &mut buf)?;
        write_uint(2, self.kem, &mut buf)?;
        let pk_buf = self.pk.key_data()?;
        buf.extend_from_slice(&pk_buf);
        write_uint(
            2,
            u16::try_from(self.symmetric.len() * 4).unwrap(),
            &mut buf,
        )?;
        for s in &self.symmetric {
            write_uint(2, s.kdf(), &mut buf)?;
            write_uint(2, s.aead(), &mut buf)?;
        }
        Ok(buf)
    }

    /// Construct a configuration from the encoded server configuration.
    /// The format of `encoded_config` is the output of `Self::encode`.
    fn parse(encoded_config: &[u8]) -> Res<Self> {
        let mut r = BufReader::new(encoded_config);
        let key_id = KeyId::try_from(read_uint(size_of::<KeyId>(), &mut r)?).unwrap();
        let kem = KemId::Type::try_from(read_uint(2, &mut r)?).unwrap();

        // Note that the KDF and AEAD doesn't matter here.
        let kem_config = HpkeConfig::new(kem, KdfId::HpkeKdfHkdfSha256, AeadId::HpkeAeadAes128Gcm);
        if !kem_config.supported() {
            return Err(Error::Unsupported);
        }
        let mut pk_buf = vec![0; kem_config.n_pk()];
        r.read_exact(&mut pk_buf)?;

        let sym = read_uvec(2, &mut r)?;
        if sym.is_empty() || (sym.len() % 4 != 0) {
            return Err(Error::Format);
        }
        let sym_count = sym.len() / 4;
        let mut sym_r = BufReader::new(&sym[..]);
        let mut symmetric = Vec::with_capacity(sym_count);
        for _ in 0..sym_count {
            let kdf = KdfId::Type::try_from(read_uint(2, &mut sym_r)?).unwrap();
            let aead = AeadId::Type::try_from(read_uint(2, &mut sym_r)?).unwrap();
            symmetric.push(SymmetricSuite::new(kdf, aead));
        }

        // Check that there was nothing extra.
        let mut tmp = [0; 1];
        if r.read(&mut tmp)? > 0 {
            return Err(Error::Format);
        }

        Self::strip_unsupported(&mut symmetric, kem);
        let hpke = Hpke::new(kem_config)?;
        let pk = hpke.decode_public_key(&pk_buf)?;

        Ok(Self {
            key_id,
            kem,
            symmetric,
            sk: None,
            pk,
        })
    }

    fn create_hpke(&mut self, sym: SymmetricSuite) -> Res<Hpke> {
        if self.symmetric.contains(&sym) {
            let config = HpkeConfig::new(self.kem, sym.kdf(), sym.aead());
            Ok(Hpke::new(config)?)
        } else {
            Err(Error::Unsupported)
        }
    }
}

/// This is the sort of information we expect to receive from the receiver.
/// This might not be necessary if we agree on a format.
#[cfg(feature = "client")]
pub struct ClientRequest {
    key_id: KeyId,
    hpke: Hpke,
}

impl ClientRequest {
    /// Reads an encoded configuration and constructs a single use client sender.
    /// See `KeyConfig::encode` for the structure details.
    #[allow(clippy::similar_names)] // for `sk_s` and `pk_s`
    pub fn new(encoded_config: &[u8]) -> Res<Self> {
        let mut config = KeyConfig::parse(encoded_config)?;

        // TODO(mt) choose the best config, not just the first.
        let mut hpke = config.create_hpke(config.symmetric[0])?;
        let (mut sk_s, pk_s) = hpke.generate_key_pair()?;
        hpke.setup_s(&pk_s, &mut sk_s, &mut config.pk, INFO_REQUEST)?;

        Ok(Self {
            key_id: config.key_id,
            hpke,
        })
    }

    /// Encapsulate a request.  This consumes this object.
    /// This produces a response handler and the bytes of an encapsulated request.
    pub fn encapsulate(mut self, request: &[u8]) -> Res<(Vec<u8>, ClientResponse)> {
        // AAD is keyID + kdfID + aeadID:
        let mut enc_request = Vec::new();
        write_uint(size_of::<KeyId>(), self.key_id, &mut enc_request)?;
        write_uint(2, self.hpke.kem(), &mut enc_request)?;
        write_uint(2, self.hpke.kdf(), &mut enc_request)?;
        write_uint(2, self.hpke.aead(), &mut enc_request)?;

        let mut ct = self.hpke.seal(&enc_request, request)?;
        let enc = self.hpke.enc()?;
        enc_request.extend_from_slice(&enc);
        enc_request.append(&mut ct);
        Ok((enc_request, ClientResponse::new(self.hpke, enc)))
    }
}

/// A server can handle multiple requests.
/// It holds a single key pair and can generate a configuration.
/// (A more complex server would have multiple key pairs. This is simple.)
#[cfg(feature = "server")]
pub struct Server {
    config: KeyConfig,
}

impl Server {
    /// Create a new server configuration.
    /// Panics if the configuration doesn't include a private key.
    pub fn new(config: KeyConfig) -> Res<Self> {
        assert!(config.sk.is_some());
        Ok(Self { config })
    }

    /// Get the configuration that this server uses.
    #[must_use]
    pub fn config(&self) -> &KeyConfig {
        &self.config
    }

    #[allow(clippy::similar_names)] // for kem_id and key_id
    pub fn decapsulate(&mut self, enc_request: &[u8]) -> Res<(Vec<u8>, ServerResponse)> {
        // Can't size_of() for KemId::Type and friends; the AAD covers each of these.
        const AAD_LEN: usize = size_of::<KeyId>() + 6;
        if enc_request.len() < AAD_LEN {
            return Err(Error::Truncated);
        }
        let aad = &enc_request[..AAD_LEN];
        let mut r = BufReader::new(enc_request);
        let key_id = u8::try_from(read_uint(size_of::<KeyId>(), &mut r)?).unwrap();
        if key_id != self.config.key_id {
            return Err(Error::KeyId);
        }
        let kem_id = KemId::Type::try_from(read_uint(2, &mut r)?).unwrap();
        if kem_id != self.config.kem {
            return Err(Error::InvalidKem);
        }
        let kdf_id = KdfId::Type::try_from(read_uint(2, &mut r)?).unwrap();
        let aead_id = AeadId::Type::try_from(read_uint(2, &mut r)?).unwrap();
        let sym = SymmetricSuite::new(kdf_id, aead_id);

        let mut hpke = self.config.create_hpke(sym)?;
        let mut enc = vec![0; hpke.n_enc()];
        r.read_exact(&mut enc)?;
        hpke.setup_r(
            &self.config.pk,
            self.config.sk.as_mut().unwrap(),
            &enc,
            INFO_REQUEST,
        )?;

        let mut ct = Vec::new();
        r.read_to_end(&mut ct)?;

        let request = hpke.open(aad, &ct)?;
        Ok((request, ServerResponse::new(&hpke, enc)?))
    }
}

fn entropy(config: HpkeConfig) -> usize {
    max(config.n_n(), config.n_k())
}

fn make_aead(mode: Mode, hpke: &Hpke, enc: Vec<u8>, response_nonce: &[u8]) -> Res<Aead> {
    let secret = hpke.export(LABEL_RESPONSE, entropy(hpke.config()))?;
    let mut salt = enc;
    salt.extend_from_slice(response_nonce);

    let hkdf = Hkdf::new(hpke.config().kdf());
    let prk = hkdf.extract(&salt, &secret)?;

    let key = hkdf.expand_key(&prk, INFO_KEY, KeyMechanism::Aead(hpke.config().aead()))?;
    let iv = hkdf.expand_data(&prk, INFO_NONCE, hpke.config().n_n())?;
    let nonce_base = <[u8; NONCE_LEN]>::try_from(iv).unwrap();

    Ok(Aead::new(mode, hpke.config().aead(), &key, nonce_base)?)
}

/// An object for encapsulating responses.
/// The only way to obtain one of these is through `Server::decapsulate()`.
#[cfg(feature = "server")]
pub struct ServerResponse {
    response_nonce: Vec<u8>,
    aead: Aead,
}

impl ServerResponse {
    fn new(hpke: &Hpke, enc: Vec<u8>) -> Res<Self> {
        let response_nonce = random(entropy(hpke.config()));
        let aead = make_aead(Mode::Encrypt, hpke, enc, &response_nonce)?;
        Ok(Self {
            response_nonce,
            aead,
        })
    }

    /// Consume this object by encapsulating a response.
    pub fn encapsulate(mut self, response: &[u8]) -> Res<Vec<u8>> {
        let mut enc_response = self.response_nonce;
        let mut ct = self.aead.seal(&[], response)?;
        enc_response.append(&mut ct);
        Ok(enc_response)
    }
}

/// An object for decapsulating responses.
/// The only way to obtain one of these is through `ClientRequest::encapsulate()`.
#[cfg(feature = "client")]
pub struct ClientResponse {
    hpke: Hpke,
    enc: Vec<u8>,
}

impl ClientResponse {
    /// Private method for constructing one of these.
    /// Doesn't do anything because we don't have the nonce yet, so
    /// the work that can be done is limited.
    fn new(hpke: Hpke, enc: Vec<u8>) -> Self {
        Self { hpke, enc }
    }

    /// Consume this object by decapsulating a response.
    pub fn decapsulate(self, enc_response: &[u8]) -> Res<Vec<u8>> {
        let (response_nonce, ct) = enc_response.split_at(entropy(self.hpke.config()));
        let aead = make_aead(Mode::Decrypt, &self.hpke, self.enc, response_nonce)?;
        Ok(aead.open(&[], 0, ct)?) // 0 is the sequence number
    }
}

#[cfg(all(test, feature = "client", feature = "server"))]
mod test {
    use crate::nss::hpke::{AeadId, KdfId, KemId};
    use crate::{ClientRequest, KeyConfig, KeyId, Server, SymmetricSuite};
    use log::trace;

    const KEY_ID: KeyId = 1;
    const KEM: KemId::Type = KemId::HpkeDhKemX25519Sha256;
    const SYMMETRIC: &[SymmetricSuite] = &[
        SymmetricSuite::new(KdfId::HpkeKdfHkdfSha256, AeadId::HpkeAeadAes128Gcm),
        SymmetricSuite::new(KdfId::HpkeKdfHkdfSha256, AeadId::HpkeAeadChaCha20Poly1305),
    ];

    const REQUEST: &[u8] = &[
        0x00, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73, 0x0b, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x01, 0x2f,
    ];
    const RESPONSE: &[u8] = &[0x01, 0x40, 0xc8];

    #[test]
    fn request_response() {
        crate::init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let mut server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        let client = ClientRequest::new(&encoded_config).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();
        trace!("Request: {}", hex::encode(REQUEST));
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let enc_response = server_response.encapsulate(RESPONSE).unwrap();
        trace!("Encapsulated Response: {}", hex::encode(&enc_response));

        let response = client_response.decapsulate(&enc_response).unwrap();
        assert_eq!(&response[..], RESPONSE);
        trace!("Response: {}", hex::encode(RESPONSE));
    }

    #[test]
    fn two_requests() {
        crate::init();

        let server_config = KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap();
        let mut server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();

        let client1 = ClientRequest::new(&encoded_config).unwrap();
        let (enc_request1, client_response1) = client1.encapsulate(REQUEST).unwrap();
        let client2 = ClientRequest::new(&encoded_config).unwrap();
        let (enc_request2, client_response2) = client2.encapsulate(REQUEST).unwrap();
        assert_ne!(enc_request1, enc_request2);

        let (request1, server_response1) = server.decapsulate(&enc_request1).unwrap();
        assert_eq!(&request1[..], REQUEST);
        let (request2, server_response2) = server.decapsulate(&enc_request2).unwrap();
        assert_eq!(&request2[..], REQUEST);

        let enc_response1 = server_response1.encapsulate(RESPONSE).unwrap();
        let enc_response2 = server_response2.encapsulate(RESPONSE).unwrap();
        assert_ne!(enc_response1, enc_response2);

        let response1 = client_response1.decapsulate(&enc_response1).unwrap();
        assert_eq!(&response1[..], RESPONSE);
        let response2 = client_response2.decapsulate(&enc_response2).unwrap();
        assert_eq!(&response2[..], RESPONSE);
    }
}
