#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)] // I'm too lazy

mod err;
mod hex;
mod nss;
mod rw;

pub use err::Error;
pub use nss::init;

use err::Res;
use nss::aead::{Aead, Mode, NONCE_LEN};
use nss::hkdf::{Hkdf, KeyMechanism};
use nss::hpke::{AeadId, Hpke, HpkeConfig, KdfId, KemId};
use nss::{random, PrivateKey, PublicKey};
use rw::{read_uint, read_vec, write_uint, write_vec};
use std::cmp::max;
use std::convert::TryFrom;
use std::io::{BufReader, Read};

const INFO_REQUEST: &[u8] = b"request";
const LABEL_RESPONSE: &[u8] = b"response";
const INFO_KEY: &[u8] = b"key";
const INFO_NONCE: &[u8] = b"nonce";

/// This is the sort of information we expect to receive from the receiver.
/// This might not be necessary if we agree on a format.
pub struct ClientRequest {
    key_id: Vec<u8>,
    hpke: Hpke,
    config: HpkeConfig,
}

impl ClientRequest {
    /// Reads an encoded configuration and constructs a single use client sender.
    /// Structure is:
    /// Config {
    ///   Key ID Length (i),
    ///   Key ID (..),
    ///   KEM (16),
    ///   KDF (16),
    ///   AEAD (16),
    ///   Public Key (..), # no length, this consumes the remainder
    /// }
    #[allow(clippy::similar_names)] // for `sk_s` and `pk_s`
    pub fn new(config: &[u8]) -> Res<Self> {
        let mut r = BufReader::new(config);
        let key_id = read_vec(&mut r)?;

        let kem = KemId::Type::try_from(read_uint(2, &mut r)?).unwrap();
        let kdf = KdfId::Type::try_from(read_uint(2, &mut r)?).unwrap();
        let aead = AeadId::Type::try_from(read_uint(2, &mut r)?).unwrap();
        let config = HpkeConfig::default().kem(kem).kdf(kdf).aead(aead);

        let mut pk_buf = Vec::new();
        let _ = r.read_to_end(&mut pk_buf)?;

        let mut hpke = Hpke::new(config)?;
        let mut pk_r = hpke.decode_public_key(&pk_buf)?;
        let (mut sk_s, pk_s) = hpke.generate_key_pair()?;
        hpke.setup_s(&pk_s, &mut sk_s, &mut pk_r, INFO_REQUEST)?;

        Ok(Self {
            key_id,
            hpke,
            config,
        })
    }

    /// Encapsulate a request.  This consumes this object.
    /// This produces a response handler and the bytes of an encapsulated request.
    pub fn encapsulate(mut self, request: &[u8]) -> Res<(Vec<u8>, ClientResponse)> {
        let mut ct = self.hpke.seal(&self.key_id, request)?;
        let enc = self.hpke.enc()?;
        let mut enc_request = Vec::new();
        write_vec(&self.key_id, &mut enc_request)?;
        enc_request.extend_from_slice(&enc);
        enc_request.append(&mut ct);
        Ok((
            enc_request,
            ClientResponse::new(self.hpke, self.config, enc),
        ))
    }
}

/// A server can handle multiple requests.
/// It holds a single key pair and can generate a configuration.
/// (A more complex server would have multiple key pairs.)
pub struct Server {
    key_id: Vec<u8>,
    config: HpkeConfig,
    sk: PrivateKey,
    pk: PublicKey,
}

impl Server {
    pub fn new(key_id: Vec<u8>, config: HpkeConfig) -> Res<Self> {
        // Create a temporary HPKE for generating a key.
        let (sk, pk) = Hpke::new(config)?.generate_key_pair()?;
        Ok(Self {
            key_id,
            config,
            sk,
            pk,
        })
    }

    pub fn encode_config(&self) -> Res<Vec<u8>> {
        let mut buf = Vec::new();
        write_vec(&self.key_id, &mut buf)?;
        write_uint(2, self.config.get_kem(), &mut buf)?;
        write_uint(2, self.config.get_kdf(), &mut buf)?;
        write_uint(2, self.config.get_aead(), &mut buf)?;
        let mut pk_buf = self.pk.serialize()?;
        buf.append(&mut pk_buf);
        Ok(buf)
    }

    pub fn decapsulate(&mut self, enc_request: &[u8]) -> Res<(Vec<u8>, ServerResponse)> {
        let mut r = BufReader::new(enc_request);
        let key_id = read_vec(&mut r)?;
        if key_id[..] != self.key_id {
            return Err(Error::KeyId);
        }

        let mut hpke = Hpke::new(self.config)?;
        let mut enc = vec![0; self.config.n_enc()];
        r.read_exact(&mut enc)?;
        hpke.setup_r(&self.pk, &mut self.sk, &enc, INFO_REQUEST)?;

        let mut ct = Vec::new();
        r.read_to_end(&mut ct)?;

        let request = hpke.open(&self.key_id, &ct)?;
        Ok((request, ServerResponse::new(&hpke, self.config, enc)?))
    }
}

fn entropy(config: HpkeConfig) -> usize {
    max(config.n_n(), config.n_k())
}

fn make_aead(
    mode: Mode,
    hpke: &Hpke,
    config: HpkeConfig,
    enc: Vec<u8>,
    response_nonce: &[u8],
) -> Res<Aead> {
    let secret = hpke.export(LABEL_RESPONSE, entropy(config))?;
    let mut salt = enc;
    salt.extend_from_slice(response_nonce);

    let hkdf = Hkdf::new(config.get_kdf());
    let prk = hkdf.extract(&salt, &secret)?;

    let key = hkdf.expand_key(&prk, INFO_KEY, KeyMechanism::Aead(config.get_aead()))?;
    let iv = hkdf.expand_data(&prk, INFO_NONCE, config.n_n())?;
    let nonce_base = <[u8; NONCE_LEN]>::try_from(iv).unwrap();

    Ok(Aead::new(mode, config.get_aead(), &key, nonce_base)?)
}

/// An object for encapsulating responses.
/// The only way to obtain one of these is through `Server::decapsulate()`.
pub struct ServerResponse {
    response_nonce: Vec<u8>,
    aead: Aead,
}

impl ServerResponse {
    fn new(hpke: &Hpke, config: HpkeConfig, enc: Vec<u8>) -> Res<Self> {
        let response_nonce = random(entropy(config));
        let aead = make_aead(Mode::Encrypt, &hpke, config, enc, &response_nonce)?;
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
pub struct ClientResponse {
    hpke: Hpke,
    config: HpkeConfig,
    enc: Vec<u8>,
}

impl ClientResponse {
    /// Private method for constructing one of these.
    /// Doesn't do anything because we don't have the nonce yet, so
    /// the work that can be done is limited.
    fn new(hpke: Hpke, config: HpkeConfig, enc: Vec<u8>) -> Self {
        Self { hpke, config, enc }
    }

    /// Consume this object by decapsulating a response.
    pub fn decapsulate(self, enc_response: &[u8]) -> Res<Vec<u8>> {
        let (response_nonce, ct) = enc_response.split_at(entropy(self.config));
        let aead = make_aead(
            Mode::Decrypt,
            &self.hpke,
            self.config,
            self.enc,
            response_nonce,
        )?;
        Ok(aead.open(&[], 0, ct)?) // 0 is the sequence number
    }
}

#[cfg(test)]
mod test {
    use crate::nss::hpke::HpkeConfig;
    use crate::{ClientRequest, Server};

    const KEY_ID: &[u8] = b"key id";
    const REQUEST: &[u8] = b"why is the sky blue?";
    const RESPONSE: &[u8] = b"because air is blue";

    #[test]
    fn request_response() {
        crate::nss::init();

        let mut server = Server::new(Vec::from(KEY_ID), HpkeConfig::default()).unwrap();
        let server_cfg = server.encode_config().unwrap();

        let client = ClientRequest::new(&server_cfg).unwrap();
        let (enc_request, client_response) = client.encapsulate(REQUEST).unwrap();

        let (request, server_response) = server.decapsulate(&enc_request).unwrap();
        assert_eq!(&request[..], REQUEST);

        let enc_response = server_response.encapsulate(RESPONSE).unwrap();

        let response = client_response.decapsulate(&enc_response).unwrap();
        assert_eq!(&response[..], RESPONSE);
    }
}
