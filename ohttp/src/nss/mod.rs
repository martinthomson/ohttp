#![allow(clippy::incompatible_msrv)] // This feature needs 1.70

pub mod aead;
pub mod hkdf;
pub mod hpke;

pub use nss_rs::{PrivateKey, PublicKey, SymKey, init};

pub fn random(n: usize) -> Vec<u8> {
    let mut buf = vec![0; n];
    nss_rs::randomize(&mut buf);
    buf
}
