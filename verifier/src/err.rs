use base64::DecodeError;
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("an internal error occurred")]
    Internal,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("openssl error: {0}")]
    ErrorStack(#[from] openssl::error::ErrorStack),
    #[error("hex error: {0}")]
    HexError(#[from] FromHexError),
    #[error("base64 decode error: {0}")]
    DecodeError(#[from] DecodeError),
}

pub type Res<T> = Result<T, Error>;
