//! Asynchronous streaming conversion between HTTP types and BHTTP format.
//!
//! This module provides asynchronous streaming encoders and decoders for converting between
//! `http::Request`/`http::Response` and BHTTP format using streams.
//!
//! The encoding functionality allows you to convert HTTP requests and responses into
//! BHTTP binary format through an asynchronous stream. The decoding functionality allows
//! you to convert BHTTP binary data back into HTTP requests or responses.
//!
//! Both encoding and decoding operations are performed asynchronously, making them
//! suitable for use in async contexts such as with the axum web framework.
pub mod decode;
pub mod encode;