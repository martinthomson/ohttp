use std::{
    cmp::min,
    io::{Error as IoError, Result as IoResult},
    pin::Pin,
    task::{Context, Poll},
};

use futures::AsyncRead;

use crate::HpkeS;

pub(crate) const INFO_REQUEST: &[u8] = b"message/bhttp chunked request";

fn write_len(w: &mut [u8], len: usize) -> usize {
    let v: u64 = len.try_into().unwrap();
    let (v, len) = match () {
        () if v < (1 << 6) => (v, 1),
        () if v < (1 << 14) => (v | 1 << 14, 2),
        () if v < (1 << 30) => (v | (2 << 30), 4),
        () if v < (1 << 62) => (v | (3 << 62), 8),
        () => panic!("varint value too large"),
    };
    w[..len].copy_from_slice(&v.to_be_bytes()[(8 - len)..]);
    len
}

#[pin_project::pin_project]
pub struct ClientRequestStream<S> {
    #[pin]
    src: S,
    hpke: HpkeS,
    buf: Vec<u8>,
}

impl<S> ClientRequestStream<S> {
    pub fn new(src: S, hpke: HpkeS, header: Vec<u8>) -> Self {
        Self {
            src,
            hpke,
            buf: header,
        }
    }
}

impl<S: AsyncRead> AsyncRead for ClientRequestStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let this = self.project();
        // We have buffered data, so dump it into the output directly.
        let mut written = if this.buf.is_empty() {
            0
        } else {
            let amnt = min(this.buf.len(), buf.len());
            buf[..amnt].copy_from_slice(&this.buf[..amnt]);
            buf = &mut buf[amnt..];
            *this.buf = this.buf.split_off(amnt);
            if buf.is_empty() {
                return Poll::Ready(Ok(amnt));
            }
            amnt
        };

        // Now read into the buffer.
        // Because we are expanding the data, when the buffer we are provided is too small,
        // we have to use a temporary buffer so that we can save some bytes.
        let mut tmp = [0; 64];
        let read_buf = if buf.len() < tmp.len() {
            // Use the provided buffer, but leave room for AEAD tag and a varint.
            let read_len = min(buf.len(), 1 << 62) - this.hpke.aead().n_t();
            &mut buf[8..read_len]
        } else {
            &mut tmp[..]
        };
        let (aad, len): (&[u8], _) = match this.src.poll_read(cx, read_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(0)) => (&b"final"[..], 0),
            Poll::Ready(Ok(len)) => (&[], len),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        };

        let ct = this
            .hpke
            .seal(aad, &mut read_buf[..len])
            .map_err(IoError::other)?;

        // Now we need to write the length of the chunk.
        let len_len = write_len(&mut tmp, ct.len());
        if len_len <= buf.len() {
            // If the length fits in the buffer, that's easy.
            buf[..len_len].copy_from_slice(&tmp[..len_len]);
            written += len_len;
            buf = &mut buf[len_len..];
        } else {
            // Otherwise, we need to save any remainder in our own buffer.
            buf.copy_from_slice(&tmp[..buf.len()]);
            this.buf.extend_from_slice(&tmp[buf.len()..len_len]);
            let amnt = buf.len();
            written += amnt;
            buf = &mut buf[amnt..];
        }

        let amnt = min(ct.len(), buf.len());
        buf[..amnt].copy_from_slice(&ct[..amnt]);
        this.buf.extend_from_slice(&ct[amnt..]);
        Poll::Ready(Ok(amnt + written))
    }
}
