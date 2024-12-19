#![allow(clippy::incompatible_msrv)] // Until I can make MSRV conditional on feature choice.

use std::{
    cmp::min,
    io::{Error as IoError, Result as IoResult},
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};

use crate::{
    build_info, entropy, err::Res, export_secret, make_aead, Aead, Error, HpkeConfig, HpkeR, HpkeS,
    KeyConfig, KeyId, Mode, PublicKey, SymKey, REQUEST_HEADER_LEN,
};

/// The info string for a chunked request.
pub(crate) const INFO_REQUEST: &[u8] = b"message/bhttp chunked request";
/// The exporter label for a chunked response.
pub(crate) const LABEL_RESPONSE: &[u8] = b"message/bhttp chunked response";
/// The length of the plaintext of the largest chunk that is permitted.
const MAX_CHUNK_PLAINTEXT: usize = 1 << 14;
const CHUNK_AAD: &[u8] = b"";
const FINAL_CHUNK_AAD: &[u8] = b"final";

fn write_len(w: &mut [u8], len: usize) -> &[u8] {
    let v: u64 = len.try_into().unwrap();
    let (v, len) = match () {
        () if v < (1 << 6) => (v, 1),
        () if v < (1 << 14) => (v | 1 << 14, 2),
        () if v < (1 << 30) => (v | (2 << 30), 4),
        () if v < (1 << 62) => (v | (3 << 62), 8),
        () => panic!("varint value too large"),
    };
    w[..len].copy_from_slice(&v.to_be_bytes()[(8 - len)..]);
    &w[..len]
}

#[pin_project::pin_project(project = ClientProjection)]
pub struct ClientRequest<S> {
    #[pin]
    dst: S,
    hpke: HpkeS,
    buf: Vec<u8>,
}

impl<S> ClientRequest<S> {
    /// Start the processing of a stream.
    pub fn start(dst: S, config: HpkeConfig, key_id: KeyId, mut pk: PublicKey) -> Res<Self> {
        let info = build_info(INFO_REQUEST, key_id, config)?;
        let hpke = HpkeS::new(config, &mut pk, &info)?;

        let mut header = Vec::from(&info[INFO_REQUEST.len() + 1..]);
        debug_assert_eq!(header.len(), REQUEST_HEADER_LEN);

        let mut e = hpke.enc()?;
        header.append(&mut e);

        Ok(Self {
            dst,
            hpke,
            buf: header,
        })
    }

    /// Get an object that can be used to process the response.
    ///
    /// While this can be used while sending the request,
    /// doing so creates a risk of revealing unwanted information to the gateway.
    /// That includes the round trip time between client and gateway,
    /// which might reveal information about the location of the client.
    pub fn response<R>(&self, src: R) -> Res<ClientResponse<R>> {
        let enc = self.hpke.enc()?;
        let secret = export_secret(&self.hpke, LABEL_RESPONSE, self.hpke.config())?;
        Ok(ClientResponse {
            src,
            config: self.hpke.config(),
            state: ClientResponseState::Header {
                enc,
                secret,
                nonce: [0; 16],
                read: 0,
            },
        })
    }
}

impl<S: AsyncRead> AsyncRead for ClientRequest<S> {
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
            // Use the provided buffer, but cap the amount we read to MAX_CHUNK_PLAINTEXT.
            let read_len = min(buf.len(), MAX_CHUNK_PLAINTEXT);
            &mut buf[8..read_len]
        } else {
            &mut tmp[..]
        };
        let (aad, len): (&[u8], _) = match this.dst.poll_read(cx, read_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(0)) => (FINAL_CHUNK_AAD, 0),
            Poll::Ready(Ok(len)) => (&[], len),
            e @ Poll::Ready(Err(_)) => return e,
        };

        let ct = this
            .hpke
            .seal(aad, &read_buf[..len])
            .map_err(IoError::other)?;

        // Now we need to write the length of the chunk.
        let len_len = write_len(&mut tmp, ct.len()).len();
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

impl<S: AsyncWrite> ClientRequest<S> {
    /// Flush our buffer.
    /// Returns `Some` if the flush blocks or is unsuccessful.
    /// If that contains `Ready`, it does so only when there is an error.
    fn flush(this: &mut ClientProjection<'_, S>, cx: &mut Context<'_>) -> Option<Poll<IoError>> {
        while !this.buf.is_empty() {
            match this.dst.as_mut().poll_write(cx, &this.buf[..]) {
                Poll::Pending => return Some(Poll::Pending),
                Poll::Ready(Ok(len)) => {
                    if len < this.buf.len() {
                        // We've written something to the underlying writer,
                        // which is probably blocked.
                        // We could return `Poll::Pending`,
                        // but that would mean taking responsibility
                        // for calling `cx.waker().wake()`
                        // when more space comes available.
                        //
                        // So, rather than do that, loop.
                        // If the underlying writer is truly blocked,
                        // it assumes responsibility for waking the task.
                        *this.buf = this.buf.split_off(len);
                    } else {
                        this.buf.clear();
                    }
                }
                Poll::Ready(Err(e)) => return Some(Poll::Ready(e)),
            }
        }
        None
    }

    fn write_chunk(
        this: &mut ClientProjection<'_, S>,
        cx: &mut Context<'_>,
        input: &[u8],
        last: bool,
    ) -> Poll<IoResult<usize>> {
        let aad = if last { FINAL_CHUNK_AAD } else { CHUNK_AAD };
        let mut ct = this.hpke.seal(aad, input).map_err(IoError::other)?;
        let (len, written) = if last {
            (0, 0)
        } else {
            (ct.len(), input.len())
        };

        let mut len_buf = [0; 8];
        let len = write_len(&mut len_buf[..], len);
        let w = match this.dst.as_mut().poll_write(cx, len) {
            Poll::Pending => 0,
            Poll::Ready(Ok(w)) => w,
            e @ Poll::Ready(Err(_)) => return e,
        };

        if w < len.len() {
            this.buf.extend_from_slice(&len[w..]);
            this.buf.append(&mut ct);
        } else {
            match this.dst.as_mut().poll_write(cx, &ct[..]) {
                Poll::Pending => {
                    *this.buf = ct;
                }
                Poll::Ready(Ok(w)) => {
                    *this.buf = ct.split_off(w);
                }
                e @ Poll::Ready(Err(_)) => return e,
            }
        }
        Poll::Ready(Ok(written))
    }
}

impl<S: AsyncWrite> AsyncWrite for ClientRequest<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<IoResult<usize>> {
        let mut this = self.project();
        // We have buffered data, so dump it into the output directly.
        if let Some(value) = Self::flush(&mut this, cx) {
            return value.map(Err);
        }

        // Now encipher a chunk.
        let len = min(input.len(), MAX_CHUNK_PLAINTEXT);
        Self::write_chunk(&mut this, cx, &input[..len], false)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let mut this = self.project();
        if let Some(p) = Self::flush(&mut this, cx) {
            // Flushing our buffers either blocked or failed.
            p.map(Err)
        } else {
            this.dst.as_mut().poll_flush(cx)
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Self::write_chunk(&mut self.project(), cx, &[], true).map(|p| p.map(|_| ()))
    }
}

enum ChunkState {
    Length {
        len: [u8; 8],
        offset: usize,
    },
    Data {
        buf: Vec<u8>,
        offset: usize,
        length: usize,
    },
    Done,
}

impl ChunkState {
    fn length() -> Self {
        Self::Length {
            len: [0; 8],
            offset: 0,
        }
    }

    fn data(length: usize) -> Self {
        // Avoid use `with_capacity` here.  Only allocate when necessary.
        // We might be able to into the buffer we're given instead, to save an allocation.
        Self::Data {
            buf: Vec::new(),
            // Note that because we're allocating the full chunk,
            // we need to track what has been used.
            offset: 0,
            length,
        }
    }
}

#[allow(dead_code)] // TODO
enum ServerRequestState {
    HpkeConfig {
        config: KeyConfig,
        buf: [u8; 7],
        read: usize,
    },
    Enc {
        config: HpkeConfig,
        info: Vec<u8>,
        buf: Vec<u8>,
    },
    Body {
        hpke: HpkeR,
        state: ChunkState,
    },
}

#[pin_project::pin_project(project = ServerRequestProjection)]
pub struct ServerRequest<S> {
    #[pin]
    src: S,
    state: ServerRequestState,
}

impl<S> ServerRequest<S> {
    pub fn new(config: KeyConfig, src: S) -> Self {
        Self {
            src,
            state: ServerRequestState::HpkeConfig {
                config,
                buf: [0; 7],
                read: 0,
            },
        }
    }
}

enum ClientResponseState {
    Header {
        enc: Vec<u8>,
        secret: SymKey,
        nonce: [u8; 16],
        read: usize,
    },
    Body {
        aead: Aead,
        state: ChunkState,
    },
}

impl ClientResponseState {
    fn done(&self) -> bool {
        matches!(
            self,
            Self::Body {
                state: ChunkState::Done,
                ..
            }
        )
    }
}

#[pin_project::pin_project(project = ClientResponseProjection)]
pub struct ClientResponse<S> {
    #[pin]
    src: S,
    config: HpkeConfig,
    state: ClientResponseState,
}

impl<S: AsyncRead> ClientResponse<S> {
    fn read_nonce(
        this: &mut ClientResponseProjection<'_, S>,
        cx: &mut Context<'_>,
    ) -> Option<Poll<IoResult<usize>>> {
        if let ClientResponseState::Header {
            enc,
            secret,
            nonce,
            read,
        } = &mut this.state
        {
            let aead = match this.src.as_mut().poll_read(cx, &mut nonce[*read..]) {
                Poll::Pending => return Some(Poll::Pending),
                Poll::Ready(Ok(0)) => {
                    return Some(Poll::Ready(Err(IoError::other(Error::Truncated))))
                }
                Poll::Ready(Ok(len)) => {
                    *read += len;
                    if *read < entropy(*this.config) {
                        return Some(Poll::Pending);
                    }
                    match make_aead(
                        Mode::Decrypt,
                        *this.config,
                        secret,
                        mem::take(enc),
                        &nonce[..entropy(*this.config)],
                    ) {
                        Ok(aead) => aead,
                        Err(e) => return Some(Poll::Ready(Err(IoError::other(e)))),
                    }
                }
                e @ Poll::Ready(Err(_)) => return Some(e),
            };

            *this.state = ClientResponseState::Body {
                aead,
                state: ChunkState::length(),
            };
        };
        None
    }

    fn read_length(
        this: &mut ClientResponseProjection<'_, S>,
        cx: &mut Context<'_>,
    ) -> Option<Poll<IoResult<usize>>> {
        if let ClientResponseState::Body { aead: _, state } = this.state {
            // Read the first byte.
            if let ChunkState::Length { len, offset } = state {
                if *offset == 0 {
                    match this.src.as_mut().poll_read(cx, &mut len[..1]) {
                        Poll::Pending => return Some(Poll::Pending),
                        Poll::Ready(Ok(0)) => {
                            return Some(Poll::Ready(Err(IoError::other(Error::Truncated))));
                        }
                        Poll::Ready(Ok(1)) => {
                            let form = len[0] >> 6;
                            if form == 0 {
                                *state = ChunkState::data(usize::from(len[0]));
                            } else {
                                let v = mem::replace(&mut len[0], 0) & 0x3f;
                                let i = match form {
                                    1 => 6,
                                    2 => 4,
                                    3 => 0,
                                    _ => unreachable!(),
                                };
                                len[i] = v;
                                *offset = i + 1;
                            }
                        }
                        Poll::Ready(Ok(_)) => unreachable!(),
                        e @ Poll::Ready(Err(_)) => return Some(e),
                    }
                }
            }

            // Read any remaining bytes of the length.
            if let ChunkState::Length { len, offset } = state {
                if *offset != 0 {
                    *state = match this.src.as_mut().poll_read(cx, &mut len[*offset..]) {
                        Poll::Pending => return Some(Poll::Pending),
                        Poll::Ready(Ok(0)) => {
                            return Some(Poll::Ready(Err(IoError::other(Error::Truncated))));
                        }
                        Poll::Ready(Ok(r)) => {
                            *offset += r;
                            if *offset < 8 {
                                return Some(Poll::Pending);
                            }
                            let remaining = match usize::try_from(u64::from_be_bytes(*len)) {
                                Ok(remaining) => remaining,
                                Err(e) => return Some(Poll::Ready(Err(IoError::other(e)))),
                            };
                            if remaining > MAX_CHUNK_PLAINTEXT + this.config.aead().n_t() {
                                return Some(Poll::Ready(Err(IoError::other(
                                    Error::ChunkTooLarge,
                                ))));
                            }
                            ChunkState::data(remaining)
                        }
                        e @ Poll::Ready(Err(_)) => return Some(e),
                    };
                }
            }
        }

        None
    }

    /// Optional optimization that reads a single chunk into the output buffer.
    fn read_into_output(
        this: &mut ClientResponseProjection<'_, S>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Option<Poll<IoResult<usize>>> {
        if let ClientResponseState::Body { aead, state } = this.state {
            if let ChunkState::Data {
                buf,
                offset,
                length,
            } = state
            {
                if *length > 0 && *offset == 0 && output.len() + this.config.aead().n_t() >= *length
                {
                    match this.src.as_mut().poll_read(cx, output) {
                        Poll::Pending => return Some(Poll::Pending),
                        Poll::Ready(Ok(0)) => {
                            return Some(Poll::Ready(Err(IoError::other(Error::Truncated))));
                        }
                        Poll::Ready(Ok(r)) => {
                            if r < *length {
                                buf.extend_from_slice(&output[..r]);
                                *offset += r;
                                return Some(Poll::Pending);
                            }

                            let pt = match aead.open(CHUNK_AAD, &output[..r]) {
                                Ok(pt) => pt,
                                Err(e) => return Some(Poll::Ready(Err(IoError::other(e)))),
                            };
                            output[..pt.len()].copy_from_slice(&pt);
                            *state = ChunkState::length();
                            return Some(Poll::Ready(Ok(pt.len())));
                        }
                        e @ Poll::Ready(Err(_)) => return Some(e),
                    }
                }
            }
        }

        None
    }
}

impl<S: AsyncRead> AsyncRead for ClientResponse<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let mut this = self.project();
        if let Some(res) = Self::read_nonce(&mut this, cx) {
            return res;
        }

        while !this.state.done() {
            if let Some(res) = Self::read_length(&mut this, cx) {
                return res;
            }

            // Read data.
            if let Some(res) = Self::read_into_output(&mut this, cx, output) {
                return res;
            }

            if let ClientResponseState::Body { aead, state } = this.state {
                if let ChunkState::Data {
                    buf,
                    offset,
                    length,
                } = state
                {
                    // Allocate now as needed.
                    let last = *length == 0;
                    if buf.is_empty() {
                        let sz = if last {
                            MAX_CHUNK_PLAINTEXT + this.config.aead().n_t()
                        } else {
                            *length
                        };
                        buf.resize(sz, 0);
                    }

                    let aad = match this.src.as_mut().poll_read(cx, &mut buf[*offset..]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(0)) => {
                            if !last {
                                return Poll::Ready(Err(IoError::other(Error::Truncated)));
                            }

                            FINAL_CHUNK_AAD
                        }
                        Poll::Ready(Ok(r)) => {
                            if *offset + r < *length {
                                buf.extend_from_slice(&output[..r]);
                                *offset += r;
                                return Poll::Pending;
                            }

                            CHUNK_AAD
                        }
                        e @ Poll::Ready(Err(_)) => return e,
                    };

                    let pt = aead.open(aad, buf).map_err(IoError::other)?;
                    output[..pt.len()].copy_from_slice(&pt);
                    *state = if last {
                        ChunkState::Done
                    } else {
                        ChunkState::length()
                    };
                    if !pt.is_empty() {
                        return Poll::Ready(Ok(pt.len()));
                    }
                }
            }
        }
        Poll::Ready(Ok(0))
    }
}

#[cfg(test)]
mod test {
    use futures::{io::Cursor, AsyncReadExt, AsyncWriteExt};
    use log::trace;
    use sync_async::{SyncRead, SyncResolve};

    use crate::{
        test::{init, make_config, REQUEST, RESPONSE},
        ClientRequest, Server,
    };

    #[test]
    fn request_response() {
        init();

        let server_config = make_config();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (mut request_read, request_write) = AsyncReadExt::split(Cursor::new(Vec::new()));
        let mut client_request = client.encapsulate_stream(request_write).unwrap();
        client_request.write_all(REQUEST).sync_resolve().unwrap();
        client_request.close().sync_resolve().unwrap();

        trace!("Request: {}", hex::encode(REQUEST));
        let request_buf = request_read.sync_read_to_end();
        trace!("Encapsulated Request: {}", hex::encode(&request_buf));

        let (request, server_response) = server.decapsulate(&request_buf[..]).unwrap();
        assert_eq!(&request[..], REQUEST);

        let enc_response = server_response.encapsulate(RESPONSE).unwrap();
        trace!("Encapsulated Response: {}", hex::encode(&enc_response));

        let mut client_response = client_request.response(&enc_response[..]).unwrap();

        let response_buf = client_response.sync_read_to_end();
        assert_eq!(response_buf, RESPONSE);
        trace!("Response: {}", hex::encode(response_buf));
    }
}
