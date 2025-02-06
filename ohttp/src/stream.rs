#![allow(clippy::incompatible_msrv)] // Until I can make MSRV conditional on feature choice.

use std::{
    cmp::min,
    io::{Cursor, Error as IoError, Result as IoResult},
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use pin_project::pin_project;

use crate::{
    build_info,
    crypto::{Decrypt, Encrypt},
    entropy,
    err::Res,
    export_secret, make_aead, random, Aead, Error, HpkeConfig, HpkeR, HpkeS, KeyConfig, KeyId,
    Mode, PublicKey, SymKey, REQUEST_HEADER_LEN,
};

/// The info string for a chunked request.
pub(crate) const INFO_REQUEST: &[u8] = b"message/bhttp chunked request";
/// The exporter label for a chunked response.
pub(crate) const LABEL_RESPONSE: &[u8] = b"message/bhttp chunked response";
/// The length of the plaintext of the largest chunk that is permitted.
const MAX_CHUNK_PLAINTEXT: usize = 1 << 14;
const CHUNK_AAD: &[u8] = b"";
const FINAL_CHUNK_AAD: &[u8] = b"final";

#[allow(clippy::unnecessary_wraps)]
fn ioerror<T, E>(e: E) -> Poll<IoResult<T>>
where
    Error: From<E>,
{
    Poll::Ready(Err(IoError::other(Error::from(e))))
}

#[pin_project(project = ChunkWriterProjection)]
struct ChunkWriter<D, E> {
    #[pin]
    dst: D,
    cipher: E,
    buf: Vec<u8>,
    closed: bool,
}

impl<D, E> ChunkWriter<D, E> {
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
}

impl<D: AsyncWrite, C: Encrypt> ChunkWriter<D, C> {
    /// Flush our buffer.
    /// Returns `Some` if the flush blocks or is unsuccessful.
    /// If that contains `Ready`, it does so only when there is an error.
    fn flush(
        this: &mut ChunkWriterProjection<'_, D, C>,
        cx: &mut Context<'_>,
    ) -> Option<Poll<IoError>> {
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
        this: &mut ChunkWriterProjection<'_, D, C>,
        cx: &mut Context<'_>,
        input: &[u8],
        last: bool,
    ) -> Poll<IoResult<usize>> {
        let aad = if last { FINAL_CHUNK_AAD } else { CHUNK_AAD };
        let mut ct = this.cipher.seal(aad, input).map_err(IoError::other)?;
        let (len, written) = if last {
            (0, 0)
        } else {
            (ct.len(), input.len())
        };

        let mut len_buf = [0; 8];
        let len = Self::write_len(&mut len_buf[..], len);
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

impl<D: AsyncWrite, C: Encrypt> AsyncWrite for ChunkWriter<D, C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<IoResult<usize>> {
        let mut this = self.project();
        if *this.closed {
            return ioerror(Error::WriteAfterClose);
        }

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
        let mut this = self.project();
        if let Some(value) = Self::flush(&mut this, cx) {
            return value.map(Err);
        }

        if !*this.closed {
            *this.closed = true;
            if let Poll::Ready(Err(e)) = Self::write_chunk(&mut this, cx, &[], true) {
                return Poll::Ready(Err(e));
            }
            // `write_chunk` might have buffered some data after being blocked.
            // We have to try to write that out here.
            // If the write was partly successful, the underlying sink (`dst`)
            // won't be responsible for waking `cx`.
            // `flush` forces that to take responsibility for waking.
            if let Some(value) = Self::flush(&mut this, cx) {
                return value.map(Err);
            }
        }
        this.dst.as_mut().poll_close(cx)
    }
}

#[pin_project(project = ClientProjection)]
pub struct ClientRequest<D> {
    #[pin]
    writer: ChunkWriter<D, HpkeS>,
}

impl<D> ClientRequest<D> {
    /// Start the processing of a stream.
    pub fn start(dst: D, config: HpkeConfig, key_id: KeyId, mut pk: PublicKey) -> Res<Self> {
        let info = build_info(INFO_REQUEST, key_id, config)?;
        let hpke = HpkeS::new(config, &mut pk, &info)?;

        let mut header = Vec::from(&info[INFO_REQUEST.len() + 1..]);
        debug_assert_eq!(header.len(), REQUEST_HEADER_LEN);

        let mut e = hpke.enc()?;
        header.append(&mut e);

        Ok(Self {
            writer: ChunkWriter {
                dst,
                cipher: hpke,
                buf: header,
                closed: false,
            },
        })
    }

    /// Get an object that can be used to process the response.
    ///
    /// While this can be used while sending the request,
    /// doing so creates a risk of revealing unwanted information to the gateway.
    /// That includes the round trip time between client and gateway,
    /// which might reveal information about the location of the client.
    pub fn response<R>(&self, src: R) -> Res<ClientResponse<R>> {
        let enc = self.writer.cipher.enc()?;
        let secret = export_secret(
            &self.writer.cipher,
            LABEL_RESPONSE,
            self.writer.cipher.config(),
        )?;
        Ok(ClientResponse {
            src,
            config: self.writer.cipher.config(),
            state: ClientResponseState::Header {
                enc,
                secret,
                nonce: [0; 16],
                read: 0,
            },
        })
    }
}

impl<D: AsyncWrite> AsyncWrite for ClientRequest<D> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<IoResult<usize>> {
        self.project().writer.as_mut().poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().writer.as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().writer.as_mut().poll_close(cx)
    }
}

enum ChunkReader {
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

impl ChunkReader {
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

    fn read_fixed<S: AsyncRead>(
        mut src: Pin<&mut S>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> Option<Poll<IoResult<usize>>> {
        while *offset < buf.len() {
            // Read any remaining bytes of the length.
            match src.as_mut().poll_read(cx, &mut buf[*offset..]) {
                Poll::Pending => return Some(Poll::Pending),
                Poll::Ready(Ok(0)) => {
                    return Some(ioerror(Error::Truncated));
                }
                Poll::Ready(Ok(r)) => {
                    *offset += r;
                }
                e @ Poll::Ready(Err(_)) => return Some(e),
            }
        }
        None
    }

    fn read_length0<S: AsyncRead>(
        &mut self,
        mut src: Pin<&mut S>,
        cx: &mut Context<'_>,
    ) -> Option<Poll<IoResult<usize>>> {
        let Self::Length { len, offset } = self else {
            return None;
        };

        let res = Self::read_fixed(src.as_mut(), cx, &mut len[..1], offset);
        if res.is_some() {
            return res;
        }

        let form = len[0] >> 6;
        if form == 0 {
            *self = Self::data(usize::from(len[0]));
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
        None
    }

    fn read_length<S: AsyncRead, C: Decrypt>(
        &mut self,
        mut src: Pin<&mut S>,
        cx: &mut Context<'_>,
        aead: &mut C,
    ) -> Option<Poll<IoResult<usize>>> {
        // Read the first byte.
        let res = self.read_length0(src.as_mut(), cx);
        if res.is_some() {
            return res;
        }

        let Self::Length { len, offset } = self else {
            return None;
        };

        let res = Self::read_fixed(src.as_mut(), cx, &mut len[..], offset);
        if res.is_some() {
            return res;
        }

        let remaining = match usize::try_from(u64::from_be_bytes(*len)) {
            Ok(remaining) => remaining,
            Err(e) => return Some(ioerror(e)),
        };
        if remaining > MAX_CHUNK_PLAINTEXT + aead.alg().n_t() {
            return Some(ioerror(Error::ChunkTooLarge));
        }

        *self = Self::data(remaining);
        None
    }

    /// Optional optimization that reads a single chunk into the output buffer.
    fn read_into_output<S: AsyncRead, C: Decrypt>(
        &mut self,
        mut src: Pin<&mut S>,
        cx: &mut Context<'_>,
        aead: &mut C,
        output: &mut [u8],
    ) -> Option<Poll<IoResult<usize>>> {
        let Self::Data {
            buf,
            offset,
            length,
        } = self
        else {
            return None;
        };
        if *length == 0 || *offset > 0 || output.len() < *length {
            // We need to pull in a complete chunk in one go for this to be worthwhile.
            return None;
        }

        match src.as_mut().poll_read(cx, &mut output[..*length]) {
            Poll::Pending => Some(Poll::Pending),
            Poll::Ready(Ok(0)) => Some(ioerror(Error::Truncated)),
            Poll::Ready(Ok(r)) => {
                if r == *length {
                    let pt = match aead.open(CHUNK_AAD, &output[..r]) {
                        Ok(pt) => pt,
                        Err(e) => return Some(ioerror(e)),
                    };
                    output[..pt.len()].copy_from_slice(&pt);
                    *self = Self::length();
                    Some(Poll::Ready(Ok(pt.len())))
                } else {
                    buf.reserve_exact(*length);
                    buf.extend_from_slice(&output[..r]);
                    buf.resize(*length, 0);
                    *offset += r;
                    None
                }
            }
            e @ Poll::Ready(Err(_)) => Some(e),
        }
    }

    fn read<S: AsyncRead, C: Decrypt>(
        &mut self,
        mut src: Pin<&mut S>,
        cx: &mut Context<'_>,
        cipher: &mut C,
        output: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        while !matches!(self, Self::Done) {
            if let Some(res) = self.read_length(src.as_mut(), cx, cipher) {
                return res;
            }

            // Read data.
            if let Some(res) = self.read_into_output(src.as_mut(), cx, cipher, output) {
                return res;
            }

            let Self::Data {
                buf,
                offset,
                length,
            } = self
            else {
                unreachable!();
            };

            // Allocate now as needed.
            let last = *length == 0;
            if buf.is_empty() {
                let sz = if last {
                    MAX_CHUNK_PLAINTEXT + cipher.alg().n_t()
                } else {
                    *length
                };
                buf.resize(sz, 0);
            }

            match src.as_mut().poll_read(cx, &mut buf[*offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    if last {
                        buf.truncate(*offset);
                    } else {
                        return ioerror(Error::Truncated);
                    }
                }
                Poll::Ready(Ok(r)) => {
                    *offset += r;
                    if last || *offset < *length {
                        continue; // Keep reading
                    }
                }
                e @ Poll::Ready(Err(_)) => return e,
            }

            let aad = if last { FINAL_CHUNK_AAD } else { CHUNK_AAD };
            let pt = cipher.open(aad, buf).map_err(IoError::other)?;
            output[..pt.len()].copy_from_slice(&pt);

            if last {
                *self = Self::Done;
            } else {
                *self = Self::length();
                if pt.is_empty() {
                    continue; // Read the next chunk
                }
            };

            return Poll::Ready(Ok(pt.len()));
        }

        Poll::Ready(Ok(0))
    }
}

enum ServerRequestState {
    HpkeConfig {
        buf: [u8; 7],
        read: usize,
    },
    Enc {
        config: HpkeConfig,
        info: Vec<u8>,
        read: usize,
    },
    Body {
        hpke: HpkeR,
        state: ChunkReader,
    },
}

#[pin_project(project = ServerRequestProjection)]
pub struct ServerRequest<S> {
    #[pin]
    src: S,
    key_config: KeyConfig,
    enc: Vec<u8>,
    state: ServerRequestState,
}

impl<S> ServerRequest<S> {
    pub fn new(key_config: KeyConfig, src: S) -> Self {
        Self {
            src,
            key_config,
            enc: Vec::new(),
            state: ServerRequestState::HpkeConfig {
                buf: [0; 7],
                read: 0,
            },
        }
    }

    /// Get a response that wraps the given async write instance.
    /// This fails with an error if the request header hasn't been processed.
    /// This condition is not exposed through a future anywhere,
    /// but you can wait for the first byte of data.
    pub fn response<D>(&self, dst: D) -> Res<ServerResponse<D>> {
        let ServerRequestState::Body { hpke, state: _ } = &self.state else {
            return Err(Error::NotReady);
        };

        let response_nonce = random(entropy(hpke.config()));
        let aead = make_aead(
            Mode::Encrypt,
            hpke.config(),
            &export_secret(hpke, LABEL_RESPONSE, hpke.config())?,
            &self.enc,
            &response_nonce,
        )?;
        Ok(ServerResponse {
            writer: ChunkWriter {
                dst,
                cipher: aead,
                buf: response_nonce,
                closed: false,
            },
        })
    }
}

impl<S: AsyncRead> ServerRequest<S> {
    fn read_config(
        this: &mut ServerRequestProjection<'_, S>,
        cx: &mut Context<'_>,
    ) -> Option<Poll<IoResult<usize>>> {
        let ServerRequestState::HpkeConfig { buf, read } = this.state else {
            return None;
        };

        let res = ChunkReader::read_fixed(this.src.as_mut(), cx, &mut buf[..], read);
        if res.is_some() {
            return res;
        }

        let config = match this
            .key_config
            .decode_hpke_config(&mut Cursor::new(&buf[..]))
        {
            Ok(cfg) => cfg,
            Err(e) => return Some(ioerror(e)),
        };
        let info = match build_info(INFO_REQUEST, this.key_config.key_id, config) {
            Ok(info) => info,
            Err(e) => return Some(ioerror(e)),
        };
        this.enc.resize(config.kem().n_enc(), 0);

        *this.state = ServerRequestState::Enc {
            config,
            info,
            read: 0,
        };
        None
    }

    fn read_enc(
        this: &mut ServerRequestProjection<'_, S>,
        cx: &mut Context<'_>,
    ) -> Option<Poll<IoResult<usize>>> {
        let ServerRequestState::Enc { config, info, read } = this.state else {
            return None;
        };

        let res = ChunkReader::read_fixed(this.src.as_mut(), cx, &mut this.enc[..], read);
        if res.is_some() {
            return res;
        }

        let hpke = match HpkeR::new(
            *config,
            &this.key_config.pk,
            this.key_config.sk.as_ref().unwrap(),
            this.enc,
            info,
        ) {
            Ok(hpke) => hpke,
            Err(e) => return Some(ioerror(e)),
        };

        *this.state = ServerRequestState::Body {
            hpke,
            state: ChunkReader::length(),
        };
        None
    }
}

impl<S: AsyncRead> AsyncRead for ServerRequest<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let mut this = self.project();
        if let Some(res) = Self::read_config(&mut this, cx) {
            return res;
        }

        if let Some(res) = Self::read_enc(&mut this, cx) {
            return res;
        }

        if let ServerRequestState::Body { hpke, state } = this.state {
            state.read(this.src, cx, hpke, output)
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

#[pin_project(project = ServerResponseProjection)]
pub struct ServerResponse<D> {
    #[pin]
    writer: ChunkWriter<D, Aead>,
}

impl<D: AsyncWrite> AsyncWrite for ServerResponse<D> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<IoResult<usize>> {
        self.project().writer.as_mut().poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().writer.as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().writer.as_mut().poll_close(cx)
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
        state: ChunkReader,
    },
}

#[pin_project(project = ClientResponseProjection)]
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
        let ClientResponseState::Header {
            enc,
            secret,
            nonce,
            read,
        } = this.state
        else {
            return None;
        };

        let nonce = &mut nonce[..entropy(*this.config)];
        let res = ChunkReader::read_fixed(this.src.as_mut(), cx, nonce, read);
        if res.is_some() {
            return res;
        }

        let aead = match make_aead(Mode::Decrypt, *this.config, secret, enc, nonce) {
            Ok(aead) => aead,
            Err(e) => return Some(ioerror(e)),
        };

        *this.state = ClientResponseState::Body {
            aead,
            state: ChunkReader::length(),
        };
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

        if let ClientResponseState::Body { aead, state } = this.state {
            state.read(this.src, cx, aead, output)
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

#[cfg(test)]
mod test {
    use futures::AsyncWriteExt;
    use log::trace;
    use sync_async::{Dribble, Pipe, Stutter, SyncRead, SyncResolve};

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

        // The client sends a request.
        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (mut request_read, request_write) = Pipe::new();
        let mut client_request = client.encapsulate_stream(request_write).unwrap();
        client_request.write_all(REQUEST).sync_resolve().unwrap();
        client_request.close().sync_resolve().unwrap();

        trace!("Request: {}", hex::encode(REQUEST));
        let enc_request = request_read.sync_read_to_end();
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        // The server receives a request.
        let mut server_request = server.decapsulate_stream(&enc_request[..]);
        assert_eq!(server_request.sync_read_to_end(), REQUEST);

        // The server sends a response.
        let (mut response_read, response_write) = Pipe::new();
        let mut server_response = server_request.response(response_write).unwrap();
        server_response.write_all(RESPONSE).sync_resolve().unwrap();
        server_response.close().sync_resolve().unwrap();

        let enc_response = response_read.sync_read_to_end();
        trace!("Encapsulated Response: {}", hex::encode(&enc_response));

        // The client receives a response.
        let mut client_response = client_request.response(&enc_response[..]).unwrap();
        let response_buf = client_response.sync_read_to_end();
        assert_eq!(response_buf, RESPONSE);
        trace!("Response: {}", hex::encode(response_buf));
    }

    /// Run the `request_response` test, but do it with streams that are one byte apiece.
    #[test]
    fn dribble() {
        init();

        let server_config = make_config();
        let server = Server::new(server_config).unwrap();
        let encoded_config = server.config().encode().unwrap();
        trace!("Config: {}", hex::encode(&encoded_config));

        // The client sends a request.
        let client = ClientRequest::from_encoded_config(&encoded_config).unwrap();
        let (mut request_read, request_write) = Pipe::new();
        let request_write = Stutter::new(Dribble::new(request_write));
        let mut client_request = client.encapsulate_stream(request_write).unwrap();
        client_request.write_all(REQUEST).sync_resolve().unwrap();
        client_request.close().sync_resolve().unwrap();

        trace!("Request: {}", hex::encode(REQUEST));
        let enc_request = request_read.sync_read_to_end();
        trace!("Encapsulated Request: {}", hex::encode(&enc_request));

        // The server receives a request.
        let enc_req_stream = Stutter::new(Dribble::new(&enc_request[..]));
        let mut server_request = server.decapsulate_stream(enc_req_stream);
        assert_eq!(server_request.sync_read_to_end(), REQUEST);

        // The server sends a response.
        let (mut response_read, response_write) = Pipe::new();
        let response_write = Stutter::new(Dribble::new(response_write));
        let mut server_response = server_request.response(response_write).unwrap();
        server_response.write_all(RESPONSE).sync_resolve().unwrap();
        server_response.close().sync_resolve().unwrap();

        let enc_response = response_read.sync_read_to_end();
        trace!("Encapsulated Response: {}", hex::encode(&enc_response));

        // The client receives a response.
        let enc_resp_stream = Stutter::new(Dribble::new(&enc_response[..]));
        let mut client_response = client_request.response(enc_resp_stream).unwrap();
        let response_buf = client_response.sync_read_to_end();
        assert_eq!(response_buf, RESPONSE);
        trace!("Response: {}", hex::encode(response_buf));
    }
}
