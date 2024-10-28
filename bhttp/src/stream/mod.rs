#![allow(clippy::incompatible_msrv)] // This module uses features from rust 1.82

use std::{
    cmp::min,
    io::{Cursor, Error as IoError, Result as IoResult},
    mem,
    pin::{pin, Pin},
    task::{Context, Poll},
};

use futures::{stream::unfold, AsyncRead, FutureExt, Stream, TryStreamExt};
use int::ReadVarint;

use crate::{
    err::Res,
    stream::{int::read_varint, vec::read_vec},
    ControlData, Error, Field, FieldSection, Header, InformationalResponse, Message, Mode, COOKIE,
};
#[cfg(test)]
mod future;
mod int;
mod vec;

trait AsyncReadControlData: Sized {
    async fn async_read<S: AsyncRead + Unpin>(request: bool, src: S) -> Res<Self>;
}

impl AsyncReadControlData for ControlData {
    async fn async_read<S: AsyncRead + Unpin>(request: bool, mut src: S) -> Res<Self> {
        let v = if request {
            let method = read_vec(&mut src).await?.ok_or(Error::Truncated)?;
            let scheme = read_vec(&mut src).await?.ok_or(Error::Truncated)?;
            let authority = read_vec(&mut src).await?.ok_or(Error::Truncated)?;
            let path = read_vec(&mut src).await?.ok_or(Error::Truncated)?;
            Self::Request {
                method,
                scheme,
                authority,
                path,
            }
        } else {
            let code = read_varint(&mut src).await?.ok_or(Error::Truncated)?;
            Self::Response(crate::StatusCode::try_from(code)?)
        };
        Ok(v)
    }
}

trait AsyncReadFieldSection: Sized {
    async fn async_read<S: AsyncRead + Unpin>(mode: Mode, src: S) -> Res<Self>;
}

impl AsyncReadFieldSection for FieldSection {
    async fn async_read<S: AsyncRead + Unpin>(mode: Mode, mut src: S) -> Res<Self> {
        let fields = if mode == Mode::KnownLength {
            // Known-length fields can just be read into a buffer.
            if let Some(buf) = read_vec(&mut src).await? {
                Self::read_bhttp_fields(false, &mut Cursor::new(&buf[..]))?
            } else {
                Vec::new()
            }
        } else {
            // The async version needs to be implemented directly.
            let mut fields: Vec<Field> = Vec::new();
            let mut cookie_index: Option<usize> = None;
            loop {
                if let Some(n) = read_vec(&mut src).await? {
                    if n.is_empty() {
                        break fields;
                    }
                    let mut v = read_vec(&mut src).await?.ok_or(Error::Truncated)?;
                    if n == COOKIE {
                        if let Some(i) = &cookie_index {
                            fields[*i].value.extend_from_slice(b"; ");
                            fields[*i].value.append(&mut v);
                            continue;
                        }
                        cookie_index = Some(fields.len());
                    }
                    fields.push(Field::new(n, v));
                } else if fields.is_empty() {
                    break fields;
                } else {
                    return Err(Error::Truncated);
                }
            }
        };
        Ok(Self(fields))
    }
}

#[allow(clippy::mut_mut)] // TODO look into this more.
enum BodyState<'a, 'b, S> {
    // When reading the length, use this.
    // Invariant: This is always `Some`.
    ReadLength(Option<ReadVarint<&'b mut &'a mut S>>),
    // When reading the data, track how much is left.
    // Invariant: `src` is always `Some`.
    ReadData {
        remaining: usize,
        src: Option<&'b mut &'a mut S>,
    },
}

pub struct Body<'a, 'b, S> {
    mode: Mode,
    state: &'b mut AsyncMessageState<'a, 'b, S>,
}

impl<'a, 'b, S> Body<'a, 'b, S> {
    fn set_state(&mut self, s: BodyState<'a, 'b, S>) {
        *self.state = AsyncMessageState::Body(s);
    }

    fn done(&mut self) {
        *self.state = AsyncMessageState::Trailer;
    }
}

impl<'a, 'b, S: AsyncRead + Unpin> AsyncRead for Body<'a, 'b, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        fn poll_error(e: Error) -> Poll<IoResult<usize>> {
            Poll::Ready(Err(IoError::other(e)))
        }

        let mode = self.mode;
        if let AsyncMessageState::Body(BodyState::ReadLength(r)) = &mut self.state {
            match r.as_mut().unwrap().poll_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(Some(0) | None)) => {
                    self.done();
                    return Poll::Ready(Ok(0));
                }
                Poll::Ready(Ok(Some(len))) => {
                    match usize::try_from(len) {
                        Ok(remaining) => {
                            let src = r.take().map(ReadVarint::stream);
                            self.set_state(BodyState::ReadData { remaining, src });
                            // fall through to maybe read the body
                        }
                        Err(e) => return poll_error(Error::IntRange(e)),
                    }
                }
                Poll::Ready(Err(e)) => return poll_error(e),
            }
        }

        if let AsyncMessageState::Body(BodyState::ReadData { remaining, src }) = &mut self.state {
            let amount = min(*remaining, buf.len());
            let res = pin!(src.as_mut().unwrap()).poll_read(cx, &mut buf[..amount]);
            match res {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(0)) => poll_error(Error::Truncated),
                Poll::Ready(Ok(len)) => {
                    *remaining -= len;
                    if *remaining == 0 {
                        if mode == Mode::IndeterminateLength {
                            let src = src.take().map(read_varint);
                            self.set_state(BodyState::ReadLength(src));
                        } else {
                            self.done();
                        }
                    }
                    Poll::Ready(Ok(len))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            }
        } else {
            Poll::Pending
        }
    }
}

enum AsyncMessageState<'a, 'b, S> {
    // Processing Informational responses (or before that).
    Informational,
    // Having obtained the control data for the header, this is it.
    Header(ControlData),
    // Processing the Body.
    Body(BodyState<'a, 'b, S>),
    // Processing the trailer.
    Trailer,
}

pub struct AsyncMessage<'a, 'b, S> {
    // Whether this is a request and which mode.
    framing: Option<(bool, Mode)>,
    state: AsyncMessageState<'a, 'b, S>,
    src: &'a mut S,
}

unsafe impl<S: Send> Send for AsyncMessage<'_, '_, S> {}

impl<'a, 'b, S: AsyncRead + Unpin> AsyncMessage<'a, 'b, S> {
    /// Get the mode.  This panics if the header hasn't been read yet.
    fn mode(&self) -> Mode {
        self.framing.unwrap().1
    }

    async fn next_info(&mut self) -> Res<Option<InformationalResponse>> {
        if !matches!(self.state, AsyncMessageState::Informational) {
            return Ok(None);
        }

        let (request, mode) = if let Some((request, mode)) = self.framing {
            (request, mode)
        } else {
            let t = read_varint(&mut self.src).await?.ok_or(Error::Truncated)?;
            let request = t == 0 || t == 2;
            let mode = Mode::try_from(t)?;
            self.framing = Some((request, mode));
            (request, mode)
        };

        let control = ControlData::async_read(request, &mut self.src).await?;
        if let Some(status) = control.informational() {
            let fields = FieldSection::async_read(mode, &mut self.src).await?;
            Ok(Some(InformationalResponse::new(status, fields)))
        } else {
            self.state = AsyncMessageState::Header(control);
            Ok(None)
        }
    }

    /// Produces a stream of informational responses from a fresh message.
    /// Returns an empty stream if called at other times.
    /// Error values on the stream indicate failures.
    ///
    /// There is no need to call this method to read a request, though
    /// doing so is harmless.
    ///
    /// You can discard the stream that this function returns
    /// without affecting the message.  You can then either call this
    /// method again to get any additional informational responses or
    /// call `header()` to get the message header.
    pub fn informational(
        &mut self,
    ) -> impl Stream<Item = Res<InformationalResponse>> + use<'_, 'a, 'b, S> {
        unfold(self, |this| async move {
            this.next_info().await.transpose().map(|info| (info, this))
        })
    }

    /// This reads the header.  If you have not called `informational`
    /// and drained the resulting stream, this will do that for you.
    pub async fn header(&'b mut self) -> Res<Header> {
        if matches!(self.state, AsyncMessageState::Informational) {
            // Need to scrub for errors,
            // so that this can abort properly if there is one.
            // The `try_any` usage is there to ensure that the stream is fully drained.
            _ = self.informational().try_any(|_| async { false }).await?;
        }
        if matches!(self.state, AsyncMessageState::Header(_)) {
            let mode = self.mode();
            let hfields = FieldSection::async_read(mode, &mut self.src).await?;

            let bs: BodyState<'a, 'b, S> = BodyState::ReadLength(Some(read_varint(&mut self.src)));
            let AsyncMessageState::Header(control) =
                mem::replace(&mut self.state, AsyncMessageState::Body(bs))
            else {
                unreachable!();
            };
            Ok(Header::from((control, hfields)))
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Read the body.
    /// This produces an implementation of `AsyncRead` that filters out
    /// the framing from the message body.
    /// # Errors
    /// This errors when the header has not been read.
    /// Any IO errors are generated by the returned `Body` instance.
    pub fn body(&'b mut self) -> Res<Body<'a, 'b, S>> {
        if matches!(self.state, AsyncMessageState::Body(_)) {
            let mode = self.mode();
            Ok(Body {
                mode,
                state: &mut self.state,
            })
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Read any trailer.
    /// This might be empty.
    /// # Errors
    /// This errors when the body has not been read.
    pub async fn trailer(&mut self) -> Res<FieldSection> {
        if matches!(self.state, AsyncMessageState::Trailer) {
            Ok(FieldSection::async_read(self.mode(), &mut self.src).await?)
        } else {
            Err(Error::InvalidState)
        }
    }
}

pub trait AsyncReadMessage: Sized {
    fn async_read<'b, S: AsyncRead + Unpin>(src: &mut S) -> AsyncMessage<'_, 'b, S>;
}

impl AsyncReadMessage for Message {
    fn async_read<'b, S: AsyncRead + Unpin>(src: &mut S) -> AsyncMessage<'_, 'b, S> {
        AsyncMessage {
            framing: None,
            state: AsyncMessageState::Informational,
            src,
        }
    }
}

#[cfg(test)]
mod test {
    use std::pin::pin;

    use futures::TryStreamExt;

    use crate::{
        stream::{
            future::{SyncCollect, SyncRead, SyncResolve},
            AsyncReadMessage,
        },
        Error, Message,
    };

    // Example from Section 5.1 of RFC 9292.
    const REQUEST1: &[u8] = &[
        0x00, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73, 0x00, 0x0a, 0x2f, 0x68,
        0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x40, 0x6c, 0x0a, 0x75, 0x73, 0x65, 0x72,
        0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x34, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e, 0x31,
        0x36, 0x2e, 0x33, 0x20, 0x6c, 0x69, 0x62, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e, 0x31,
        0x36, 0x2e, 0x33, 0x20, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x4c, 0x2f, 0x30, 0x2e, 0x39,
        0x2e, 0x37, 0x6c, 0x20, 0x7a, 0x6c, 0x69, 0x62, 0x2f, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x04,
        0x68, 0x6f, 0x73, 0x74, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x0f, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c, 0x61,
        0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x06, 0x65, 0x6e, 0x2c, 0x20, 0x6d, 0x69, 0x00, 0x00,
    ];
    const REQUEST2: &[u8] = &[
        0x02, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73, 0x00, 0x0a, 0x2f, 0x68,
        0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x0a, 0x75, 0x73, 0x65, 0x72, 0x2d, 0x61,
        0x67, 0x65, 0x6e, 0x74, 0x34, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e, 0x31, 0x36, 0x2e,
        0x33, 0x20, 0x6c, 0x69, 0x62, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e, 0x31, 0x36, 0x2e,
        0x33, 0x20, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x4c, 0x2f, 0x30, 0x2e, 0x39, 0x2e, 0x37,
        0x6c, 0x20, 0x7a, 0x6c, 0x69, 0x62, 0x2f, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x04, 0x68, 0x6f,
        0x73, 0x74, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x0f, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67,
        0x75, 0x61, 0x67, 0x65, 0x06, 0x65, 0x6e, 0x2c, 0x20, 0x6d, 0x69, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn informational() {
        const INFO: &[u8] = &[1, 64, 100, 0, 64, 200, 0];
        let mut buf_alias = INFO;
        let mut msg = Message::async_read(&mut buf_alias);
        let info = msg.informational().sync_collect().unwrap();
        assert_eq!(info.len(), 1);
        let info = msg.informational().sync_collect().unwrap();
        assert!(info.is_empty());
        let hdr = pin!(msg.header()).sync_resolve().unwrap();
        assert_eq!(hdr.control().status().unwrap().code(), 200);
        assert!(hdr.is_empty());
    }

    #[test]
    fn sample_requests() {
        fn validate_sample_request(mut buf: &[u8]) {
            let mut msg = Message::async_read(&mut buf);
            let info = msg.informational().sync_collect().unwrap();
            assert!(info.is_empty());

            let hdr = pin!(msg.header()).sync_resolve().unwrap();
            assert_eq!(hdr.control(), &(b"GET", b"https", b"", b"/hello.txt"));
            assert_eq!(
                hdr.get(b"user-agent"),
                Some(&b"curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"[..]),
            );
            assert_eq!(hdr.get(b"host"), Some(&b"www.example.com"[..]));
            assert_eq!(hdr.get(b"accept-language"), Some(&b"en, mi"[..]));
            assert_eq!(hdr.len(), 3);

            let body = pin!(msg.body().unwrap()).sync_read_to_end();
            assert!(body.is_empty());

            let trailer = pin!(msg.trailer()).sync_resolve().unwrap();
            assert!(trailer.is_empty());
        }

        validate_sample_request(REQUEST1);
        validate_sample_request(REQUEST2);
        validate_sample_request(&REQUEST2[..REQUEST2.len() - 12]);
    }

    #[test]
    fn truncated_header() {
        // The indefinite-length request example includes 10 bytes of padding.
        // The three additional zero values at the end represent:
        // 1. The terminating zero for the header field section.
        // 2. The terminating zero for the (empty) body.
        // 3. The terminating zero for the (absent) trailer field section.
        // The latter two (body and trailer) can be cut and the message will still work.
        // The first is not optional; dropping it means that the message is truncated.
        let mut buf = &mut &REQUEST2[..REQUEST2.len() - 13];
        let mut msg = Message::async_read(&mut buf);
        // Use this test to test skipping a few things.
        let err = pin!(msg.header()).sync_resolve().unwrap_err();
        assert!(matches!(err, Error::Truncated));
    }

    #[test]
    fn sample_responses() {
        const RESPONSE: &[u8] = &[
            0x03, 0x40, 0x66, 0x07, 0x72, 0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x0a, 0x22, 0x73,
            0x6c, 0x65, 0x65, 0x70, 0x20, 0x31, 0x35, 0x22, 0x00, 0x40, 0x67, 0x04, 0x6c, 0x69,
            0x6e, 0x6b, 0x23, 0x3c, 0x2f, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x2e, 0x63, 0x73, 0x73,
            0x3e, 0x3b, 0x20, 0x72, 0x65, 0x6c, 0x3d, 0x70, 0x72, 0x65, 0x6c, 0x6f, 0x61, 0x64,
            0x3b, 0x20, 0x61, 0x73, 0x3d, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x04, 0x6c, 0x69, 0x6e,
            0x6b, 0x24, 0x3c, 0x2f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x2e, 0x6a, 0x73, 0x3e,
            0x3b, 0x20, 0x72, 0x65, 0x6c, 0x3d, 0x70, 0x72, 0x65, 0x6c, 0x6f, 0x61, 0x64, 0x3b,
            0x20, 0x61, 0x73, 0x3d, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x00, 0x40, 0xc8, 0x04,
            0x64, 0x61, 0x74, 0x65, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x37, 0x20, 0x4a,
            0x75, 0x6c, 0x20, 0x32, 0x30, 0x30, 0x39, 0x20, 0x31, 0x32, 0x3a, 0x32, 0x38, 0x3a,
            0x35, 0x33, 0x20, 0x47, 0x4d, 0x54, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x06,
            0x41, 0x70, 0x61, 0x63, 0x68, 0x65, 0x0d, 0x6c, 0x61, 0x73, 0x74, 0x2d, 0x6d, 0x6f,
            0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x1d, 0x57, 0x65, 0x64, 0x2c, 0x20, 0x32, 0x32,
            0x20, 0x4a, 0x75, 0x6c, 0x20, 0x32, 0x30, 0x30, 0x39, 0x20, 0x31, 0x39, 0x3a, 0x31,
            0x35, 0x3a, 0x35, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x04, 0x65, 0x74, 0x61, 0x67, 0x14,
            0x22, 0x33, 0x34, 0x61, 0x61, 0x33, 0x38, 0x37, 0x2d, 0x64, 0x2d, 0x31, 0x35, 0x36,
            0x38, 0x65, 0x62, 0x30, 0x30, 0x22, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
            0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x05, 0x62, 0x79, 0x74, 0x65, 0x73, 0x0e, 0x63,
            0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x02,
            0x35, 0x31, 0x04, 0x76, 0x61, 0x72, 0x79, 0x0f, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74,
            0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x0c, 0x63, 0x6f, 0x6e, 0x74,
            0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x0a, 0x74, 0x65, 0x78, 0x74, 0x2f,
            0x70, 0x6c, 0x61, 0x69, 0x6e, 0x00, 0x33, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
            0x6f, 0x72, 0x6c, 0x64, 0x21, 0x20, 0x4d, 0x79, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65,
            0x6e, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x73, 0x20, 0x61, 0x20,
            0x74, 0x72, 0x61, 0x69, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x52, 0x4c, 0x46, 0x2e,
            0x0d, 0x0a, 0x00, 0x00,
        ];

        let mut buf = RESPONSE;
        let mut msg = Message::async_read(&mut buf);

        {
            // Need to scope access to `info` or it will hold the reference to `msg`.
            let mut info = pin!(msg.informational());

            let info1 = info.try_next().sync_resolve().unwrap().unwrap();
            assert_eq!(info1.status(), 102_u16);
            assert_eq!(info1.len(), 1);
            assert_eq!(info1.get(b"running"), Some(&b"\"sleep 15\""[..]));

            let info2 = info.try_next().sync_resolve().unwrap().unwrap();
            assert_eq!(info2.status(), 103_u16);
            assert_eq!(info2.len(), 2);
            let links = info2.get_all(b"link").collect::<Vec<_>>();
            assert_eq!(
                &links,
                &[
                    &b"</style.css>; rel=preload; as=style"[..],
                    &b"</script.js>; rel=preload; as=script"[..],
                ]
            );

            assert!(info.try_next().sync_resolve().unwrap().is_none());
        }

        let hdr = pin!(msg.header()).sync_resolve().unwrap();
        assert_eq!(hdr.control(), &200_u16);
        assert_eq!(hdr.len(), 8);
        assert_eq!(hdr.get(b"vary"), Some(&b"Accept-Encoding"[..]));
        assert_eq!(hdr.get(b"etag"), Some(&b"\"34aa387-d-1568eb00\""[..]));

        {
            let mut body = pin!(msg.body().unwrap());
            assert_eq!(body.sync_read_exact(12), b"Hello World!");
        }
        // Attempting to read the trailer before finishing the body should fail.
        assert!(matches!(
            pin!(msg.trailer()).sync_resolve(),
            Err(Error::InvalidState)
        ));
        {
            // Picking up the body again should work fine.
            let mut body = pin!(msg.body().unwrap());
            assert_eq!(
                body.sync_read_to_end(),
                b" My content includes a trailing CRLF.\r\n"
            );
        }
        let trailer = pin!(msg.trailer()).sync_resolve().unwrap();
        assert!(trailer.is_empty());
    }
}
