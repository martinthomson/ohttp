#![allow(dead_code)]

use std::{
    io::{Cursor, Result as IoResult},
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{stream::unfold, AsyncRead, Stream, TryStreamExt};
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
    async fn async_read<S: AsyncRead + Unpin>(request: bool, src: &mut S) -> Res<Self>;
}

impl AsyncReadControlData for ControlData {
    async fn async_read<S: AsyncRead + Unpin>(request: bool, src: &mut S) -> Res<Self> {
        let v = if request {
            let method = read_vec(src).await?.ok_or(Error::Truncated)?;
            let scheme = read_vec(src).await?.ok_or(Error::Truncated)?;
            let authority = read_vec(src).await?.ok_or(Error::Truncated)?;
            let path = read_vec(src).await?.ok_or(Error::Truncated)?;
            Self::Request {
                method,
                scheme,
                authority,
                path,
            }
        } else {
            Self::Response(crate::StatusCode::try_from(
                read_varint(src).await?.ok_or(Error::Truncated)?,
            )?)
        };
        Ok(v)
    }
}

trait AsyncReadFieldSection: Sized {
    async fn async_read<S: AsyncRead + Unpin>(mode: Mode, src: &mut S) -> Res<Self>;
}

impl AsyncReadFieldSection for FieldSection {
    async fn async_read<S: AsyncRead + Unpin>(mode: Mode, src: &mut S) -> Res<Self> {
        let fields = if mode == Mode::KnownLength {
            // Known-length fields can just be read into a buffer.
            if let Some(buf) = read_vec(src).await? {
                Self::read_bhttp_fields(false, &mut Cursor::new(&buf[..]))?
            } else {
                Vec::new()
            }
        } else {
            // The async version needs to be implemented directly.
            let mut fields: Vec<Field> = Vec::new();
            let mut cookie_index: Option<usize> = None;
            loop {
                if let Some(n) = read_vec(src).await? {
                    if n.is_empty() {
                        break fields;
                    }
                    let mut v = read_vec(src).await?.ok_or(Error::Truncated)?;
                    if n == COOKIE {
                        if let Some(i) = &cookie_index {
                            fields[*i].value.extend_from_slice(b"; ");
                            fields[*i].value.append(&mut v);
                            continue;
                        }
                        cookie_index = Some(fields.len());
                    }
                    fields.push(Field::new(n, v));
                } else {
                    return Err(Error::Truncated);
                }
            }
        };
        Ok(Self(fields))
    }
}

enum BodyState<'a, S> {
    // When reading the length, use this.
    ReadLength(ReadVarint<'a, S>),
    // When reading the data, track how much is left.
    ReadData {
        remaining: usize,
        src: Pin<&'a mut S>,
    },
}

#[pin_project::pin_project]
struct Body<'a, S> {
    mode: Mode,
    state: BodyState<'a, S>,
}

impl<'a, S: AsyncRead> AsyncRead for Body<'a, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        self.project().src.as_mut().poll_read(cx, buf)
    }
}

enum AsyncMessageState {
    // Processing Informational responses (or before that).
    Informational,
    // Having obtained the control data for the header, this is it.
    Header(ControlData),
    // Processing the Body.
    Body,
    // Processing the trailer.
    Trailer,
}

struct AsyncMessage<'a, S> {
    // Whether this is a request and which mode.
    framing: Option<(bool, Mode)>,
    state: AsyncMessageState,
    src: Pin<&'a mut S>,
}

impl<'a, S: AsyncRead> AsyncMessage<'a, S> {
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
    ) -> impl Stream<Item = Res<InformationalResponse>> + use<'_, 'a, S> {
        unfold(self, |this| async move {
            this.next_info().await.transpose().map(|info| (info, this))
        })
    }

    /// This reads the header.  If you have not called `informational`
    /// and drained the resulting stream, this will do that for you.
    pub async fn header(&mut self) -> Res<Header> {
        if matches!(self.state, AsyncMessageState::Informational) {
            // Need to scrub for errors,
            // so that this can abort properly if there is one.
            // The `try_any` usage is there to ensure that the stream is fully drained.
            _ = self.informational().try_any(|_| async { false }).await?;
        }
        if matches!(self.state, AsyncMessageState::Header(_)) {
            let AsyncMessageState::Header(control) =
                mem::replace(&mut self.state, AsyncMessageState::Body)
            else {
                unreachable!();
            };
            let mode = self.mode();
            let hfields = FieldSection::async_read(mode, &mut self.src).await?;
            Ok(Header::from((control, hfields)))
        } else {
            Err(Error::InvalidState)
        }
    }

    pub fn body<'s>(&'s mut self) -> Res<Body<'s, S>>
    where
        'a: 's,
    {
        if matches!(self.state, AsyncMessageState::Body) {
            Ok(Body {
                mode: self.mode(),
                state: BodyState::ReadLength(read_varint(self.src.as_mut())),
            })
        } else {
            Err(Error::InvalidState)
        }
    }
}

trait AsyncReadMessage: Sized {
    fn async_read<S: AsyncRead + Unpin>(src: &mut S) -> AsyncMessage<'_, S>;
}

impl AsyncReadMessage for Message {
    fn async_read<S: AsyncRead + Unpin>(src: &mut S) -> AsyncMessage<'_, S> {
        AsyncMessage {
            framing: None,
            state: AsyncMessageState::Informational,
            src: Pin::new(src),
        }
    }
}

#[cfg(test)]
mod test {
    use std::pin::pin;

    use crate::{
        stream::{
            future::{SyncCollect, SyncResolve},
            AsyncReadMessage,
        },
        Message,
    };

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
}
