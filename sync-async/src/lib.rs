use std::{
    cmp::min,
    future::Future,
    io::Result as IoResult,
    pin::{Pin, pin},
    task::{Context, Poll},
};

use futures::{
    AsyncRead, AsyncReadExt, AsyncWrite, TryStream, TryStreamExt,
    io::{ReadHalf, WriteHalf},
};
use pin_project::pin_project;

fn noop_context() -> Context<'static> {
    use std::{
        ptr::null,
        task::{RawWaker, RawWakerVTable, Waker},
    };

    const fn noop_raw_waker() -> RawWaker {
        unsafe fn noop_clone(_data: *const ()) -> RawWaker {
            noop_raw_waker()
        }

        unsafe fn noop(_data: *const ()) {}

        const NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);
        RawWaker::new(null(), &NOOP_WAKER_VTABLE)
    }

    pub fn noop_waker_ref() -> &'static Waker {
        #[repr(transparent)]
        struct SyncRawWaker(RawWaker);
        unsafe impl Sync for SyncRawWaker {}

        static NOOP_WAKER_INSTANCE: SyncRawWaker = SyncRawWaker(noop_raw_waker());

        // SAFETY: `Waker` is #[repr(transparent)] over its `RawWaker`.
        unsafe { &*(std::ptr::addr_of!(NOOP_WAKER_INSTANCE.0).cast()) }
    }

    Context::from_waker(noop_waker_ref())
}

/// Drives the given future (`f`) until it resolves.
/// Executes the indicated function (`p`) each time the
/// poll returned `Poll::Pending`.
pub trait SyncResolve {
    type Output;

    fn sync_resolve(&mut self) -> Self::Output {
        self.sync_resolve_with(|_| {})
    }

    fn sync_resolve_with<P: Fn(Pin<&mut Self>)>(&mut self, p: P) -> Self::Output;
}

impl<F: Future + Unpin> SyncResolve for F {
    type Output = F::Output;

    fn sync_resolve_with<P: Fn(Pin<&mut Self>)>(&mut self, p: P) -> Self::Output {
        let mut cx = noop_context();
        let mut fut = Pin::new(self);
        let mut v = fut.as_mut().poll(&mut cx);
        while v.is_pending() {
            p(fut.as_mut());
            v = fut.as_mut().poll(&mut cx);
        }
        if let Poll::Ready(v) = v {
            v
        } else {
            unreachable!();
        }
    }
}

/// A synchronous collect method for [`TryStream`].
pub trait SyncTryCollect {
    type Item;
    type Error;

    /// Synchronously gather all items from a stream.
    /// # Errors
    /// When the underlying source produces an error.
    fn sync_collect<C: Default + Extend<Self::Item>>(self) -> Result<C, Self::Error>;
}

impl<S: TryStream> SyncTryCollect for S {
    type Item = S::Ok;
    type Error = S::Error;

    fn sync_collect<C: Default + Extend<Self::Item>>(self) -> Result<C, Self::Error> {
        pin!(self.try_collect::<C>()).sync_resolve()
    }
}

/// Synchronous reading for [`AsyncRead`], using [`SyncResolve`].
pub trait SyncRead {
    fn sync_read_exact(&mut self, amount: usize) -> Vec<u8>;
    fn sync_read_to_end(&mut self) -> Vec<u8>;
}

impl<S: AsyncRead + Unpin> SyncRead for S {
    fn sync_read_exact(&mut self, amount: usize) -> Vec<u8> {
        let mut buf = vec![0; amount];
        let res = self.read_exact(&mut buf[..]);
        pin!(res).sync_resolve().unwrap();
        buf
    }

    fn sync_read_to_end(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        let res = self.read_to_end(&mut buf);
        pin!(res).sync_resolve().unwrap();
        buf
    }
}

pub trait Unadapt {
    type S;
    fn unadapt(self) -> Self::S;
}

/// An adapter for [`AsyncRead`] and [`AsyncWrite`] that reads or writes a single byte at a time.
#[pin_project(project = DribbleProjection)]
pub struct Dribble<S> {
    #[pin]
    s: S,
}

impl<S> Dribble<S> {
    pub fn new(s: S) -> Self {
        Self { s }
    }

    pub fn unwrap(self) -> S {
        self.s
    }
}

impl<S> Unadapt for Dribble<S> {
    type S = S;
    fn unadapt(self) -> Self::S {
        self.s
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Dribble<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let mut this = self.project();
        this.s.as_mut().poll_read(cx, &mut buf[..1])
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Dribble<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let mut this = self.project();
        this.s.as_mut().poll_write(cx, &buf[..1])
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let mut this = self.project();
        this.s.as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let mut this = self.project();
        this.s.as_mut().poll_close(cx)
    }
}

/// An adapter for [`AsyncRead`] and [`AsyncWrite`] that blocks at a chosen offset.
#[pin_project(project = SplitAtProjection)]
pub struct SplitAt<S> {
    #[pin]
    s: S,
    remaining: Option<usize>,
}

impl<S> SplitAt<S> {
    /// Split the stream at the selected `offset`.
    /// Read or write calls will stop at the indicated offset,
    /// with a single `Poll::Pending` return at that point,
    /// after which all operations proceed normally.
    pub fn new(s: S, offset: usize) -> Self {
        Self {
            s,
            remaining: Some(offset),
        }
    }
}

impl<S> Unadapt for SplitAt<S> {
    type S = S;
    fn unadapt(self) -> Self::S {
        self.s
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SplitAt<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let mut this = self.project();
        if let Some(r) = this.remaining {
            let remaining = *r;
            if remaining == 0 {
                *this.remaining = None;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let cut = min(remaining, buf.len());
            let res = this.s.as_mut().poll_read(cx, &mut buf[..cut]);
            if let Poll::Ready(Ok(count)) = res {
                *this.remaining = Some(remaining - count);
            }
            res
        } else {
            this.s.as_mut().poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SplitAt<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let mut this = self.project();
        if let Some(r) = this.remaining {
            let remaining = *r;
            if remaining == 0 {
                *this.remaining = None;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let cut = min(remaining, buf.len());
            let res = this.s.as_mut().poll_write(cx, &buf[..cut]);
            if let Poll::Ready(Ok(count)) = res {
                *this.remaining = Some(remaining - count);
            }
            res
        } else {
            this.s.as_mut().poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let mut this = self.project();
        this.s.as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let mut this = self.project();
        this.s.as_mut().poll_close(cx)
    }
}

/// An adapter for [`AsyncRead`] and [`AsyncWrite`] that blocks after every single byte read or written.
#[pin_project(project = StutterProjection)]
pub struct Stutter<S> {
    stall: bool,
    #[pin]
    s: S,
}

impl<S> Stutter<S> {
    pub fn new(s: S) -> Self {
        Self { stall: false, s }
    }

    fn stutter<T, F>(self: Pin<&mut Self>, cx: &mut Context<'_>, f: F) -> Poll<T>
    where
        F: FnOnce(Pin<&mut S>, &mut Context<'_>) -> Poll<T>,
    {
        let mut this = self.project();
        *this.stall = !*this.stall;
        if *this.stall {
            // When returning `Poll::Pending`, you have to wake the task.
            // We aren't running code anywhere except here,
            // so call it here and ensure that the task is picked up immediately.
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            f(this.s.as_mut(), cx)
        }
    }
}

impl<S> Unadapt for Stutter<S> {
    type S = S;
    fn unadapt(self) -> Self::S {
        self.s
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Stutter<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Self::stutter(self, cx, |s, cx| s.poll_read(cx, buf))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Stutter<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        Self::stutter(self, cx, |s, cx| s.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Self::stutter(self, cx, AsyncWrite::poll_flush)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Self::stutter(self, cx, AsyncWrite::poll_close)
    }
}

/// A paired [`AsyncRead`]/[`AsyncWrite`] implementation pair with separate read and write cursors.
///
/// This allows tests to create paired read and write objects,
/// where writes to one can be read by the other.
///
/// This relies on the implementation of `AyncReadExt::split` to provide
/// any locking and concurrency, rather than implementing it.
#[derive(Default)]
#[pin_project]
pub struct Pipe {
    buf: Vec<u8>,
    r: usize,
    w: usize,
}

impl Pipe {
    #[must_use]
    pub fn new() -> (ReadHalf<Self>, WriteHalf<Self>) {
        AsyncReadExt::split(Self::default())
    }
}

impl AsyncRead for Pipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let amnt = min(buf.len(), self.buf.len() - self.r);
        buf[..amnt].copy_from_slice(&self.buf[self.r..self.r + amnt]);
        self.r += amnt;
        Poll::Ready(Ok(amnt))
    }
}

impl AsyncWrite for Pipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        if self.w < self.buf.len() {
            let overlap = min(buf.len() - self.w, self.buf.len());
            let range = self.w..(self.w + overlap);
            self.buf[range].copy_from_slice(&buf[..overlap]);
            buf = &buf[overlap..];
        }
        self.buf.extend_from_slice(buf);
        self.w += buf.len();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }
}
