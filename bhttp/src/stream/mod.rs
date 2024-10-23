use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::io::AsyncRead;

use crate::{Error, Res};

#[pin_project::pin_project]
pub struct ReadUint<'a, S, const N: usize> {
    ///  The source of data.
    src: Pin<&'a mut S>,
    /// A buffer that holds the bytes that have been read so far.
    v: [u8; 8],
    /// A counter of the number of bytes that are already in place.
    /// This starts out at `8-N`.
    read: usize,
}

impl<'a, S, const N: usize> Future for ReadUint<'a, S, N>
where
    S: AsyncRead,
{
    type Output = Res<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.src.as_mut().poll_read(cx, &mut this.v[*this.read..]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(count)) => {
                if count == 0 {
                    return Poll::Ready(Err(Error::Truncated));
                }
                *this.read += count;
                if *this.read == 8 {
                    Poll::Ready(Ok(u64::from_be_bytes(*this.v)))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::from(e))),
        }
    }
}

pub fn read_uint<S: Unpin, const N: usize>(src: &mut S) -> ReadUint<'_, S, N> {
    ReadUint {
        src: Pin::new(src),
        v: [0; 8],
        read: 8 - N,
    }
}

#[pin_project::pin_project(project = ReadVariantProj)]
pub enum ReadVarint<'a, S> {
    First(Option<Pin<&'a mut S>>),
    Extra1(#[pin] ReadUint<'a, S, 8>),
    Extra3(#[pin] ReadUint<'a, S, 8>),
    Extra7(#[pin] ReadUint<'a, S, 8>),
}

impl<'a, S> Future for ReadVarint<'a, S>
where
    S: AsyncRead,
{
    type Output = Res<Option<u64>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut();
        if let Self::First(src) = this.get_mut() {
            let mut src = src.take().unwrap();
            let mut buf = [0; 1];
            if let Poll::Ready(Ok(c)) = src.as_mut().poll_read(cx, &mut buf[..]) {
                if c == 0 {
                    return Poll::Ready(Ok(None));
                }
                let b1 = buf[0];
                let mut v = [0; 8];
                let next = match b1 >> 6 {
                    0 => return Poll::Ready(Ok(Some(u64::from(b1)))),
                    1 => {
                        v[6] = b1 & 0x3f;
                        Self::Extra1(ReadUint { src, v, read: 7 })
                    }
                    2 => {
                        v[4] = b1 & 0x3f;
                        Self::Extra3(ReadUint { src, v, read: 5 })
                    }
                    3 => {
                        v[0] = b1 & 0x3f;
                        Self::Extra7(ReadUint { src, v, read: 1 })
                    }
                    _ => unreachable!(),
                };

                self.set(next);
            }
        }
        let extra = match self.project() {
            ReadVariantProj::Extra1(s)
            | ReadVariantProj::Extra3(s)
            | ReadVariantProj::Extra7(s) => s.poll(cx),
            ReadVariantProj::First(_) => return Poll::Pending,
        };
        if let Poll::Ready(v) = extra {
            Poll::Ready(v.map(Some))
        } else {
            Poll::Pending
        }
    }
}

pub fn read_varint<S: Unpin>(src: &mut S) -> ReadVarint<'_, S> {
    ReadVarint::First(Some(Pin::new(src)))
}

#[cfg(test)]
mod test {
    use std::task::{Context, Poll};

    use futures::{Future, FutureExt};

    use crate::{
        rw::{write_uint as sync_write_uint, write_varint as sync_write_varint},
        stream::{read_uint as stream_read_uint, read_varint as stream_read_varint},
    };

    pub fn noop_context() -> Context<'static> {
        use std::{
            ptr::null,
            task::{RawWaker, RawWakerVTable, Waker},
        };

        const fn noop_raw_waker() -> RawWaker {
            unsafe fn noop_clone(_data: *const ()) -> RawWaker {
                noop_raw_waker()
            }

            unsafe fn noop(_data: *const ()) {}

            const NOOP_WAKER_VTABLE: RawWakerVTable =
                RawWakerVTable::new(noop_clone, noop, noop, noop);
            RawWaker::new(null(), &NOOP_WAKER_VTABLE)
        }

        pub fn noop_waker_ref() -> &'static Waker {
            struct SyncRawWaker(RawWaker);
            unsafe impl Sync for SyncRawWaker {}

            static NOOP_WAKER_INSTANCE: SyncRawWaker = SyncRawWaker(noop_raw_waker());

            // SAFETY: `Waker` is #[repr(transparent)] over its `RawWaker`.
            unsafe { &*(std::ptr::addr_of!(NOOP_WAKER_INSTANCE.0).cast()) }
        }

        Context::from_waker(noop_waker_ref())
    }

    fn assert_unpin<T: Future + Unpin>(v: T) -> T {
        v
    }

    fn read_uint<const N: usize>(mut buf: &[u8]) -> u64 {
        println!("{buf:?}");
        let mut cx = noop_context();
        let mut fut = assert_unpin(stream_read_uint::<_, N>(&mut buf));
        let mut v = fut.poll_unpin(&mut cx);
        while v.is_pending() {
            v = fut.poll_unpin(&mut cx);
        }
        if let Poll::Ready(Ok(v)) = v {
            v
        } else {
            panic!("v is not OK: {v:?}");
        }
    }

    #[test]
    fn read_uint_values() {
        macro_rules! validate_uint_range {
            (@ $n:expr) => {
                let m = u64::MAX >> (64 - 8 * $n);
                for v in [0, 1, m] {
                    println!("{n} byte encoding of 0x{v:x}", n = $n);
                    let mut buf = Vec::with_capacity($n);
                    sync_write_uint::<$n>(v, &mut buf).unwrap();
                    assert_eq!(v, read_uint::<$n>(&buf[..]));
                }
            };
            ($($n:expr),+ $(,)?) => {
                $(
                    validate_uint_range!(@ $n);
                )+
            }
        }
        validate_uint_range!(1, 2, 3, 4, 5, 6, 7, 8);
    }

    fn read_varint(mut buf: &[u8]) -> u64 {
        let mut cx = noop_context();
        let mut fut = assert_unpin(stream_read_varint(&mut buf));
        let mut v = fut.poll_unpin(&mut cx);
        while v.is_pending() {
            v = fut.poll_unpin(&mut cx);
        }
        if let Poll::Ready(Ok(Some(v))) = v {
            v
        } else {
            panic!("v is not OK: {v:?}");
        }
    }

    #[test]
    fn read_varint_values() {
        for i in [
            0,
            1,
            63,
            64,
            (1 << 14) - 1,
            1 << 14,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut buf = Vec::new();
            sync_write_varint(i, &mut buf).unwrap();
            assert_eq!(i, read_varint(&buf[..]));
        }
    }
}
