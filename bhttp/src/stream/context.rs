use std::{
    future::Future,
    task::{Context, Poll},
};

use futures::FutureExt;

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
        struct SyncRawWaker(RawWaker);
        unsafe impl Sync for SyncRawWaker {}

        static NOOP_WAKER_INSTANCE: SyncRawWaker = SyncRawWaker(noop_raw_waker());

        // SAFETY: `Waker` is #[repr(transparent)] over its `RawWaker`.
        unsafe { &*(std::ptr::addr_of!(NOOP_WAKER_INSTANCE.0).cast()) }
    }

    Context::from_waker(noop_waker_ref())
}

fn assert_unpin<F: Future + Unpin>(v: F) -> F {
    v
}

/// Drives the given future (`f`) until it resolves.
/// Executes the indicated function (`p`) each time the
/// poll returned `Poll::Pending`.
pub fn sync_resolve_with<F: Future + Unpin, P: Fn(&mut F)>(f: F, p: P) -> F::Output {
    let mut cx = noop_context();
    let mut fut = assert_unpin(f);
    let mut v = fut.poll_unpin(&mut cx);
    while v.is_pending() {
        p(&mut fut);
        v = fut.poll_unpin(&mut cx);
    }
    if let Poll::Ready(v) = v {
        v
    } else {
        unreachable!();
    }
}

pub fn sync_resolve<F: Future + Unpin>(f: F) -> F::Output {
    sync_resolve_with(f, |_| {})
}
