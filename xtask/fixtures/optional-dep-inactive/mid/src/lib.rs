//! Fixture: an optional, INACTIVE dependency on `libc` — the `with-libc` feature is never turned
//! on by this fixture's workspace, so `libc` is never compiled in.
#[cfg(feature = "with-libc")]
pub fn touch() {
    let _pid = unsafe { libc::getpid() };
}

#[cfg(not(feature = "with-libc"))]
pub fn touch() {}
