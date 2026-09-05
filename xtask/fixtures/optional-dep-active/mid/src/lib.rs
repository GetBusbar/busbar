//! Fixture: an optional dependency on `libc` that IS active (the root fixture crate requests the
//! `with-libc` feature).
#[cfg(feature = "with-libc")]
pub fn touch() {
    let _pid = unsafe { libc::getpid() };
}

#[cfg(not(feature = "with-libc"))]
pub fn touch() {}
