//! Fixture: one of two "via" crates — depends directly on `libc`.
pub fn touch() {
    let _pid = unsafe { libc::getpid() };
}
