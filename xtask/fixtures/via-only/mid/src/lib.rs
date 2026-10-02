//! Fixture: the "via" crate — depends directly on `libc`.
pub fn touch() {
    let _pid = unsafe { libc::getpid() };
}
