//! Fixture: the other "via" crate — also depends directly on `libc`.
pub fn touch() {
    let _pid = unsafe { libc::getpid() };
}
