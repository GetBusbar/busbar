//! Fixture: reaches `libc` two ways — through `xtask-fixture-via-mid` AND directly.
pub fn touch() {
    xtask_fixture_via_mid::touch();
    let _pid = unsafe { libc::getpid() };
}
