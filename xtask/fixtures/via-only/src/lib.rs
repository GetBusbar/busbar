//! Fixture: reaches `libc` only through `xtask-fixture-via-mid`.
pub fn touch() {
    xtask_fixture_via_mid::touch();
}
