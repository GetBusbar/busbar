//! Fixture: depends on `mid`, whose `libc` dependency is optional and inactive here.
pub fn touch() {
    xtask_fixture_optional_mid::touch();
}
