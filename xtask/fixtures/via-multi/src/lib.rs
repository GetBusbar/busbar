//! Fixture: reaches `libc` two SEPARATE ways, through `xtask-fixture-via-multi-a` and
//! `xtask-fixture-via-multi-b`.
pub fn touch() {
    xtask_fixture_via_multi_a::touch();
    xtask_fixture_via_multi_b::touch();
}
