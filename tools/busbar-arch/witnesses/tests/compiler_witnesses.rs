//! The compiler witnesses of `[[compiler_witnesses]]` in ci/architecture.toml.
//!
//! Each case is a doc-comment example from busbar-contract or busbar-plugin-loader,
//! extracted by `busbar-arch witnesses --write` (and checked unchanged by
//! `busbar-arch check`). Negative witnesses must fail with the rustc error the
//! `.stderr` snapshot records (it must show the code the doc fence names);
//! positive controls must compile and run. This crate depends on the SDK with
//! production features only: no test-seal / test-support anywhere in its graph.

#[test]
fn compiler_witnesses() {
    let cases = trybuild::TestCases::new();
    cases.pass("cases/pass/*.rs");
    cases.compile_fail("cases/fail/*.rs");
}
