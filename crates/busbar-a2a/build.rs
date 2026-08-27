// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE "AM I MY OWN CRATE?" DISCRIMINATOR for the plane tests.
//
// `busbar_a2a_native` is emitted UNCONDITIONALLY whenever this crate is built AS A CRATE — its own
// `cargo test` binary, or the linked A2A plugin inside the `busbar` binary. It is ABSENT when
// `busbar-core` dual-compiles `src/a2a` back into its OWN test binary through a `#[path]` module
// declaration: a build script runs for a compiled crate, never for source pulled in by path, so the
// cfg simply is not set on that compilation unit.
//
// That absence is exactly what the plane tests key on. Each builds a `TestApp` and reads the plane's
// runtime back out of it by downcast; that runtime's type is `<compiling-crate>::a2a::plane::A2aPlane`,
// so the fixtures (which live in `busbar-core`, `pub(crate)`) only ever produce a value the tests can
// reach and downcast when BOTH are the same crate — i.e. inside busbar-core's dual-compile binary.
// The tests are therefore gated `not(busbar_a2a_native)`: present here (skip), absent in core (run).
//
// This mirrors busbar-mcp's `busbar_mcp_native` exactly. A build-script cfg cannot be switched off
// from the command line (unlike a default-on feature, which `--no-default-features` would wrongly flip
// and un-skip every plane test into this crate's own binary, where `busbar-core`'s `pub(crate)` test
// surface is unreachable and they cannot even compile), so the skip is robust.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(busbar_a2a_native)");
    println!("cargo::rustc-cfg=busbar_a2a_native");
}
