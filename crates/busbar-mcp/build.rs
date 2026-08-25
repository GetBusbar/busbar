// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE "AM I MY OWN CRATE?" DISCRIMINATOR for the plane tests.
//
// `busbar_mcp_native` is emitted UNCONDITIONALLY whenever this crate is built AS A CRATE — its own
// `cargo test` binary, or the linked MCP plugin inside the `busbar` binary. It is ABSENT when
// `busbar-core` dual-compiles `src/mcp` back into its OWN test binary through a `#[path]` module
// declaration: a build script runs for a compiled crate, never for source pulled in by path, so the
// cfg simply is not set on that compilation unit.
//
// That absence is exactly what the plane tests key on. Each builds a `TestApp` and reads the plane's
// runtime back out of it by downcast; that runtime's type is `<compiling-crate>::mcp::McpRuntime`, so
// the fixtures (which live in `busbar-core`, `pub(crate)`) only ever produce a value the tests can
// reach and downcast when BOTH are the same crate — i.e. inside busbar-core's dual-compile binary.
// The tests are therefore gated `not(busbar_mcp_native)`: present here (skip), absent in core (run).
//
// This replaced a default-on `extracted` FEATURE. A feature can be switched off — `cargo test
// --no-default-features` did exactly that and wrongly un-skipped every plane test into this crate's
// own binary, where `busbar-core`'s `pub(crate)` test surface is unreachable and they cannot even
// compile. A build-script cfg cannot be switched off from the command line, so the skip is robust.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(busbar_mcp_native)");
    println!("cargo::rustc-cfg=busbar_mcp_native");
}
