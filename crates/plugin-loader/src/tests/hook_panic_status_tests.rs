// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `export` payload-schema window the registry admits, pinned at compile time and at run time.
//!
//! OWNER 2026-10-03 (NO TEST PLUGINS): the STATUS a panicking hook returned was pinned here over the
//! deleted `busbar-hook-test-plugin` cdylib; it is gone with it (QUESTIONS CONF-SUITE-DEL).

/// Pin the accepted `export` payload-schema window. The comment beside that entry described it as
/// v1 long after 1.5.3 removed the `audit` stream and moved it to v2, so a reader checking whether
/// a v1 sink would still load got the wrong answer from the only documentation there was. A const
/// assertion cannot drift with the prose: if the window ever moves, this fails to COMPILE.
/// The compile-time half: the CEILING the window is BUILT from. `supported_abi` itself matches on a
/// `&str` kind and so cannot be a `const fn`, but the constant it reads can be pinned here, and a
/// change to it fails the build rather than a test.
///
/// 2 -> 3 (DECISIONS #85): the ceiling moved when an export response became
/// `Envelope<ExportResponse>` — `{ result, metrics[], diagnostics[] }` — so a sink can report the
/// metrics it produced and the diagnostics it raised. This assertion did exactly its job: it failed
/// the BUILD, not a test, on the day the window moved.
const _: () = assert!(busbar_contract::abi::cold::export::EXPORT_ABI_VERSION == 3);

/// The runtime half: the window `export` actually resolves to.
///
/// `[2, 3]`, and the FLOOR is the load-bearing half. v1 is still refused (1.5.3 removed the `audit`
/// stream, so a v1 sink declares a stream the engine cannot route), but v2 is NOT: a sink built
/// before the observability envelope answers a bare `ExportResponse` and the loader's decoder reads
/// both shapes, so #85 widened the window rather than moving it. Refusing v2 here would have been
/// the one outcome a migration may not produce — a working deployment that stops loading on upgrade
/// — in exchange for nothing, since no published sink exists to be protected from the old shape.
#[test]
fn export_abi_window_admits_the_pre_envelope_sink_and_the_enveloped_one() {
    assert_eq!(
        crate::registry::supported_abi("export"),
        &[2, 3],
        "v1 must not load (1.5.3 removed the `audit` stream); v2 (bare response) and v3 (the #85 \
         envelope) must both load"
    );
}
