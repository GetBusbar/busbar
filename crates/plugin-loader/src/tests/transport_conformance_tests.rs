// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DROP-IN CONFORMANCE for `kind: transport` — the transport analogue of the plane example's
//! over-the-ABI round trips (`DECISIONS #2/#3/#11`: a plugin is a plugin, both-ways for EVERY kind
//! incl. transport — the drop-in packaging the seven compiled-in carriers were owed).
//!
//! `busbar-plugin-example-transport` is a `["cdylib", "rlib"]` crate, so these tests hold BOTH forms of
//! the SAME carrier at once: the COMPILED-IN reference (`busbar_plugin_example_transport::TRANSPORT_DECL`,
//! linked via the rlib) and the DROPPED-IN artifact (the `cdylib` on disk, loaded through
//! [`crate::load_transport`] over the HOT-tier ABI). The first test proves the two decls are
//! byte-identical at the vocabulary / facet / preamble surface — "loads identically compiled-in vs
//! dropped-in". The second drives the dropped-in carrier end to end (build → connect → write → read,
//! and accept) to prove a BIDIRECTIONAL byte stream round-trips over the seam, not just a decl.

use busbar_plugin::hot::pod::StatusClass;
use busbar_plugin::hot::transport::TransportFacet;
use busbar_plugin::hot::PlaneHostVtable;
use busbar_plugin_example_transport::TRANSPORT_DECL as COMPILED_IN;

/// Locate the REAL `busbar-plugin-example-transport` cdylib built into this workspace's target dir
/// (uplifted or under `deps`, newest wins). Mirrors `plane_example_cdylib()`.
fn transport_example_cdylib() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename("busbar_plugin_example_transport");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the transport example plugin cdylib is not built under CI: `cargo test --workspace` must \
             build busbar_plugin_example_transport (checked both the uplifted target dir and \
             target/deps). Refusing to silently skip the ONLY both-ways proof for kind:transport."
        );
    }
    candidate
}

/// Read one borrowed vocabulary range from the COMPILED-IN decl into an owned string (the same shape
/// `wire_up_transport` materialises the dropped-in side to, so the two are directly comparable).
fn vocab(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: the const's vocabulary points at this crate's own `'static` byte strings.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).unwrap().to_string()
}

/// The dropped-in decl the loader reads is byte-identical to the compiled-in `TRANSPORT_DECL` at the
/// vocabulary / facet surface — a carrier loads the SAME whether compiled in or dropped in.
#[test]
fn example_transport_loads_identically_compiled_in_and_dropped_in() {
    let Some(lib) = transport_example_cdylib() else {
        eprintln!("skip: transport example cdylib not built (run under --workspace)");
        return;
    };
    let dropped =
        crate::load_transport(&lib).expect("load the example transport over the HOT-tier ABI");

    assert_eq!(
        dropped.name(),
        vocab(COMPILED_IN.name_ptr, COMPILED_IN.name_len)
    );
    assert_eq!(
        dropped.section_key(),
        vocab(COMPILED_IN.section_key_ptr, COMPILED_IN.section_key_len)
    );
    assert_eq!(
        dropped.scope(),
        vocab(COMPILED_IN.scope_ptr, COMPILED_IN.scope_len)
    );
    assert_eq!(
        dropped.label(),
        vocab(COMPILED_IN.label_ptr, COMPILED_IN.label_len)
    );
    assert_eq!(dropped.provided_facets(), COMPILED_IN.provided_facets);
    // A fully bidirectional carrier — BOTH directions of the one transport kind (DECISIONS #3).
    assert!(dropped.provides(TransportFacet::Accept));
    assert!(dropped.provides(TransportFacet::Connect));
    // Non-empty vocabulary — a decl that lost its name/label at the crossing would fail here.
    assert_eq!(dropped.name(), "example");
    assert_eq!(dropped.label(), "Example Transport");
}

/// The dropped-in carrier is a LIVE bidirectional byte stream: config_validate → build → connect →
/// write → read round-trips the bytes over the ABI, and the accept (passive) direction yields a live
/// connection too. Driven with an EMPTY host vtable (the example calls back into none of its slots).
#[test]
fn dropped_in_example_transport_round_trips_bytes_both_directions() {
    let Some(lib) = transport_example_cdylib() else {
        eprintln!("skip: transport example cdylib not built (run under --workspace)");
        return;
    };
    let carrier = crate::load_transport(&lib).expect("load the example transport");

    // config_validate produces a parsed handle; free it.
    let (cv_status, parsed) = carrier.config_validate(b"{}");
    assert_eq!(cv_status, StatusClass::Ok);
    if let Some(p) = parsed {
        if let Some(free) = p.free {
            free(p.ptr);
        }
    }

    // build with an EMPTY host vtable + null host ctx (the example never calls a host slot).
    let host = PlaneHostVtable::EMPTY;
    let host_ptr: *const PlaneHostVtable = &host;
    // SAFETY: `host_ptr` is a live EMPTY vtable that outlives these calls; the example does not
    // dereference `host_ctx`.
    let (build_status, state) =
        unsafe { carrier.build(host_ptr, core::ptr::null_mut(), b"{}", &[]) };
    assert_eq!(build_status, StatusClass::Ok);
    let state = state.expect("build yields an opaque carrier handle on Ok");
    assert!(!state.ptr.is_null());

    // CONNECT (active/client-connect direction) → write → read the SAME bytes back out.
    // SAFETY: `state.ptr` is the live carrier state `build` just produced.
    let (conn_status, conn) = unsafe { carrier.connect(state.ptr, b"loopback://example") };
    assert_eq!(conn_status, StatusClass::Ok);
    let conn = conn.expect("connect yields a connection handle on Ok");

    let payload = b"ping-both-ways";
    // SAFETY: `conn.ptr` is the live connection handle `connect` just produced.
    let (w_status, wrote) = unsafe { carrier.write(conn.ptr, payload) };
    assert_eq!(w_status, StatusClass::Ok);
    assert_eq!(
        wrote,
        payload.len(),
        "the carrier accepted every byte written over the ABI"
    );

    let mut buf = [0u8; 32];
    // SAFETY: as above.
    let (r_status, got) = unsafe { carrier.read(conn.ptr, &mut buf) };
    assert_eq!(r_status, StatusClass::Ok);
    assert_eq!(
        &buf[..got],
        payload,
        "a byte written INTO the carrier over the ABI comes back OUT of it — a real round trip"
    );
    // Close the connection through its own free (the teardown path core would take).
    if let Some(free) = conn.free {
        free(conn.ptr);
    }

    // ACCEPT (passive/server-accept direction) yields a live connection too — both directions wired.
    // SAFETY: `state.ptr` is the live carrier state.
    let (accept_status, accepted) = unsafe { carrier.accept(state.ptr) };
    assert_eq!(accept_status, StatusClass::Ok);
    let accepted = accepted.expect("accept yields a connection handle on Ok");
    if let Some(free) = accepted.free {
        free(accepted.ptr);
    }

    // Free the carrier state through its own `free` fn.
    if let Some(free) = state.free {
        free(state.ptr);
    }
}

/// `supported_abi("transport")` gates a carrier's manifest `abi_version` against the airlock-minor
/// axis — the same axis a plane uses (both are HOT-tier POD kinds).
#[test]
fn transport_supported_abi_covers_the_airlock_minor() {
    let range = crate::registry::supported_abi("transport");
    assert_eq!(range, &[1, busbar_plugin::ABI_MINOR]);
    // The other kinds still resolve; an unknown kind is still empty.
    assert!(!crate::registry::supported_abi("plane").is_empty());
    assert!(!crate::registry::supported_abi("store").is_empty());
    assert!(crate::registry::supported_abi("nonsense").is_empty());
}
