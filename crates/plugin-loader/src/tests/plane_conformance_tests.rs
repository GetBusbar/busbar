// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DROP-IN CONFORMANCE for `kind: plane` — the plane analogue of the store example's over-the-ABI
//! round trips (`DECISIONS #2/#11/#26 S4`: a plugin is a plugin, both-ways for EVERY kind incl. plane).
//!
//! `busbar-plane-example` is a `["cdylib", "rlib"]` crate, so these tests hold BOTH forms of the SAME
//! plane at once: the COMPILED-IN reference (`busbar_plane_example::PLANE_DECL`, linked via the rlib)
//! and the DROPPED-IN artifact (the `cdylib` on disk, loaded through [`crate::load_plane`] over the
//! HOT-tier ABI). The first test proves the two decls are byte-identical at the vocabulary / carrier /
//! preamble surface — "loads identically compiled-in vs dropped-in". The second drives the dropped-in
//! plane end to end (build → hydrate → start → dispatch) to prove it is a LIVE plane, not just a decl.

use busbar_plugin_example_plane::PLANE_DECL as COMPILED_IN;
use busbar_plugin::hot::pod::StatusClass;
use busbar_plugin::hot::{EmitHandle, InboundHandle, IngressCarrier, PlaneHostVtable, WorkItem};

/// Locate the REAL `busbar-plane-example` cdylib built into this workspace's target dir (uplifted or
/// under `deps`, newest wins). Mirrors `store_example_plugin_path()` in `lib_tests.rs`.
fn plane_example_cdylib() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename("busbar_plugin_example_plane");
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
            "the plane example plugin cdylib is not built under CI: `cargo test --workspace` must \
             build busbar_plane_example (checked both the uplifted target dir and target/deps). \
             Refusing to silently skip the ONLY both-ways proof for kind:plane."
        );
    }
    candidate
}

/// Read one borrowed vocabulary range from the COMPILED-IN decl into an owned string (the same shape
/// `wire_up_plane` materialises the dropped-in side to, so the two are directly comparable).
fn vocab(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: the const's vocabulary points at this crate's own `'static` byte strings.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).unwrap().to_string()
}

/// The dropped-in decl the loader reads is byte-identical to the compiled-in `PLANE_DECL` at the
/// vocabulary / carrier surface — a plane loads the SAME whether compiled in or dropped in.
#[test]
fn example_plane_loads_identically_compiled_in_and_dropped_in() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let dropped = crate::load_plane(&lib).expect("load the example plane over the HOT-tier ABI");

    assert_eq!(dropped.name(), vocab(COMPILED_IN.name_ptr, COMPILED_IN.name_len));
    assert_eq!(
        dropped.section_key(),
        vocab(COMPILED_IN.section_key_ptr, COMPILED_IN.section_key_len)
    );
    assert_eq!(dropped.scope(), vocab(COMPILED_IN.scope_ptr, COMPILED_IN.scope_len));
    assert_eq!(dropped.label(), vocab(COMPILED_IN.label_ptr, COMPILED_IN.label_len));
    assert_eq!(dropped.provided_carriers(), COMPILED_IN.provided_carriers);
    // The wired carrier the example declares.
    assert!(dropped.provides(IngressCarrier::RequestResponse));
    assert!(!dropped.provides(IngressCarrier::DuplexSession));
    // Non-empty vocabulary — a decl that lost its name/section-key at the crossing would fail here.
    assert_eq!(dropped.name(), "example");
    assert_eq!(dropped.section_key(), "example");
}

/// The dropped-in plane is a LIVE plane: config_validate → build → hydrate → start → dispatch all
/// cross the ABI and return `Ok`, driven with an EMPTY host vtable (the example calls back into none
/// of its slots, so `PlaneHostVtable::EMPTY` is a sound host for the round trip).
#[test]
fn dropped_in_example_plane_builds_hydrates_starts_and_dispatches() {
    let Some(lib) = plane_example_cdylib() else {
        eprintln!("skip: plane example cdylib not built (run under --workspace)");
        return;
    };
    let plane = crate::load_plane(&lib).expect("load the example plane");

    // config_validate produces a parsed handle; free it.
    let (cv_status, parsed) = plane.config_validate(b"{}");
    assert_eq!(cv_status, StatusClass::Ok);
    if let Some(p) = parsed {
        if let Some(free) = p.free {
            free(p.ptr);
        }
    }

    // build with an EMPTY host vtable + null host ctx (the example never calls a host slot).
    let host = PlaneHostVtable::EMPTY;
    let host_ptr: *const PlaneHostVtable = &host;
    // SAFETY: `host_ptr` is a live EMPTY vtable that outlives this call; the example plane does not
    // dereference `host_ctx`.
    let (build_status, handle) =
        unsafe { plane.build(host_ptr, core::ptr::null_mut(), b"{}", &[]) };
    assert_eq!(build_status, StatusClass::Ok);
    let handle = handle.expect("build yields an opaque plane handle on Ok");
    assert!(!handle.ptr.is_null());

    // hydrate + start + dispatch drive the built state across the seam.
    // SAFETY: `handle.ptr` is the live state `build` just produced.
    assert_eq!(unsafe { plane.hydrate(handle.ptr) }, StatusClass::Ok);
    assert_eq!(unsafe { plane.start(handle.ptr) }, StatusClass::Ok);

    let inbound_bytes = b"ping";
    let work = WorkItem::new(
        InboundHandle::finite_buffer(inbound_bytes),
        EmitHandle::absent(),
    );
    // SAFETY: as above; `inbound_bytes` outlives the dispatch call.
    assert_eq!(unsafe { plane.dispatch(handle.ptr, &work) }, StatusClass::Ok);

    // Free the plane's state through its own `free` fn (the config-swap path core would take).
    if let Some(free) = handle.free {
        free(handle.ptr);
    }
}

/// `supported_abi("plane")` gates a plane's manifest `abi_version` against the airlock-minor axis.
#[test]
fn plane_supported_abi_covers_the_airlock_minor() {
    let range = crate::registry::supported_abi("plane");
    assert_eq!(range, &[1, busbar_plugin::ABI_MINOR]);
    // The five cold kinds still resolve; an unknown kind is still empty.
    assert!(!crate::registry::supported_abi("store").is_empty());
    assert!(crate::registry::supported_abi("nonsense").is_empty());
}
