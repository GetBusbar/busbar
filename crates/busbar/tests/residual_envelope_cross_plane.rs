// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RESIDUAL ENVELOPE, asserted against the REAL linked planes: a plane claims a path only when
//! the operator's configuration mounts it.
//!
//! MOVED HERE from `crates/busbar-kernel/tests/` (kind-isolation, ARCHITECT: core names zero plane
//! types, its tests included; the door flip's analogue of 02bcf8300d): the cell needs a
//! plane that mounts a path, and every such plane is now served through its door, which the
//! composition root links and the kernel does not.
//!
//! The planes come from the test-linked table (`tests/linked/mod.rs`); this file names none of
//! them. The table of which dialect answers which residual path shape is the catch-all plane's
//! subject and lives with that plane (its own crate's residual-dialect suite); the error-shaping mechanics the
//! table feeds stay pinned in `src/tests/tests.rs`.

mod linked;

use busbar_kernel::test_support::{oversized_413_body, TestApp};

/// A PLANE CLAIMS A PATH ONLY WHEN THE OPERATOR MOUNTED IT. With none of a plane's sections in the
/// configuration there is no such plane, so the path its key spells is an ordinary unclaimed path on
/// the residual and is answered as one. The merge must not turn an unmounted plane into one that
/// claims paths by URL shape. Driven for EVERY linked plane that mounts (the fallback plane is the
/// residual itself); the mounted twin is
/// `crates/busbar/tests/plane_integration.rs::oversized_post_to_a_mounted_door_plane_is_refused_in_the_planes_own_dialect`.
#[tokio::test]
async fn an_unmounted_plane_claims_no_path_by_url_shape() {
    busbar_kernel::snapshot::init();
    let mounting: Vec<_> = linked::planes()
        .iter()
        .copied()
        .filter(|d| !d.fallback)
        .collect();
    assert!(
        !mounting.is_empty(),
        "the test-linked roster carries at least one plane that mounts a path"
    );
    for decl in mounting {
        let path = format!("/{}", decl.key);
        // No section of this plane is configured: `TestApp::new()` carries none.
        let app = TestApp::new().doors(linked::table()).build();

        let v = oversized_413_body(app, &path).await;

        assert!(
            v.get("jsonrpc").is_none(),
            "nothing mounted the `{}` plane, so `{path}` is a residual path and must not be \
             answered as a plane; got {v}",
            decl.key
        );
        assert!(
            v.pointer("/error/message").is_some(),
            "the residual plane answers the widely-understood envelope on `{path}`; got {v}"
        );
    }
}

/// THE KERNEL WORDS NO DIALECT ON A PATH NO PLANE TAKES (status row 82, D2; spec Part 1, Law 5:
/// dialects are internal to their plane; Part 3 section 12: a plane renders its own refusals
/// through its door). With the linked planes installed and none of them serving the configuration,
/// a refusal on a dialect-shaped path is the kernel's own envelope — `error.message` and
/// `error.type`, nothing a dialect's writer adds — because the kernel holds no protocol set to read
/// a dialect off the path with. A configuration 1.5.5 accepted opens the fallback plane's door,
/// whose claims take every such path and render its refusals, so no 1.5.5 answer moves.
///
/// RED before the drain: the kernel's residual arm read the linked dialect rows and answered the
/// path in the residual dialect's envelope (its `param` and `code` fields).
#[tokio::test]
async fn a_path_no_plane_serves_is_answered_in_the_kernels_own_envelope() {
    busbar_kernel::snapshot::init();
    linked::install();
    // No section of any plane is configured: `TestApp::new()` carries none.
    let app = TestApp::new().doors(linked::table()).build();

    let v = oversized_413_body(app, "/v1/chat/completions").await;

    let error = v
        .get("error")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("the kernel's envelope carries an `error` object; got {v}"));
    let mut keys: Vec<&str> = error.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["message", "type"],
        "the kernel's own envelope, with no field a dialect's writer adds; got {v}"
    );
    assert_eq!(
        v.as_object().map(serde_json::Map::len),
        Some(1),
        "nothing beside the `error` object; got {v}"
    );
}
