// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RESIDUAL ENVELOPE, asserted against the REAL linked planes: a plane claims a path only when
//! the operator's configuration mounts it.
//!
//! The planes come from the test-linked table (`tests/linked/mod.rs`); this file names none of
//! them. The table of which dialect answers which residual path shape is an llm-plane subject and
//! lives with that plane (`busbar-llm/tests/residual_dialect.rs`); the error-shaping mechanics the
//! table feeds stay pinned in `src/tests/tests.rs`.

mod linked;

use busbar_kernel::test_support::{oversized_413_body, TestApp};

/// A PLANE CLAIMS A PATH ONLY WHEN THE OPERATOR MOUNTED IT. With none of a plane's sections in the
/// configuration there is no such plane, so the path its key spells is an ordinary unclaimed path on
/// the residual and is answered as one. The merge must not turn an unmounted plane into one that
/// claims paths by URL shape. Driven for EVERY linked plane that mounts (the fallback plane is the
/// residual itself); the mounted twin is
/// `plane_integration::oversized_post_to_a_mounted_door_plane_is_refused_in_the_planes_own_dialect`.
#[tokio::test]
async fn an_unmounted_plane_claims_no_path_by_url_shape() {
    busbar_kernel::metrics::init();
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
        let app = TestApp::new().build();

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
