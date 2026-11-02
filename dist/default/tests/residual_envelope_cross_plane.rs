// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

use busbar_kernel_testkit::test_support::{oversized_413_body, TestApp};

#[tokio::test]
async fn an_unmounted_plane_claims_no_path_by_url_shape() {
    busbar_kernel_testkit::test_support::metrics::init();
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
