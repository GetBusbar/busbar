// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /api/v1/admin/groups` PROJECTS ONE PAGE. The group tree grows at runtime — a self-service
//! mint auto-provisions a leaf per key — and the read is paginated for exactly that reason. Building
//! the wire view of EVERY group and then skipping to the page made each page cost the whole tree,
//! and walking the tree page by page cost its square, on the async worker at read-only scope.
//!
//! The registry is skipped to the page first and only the page's groups are projected. This scan
//! reads the read's own body and fails if a group is projected before the skip.

/// The body of `list_groups`, as written.
fn list_groups_body(source: &str) -> &str {
    let read = source
        .split("pub(crate) async fn list_groups(")
        .nth(1)
        .expect("the group list read is declared");
    read.split("\n    pub(crate) ")
        .next()
        .expect("the read's body ends")
}

/// Whether the body projects a group into its wire view before it skips to the page.
fn projects_before_the_skip(body: &str) -> bool {
    let code: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .flat_map(str::split_whitespace)
        .collect();
    match (code.find("GroupView::from_cfg"), code.find(".skip(")) {
        (Some(project), Some(skip)) => project < skip,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// RED while the read projected every group and then skipped to the page.
#[test]
fn the_group_list_projects_only_the_page_it_serves() {
    let source = include_str!("../src/v1/service_operations.rs");
    let body = list_groups_body(source);
    assert!(
        !projects_before_the_skip(body),
        "the group list projects every group before skipping to the page: {body}"
    );
}

/// The scan sees a projection ahead of the skip, and not a skip ahead of the projection.
#[test]
fn the_projection_scan_sees_a_whole_tree_projection() {
    let whole = "pub(crate) async fn list_groups(\n        let all: Vec<GroupView> = reg\n            .iter()\n            .map(|(n, c)| GroupView::from_cfg(n, c))\n            .collect();\n        let items = all.into_iter().skip(start).take(limit).collect();\n    pub(crate) fn next(";
    assert!(projects_before_the_skip(list_groups_body(whole)));
    let page = "pub(crate) async fn list_groups(\n        let items = reg\n            .iter()\n            .skip(start)\n            .take(limit)\n            .map(|(n, c)| GroupView::from_cfg(n, c))\n            .collect();\n    pub(crate) fn next(";
    assert!(!projects_before_the_skip(list_groups_body(page)));
}
