// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[tokio::test]
async fn without_a_judge_every_destination_is_internal_and_the_condition_is_the_registered_diagnostic(
) {
    let judge = PlaneJudge::unavailable();
    let verdict = judge
        .judge(
            "example.com",
            0,
            0,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;
    assert_eq!(verdict, DEST_INTERNAL);
    assert_eq!(
        crate::diagnostics::PLANE_JUDGE_UNAVAILABLE.slug,
        "plane-judge-unavailable",
        "the row a plane's JUDGE logs is the catalogue's, not free text"
    );
}
