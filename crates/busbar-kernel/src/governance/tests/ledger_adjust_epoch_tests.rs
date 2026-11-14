// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn arrival_comparison_preserves_millisecond_precision_and_equality() {
    let now = 1_234_567;
    assert_eq!(check_epoch(now - 1, now), Ok(()));
    assert_eq!(check_epoch(now, now), Ok(()));
    assert_eq!(
        check_epoch(now + 1, now),
        Err(AdjustRefused::FutureEpoch { at: now + 1, now })
    );
}
