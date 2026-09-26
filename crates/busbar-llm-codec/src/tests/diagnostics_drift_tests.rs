// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE-CODE DRIFT GUARD (#83a O4): every code this plane defines is the host catalog's entry of
//! the same number, field for field — code, class, slug, title, severity, summary, action, since and
//! the retired flag — so `docs/diagnostics.md` / `docs/diagnostics.json`, which the host renders from
//! its catalog, describe exactly what this plane prints. A constant edited here and not there, or
//! there and not here, fails this suite.

use super::DIAGNOSTICS;

#[test]
fn every_plane_code_is_the_catalog_entry_of_its_number() {
    for &d in DIAGNOSTICS {
        let catalog = busbar_kernel::diagnostics::by_code(d.code)
            .unwrap_or_else(|| panic!("BUSBAR-{:04} is not in the host catalog", d.code));
        assert_eq!(
            format!("{d:?}"),
            format!("{catalog:?}"),
            "BUSBAR-{:04} differs from the host catalog entry",
            d.code
        );
    }
}

#[test]
fn the_plane_declares_fifteen_distinct_codes() {
    let mut codes: Vec<u16> = DIAGNOSTICS.iter().map(|d| d.code).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 15, "a plane code is listed twice or missing");
}
