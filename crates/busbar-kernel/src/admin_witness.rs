// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS-WIDE ADMIN-ERROR WITNESS LEDGER — a neutral, single-copy home for the taxonomy-drift
//! audit's record of "which (operation, error-kind, condition) an admin response has actually
//! produced".
//!
//! ## Why it lives here and not in `busbar-core`
//!
//! `busbar-core`'s own test binary links `busbar-core` TWICE: once as the crate-under-test
//! (`cfg(test)`) and once as an ordinary dependency of the extracted plane crates (`busbar-mcp` /
//! `busbar-a2a`), whose admin-verb drivers drive requests through THAT copy's recording layer. A
//! `static` witness set in `busbar-core` would therefore split in two — the plane emissions landing
//! in the dependency copy, the audit reading the test copy — and the cross-plane over-claim check
//! would report every plane trust-verb response as un-witnessed. `busbar-substrate` is a plain
//! dependency of all three crates, compiled ONCE with feature unification, so a witness ledger here is
//! the one both copies of `busbar-core` reach. The keys are NEUTRAL strings (the operation's relative
//! path, the HTTP method, the error kind, an optional condition) precisely so this crate names none of
//! `busbar-core`'s taxonomy enums.

use std::collections::BTreeSet;
use std::sync::Mutex;

/// One witnessed emission as neutral strings: `(rel, method, kind, cond)`.
pub type Witness = (String, String, String, Option<String>);

static WITNESSED: Mutex<BTreeSet<Witness>> = Mutex::new(BTreeSet::new());

/// Record one observed admin-error emission. Called from `busbar-core`'s recording layer in EITHER
/// copy of the crate; both reach this one ledger.
pub fn record(rel: &str, method: &str, kind: &str, cond: Option<&str>) {
    if let Ok(mut set) = WITNESSED.lock() {
        set.insert((
            rel.to_string(),
            method.to_string(),
            kind.to_string(),
            cond.map(str::to_string),
        ));
    }
}

/// Every emission the process has witnessed so far, across both copies of `busbar-core`.
pub fn snapshot() -> BTreeSet<Witness> {
    WITNESSED.lock().map(|s| s.clone()).unwrap_or_default()
}
