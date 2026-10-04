// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN-ERROR WITNESS LEDGER — the taxonomy-drift audit's record of "which (operation,
//! error-kind, condition) an admin response has actually produced". Test builds only.
//!
//! The recording layer of the v1 router (this crate) writes it; the over-claim audit in this crate's
//! tests reads it. The keys are neutral strings (the operation's relative path, the HTTP method, the
//! error kind's `Debug` name, an optional condition's `Debug` name). Relocated from the kernel's
//! `admin_witness` (D4): the kernel's `taxonomy::observed` keeps only the response `Tag`.

use std::collections::BTreeSet;
use std::sync::Mutex;

use busbar_kernel::admin::v1::contract::taxonomy::{observed::Tag, MethodTag};

/// One witnessed emission as neutral strings: `(rel, method, kind, cond)`.
pub type Witness = (String, String, String, Option<String>);

static WITNESSED: Mutex<BTreeSet<Witness>> = Mutex::new(BTreeSet::new());

/// Record one observed admin-error emission (called by the recording layer).
pub fn record(rel: &str, method: MethodTag, tag: Tag) {
    if let Ok(mut set) = WITNESSED.lock() {
        set.insert((
            rel.to_string(),
            method.as_str().to_string(),
            format!("{:?}", tag.kind),
            tag.cond.map(|c| format!("{c:?}")),
        ));
    }
}

/// Every emission the process has witnessed so far.
pub fn snapshot() -> BTreeSet<Witness> {
    WITNESSED.lock().map(|s| s.clone()).unwrap_or_default()
}
