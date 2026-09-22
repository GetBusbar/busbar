// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The mint-time group plan — moved verbatim (as logic; the store calls it makes are now trait
//! calls) from `busbar-core::admin::v1::json::handlers::plan_mint_group`.
//!
//! Three cases, exactly as the source states them:
//!
//! - group EXISTS, no `parent` given → bind as-is.
//! - group EXISTS, `parent` given → the given parent MUST equal the group's actual parent, else a
//!   conflict (a mint never re-homes an existing group).
//! - group MISSING, `parent` given → provision it as a leaf under `parent`, PROVIDED `parent`
//!   itself exists — existence is the only check on the named parent (the architecture document's
//!   "parity clause; no containment rule": there is no rule that the caller must own, administer,
//!   or otherwise have a relationship to `parent` beyond it existing in the group tree).
//! - group MISSING, no `parent` → refused (nowhere to root it).

use crate::refusal::{ReasonCode, Refusal, RefusalStep};

/// The plan-decision's view of the group tree. `// contract:` — the integrator binds this to the
/// real config/cost-model group registry (`busbar-core`'s `cost.group_named` /
/// `groups_registry`); this crate only asks two questions of it: does a name exist, and if so what
/// is its actual parent.
pub trait GroupLookup {
    /// Does a group with this exact name exist?
    fn group_exists(&self, name: &str) -> bool;
    /// The EXISTING group's actual parent, if any (root groups return `None`). Only meaningful when
    /// [`GroupLookup::group_exists`] is true for `name`; callers here never call it otherwise.
    fn actual_parent(&self, name: &str) -> Option<String>;
}

/// What a mint should do about its `group`/`parent` argument pair, decided PURELY from the current
/// tree shape — no lock is taken and no write happens here (the source's own doc: "PURE and
/// SYNCHRONOUS... takes no lock and performs no swap"). The caller is expected to run the
/// provisioning write, when one is planned, inside the same transaction that then binds the key —
/// exactly as the source note about "one continuous lock hold" describes; this crate has no lock to
/// hold across the two, since the actual store write is the integrator's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintPlan {
    /// The group already exists (or none was named) — bind the key to it as-is.
    BindAsIs,
    /// The group does not exist; provision it as a leaf under `parent` (which does exist) before
    /// binding.
    ProvisionLeaf {
        /// The parent to provision the new leaf under.
        parent: String,
    },
}

/// The longest a group/parent name may be (mirrors `busbar-core`'s `MAX_GROUP_NAME_LEN`; kept as a
/// caller-supplied bound rather than a crate constant so a future change to that ceiling needs no
/// change here).
pub fn plan_mint_group(
    lookup: &impl GroupLookup,
    group: Option<&str>,
    parent: Option<&str>,
    max_group_name_len: usize,
) -> Result<MintPlan, Refusal> {
    let Some(group) = group else {
        // No group named at all: nothing to plan, nothing to provision. `parent` without `group`
        // is refused by the caller before this is ever reached (it names nothing to root).
        return Ok(MintPlan::BindAsIs);
    };
    if lookup.group_exists(group) {
        if let Some(want) = parent {
            let actual = lookup.actual_parent(group);
            if actual.as_deref() != Some(want) {
                // A mint cannot re-home an existing group.
                return Err(Refusal::new(RefusalStep::Verify, ReasonCode::Conflict));
            }
        }
        return Ok(MintPlan::BindAsIs);
    }
    // The group does not exist. Without a parent there is nowhere to root it.
    let Some(parent) = parent else {
        return Err(Refusal::new(RefusalStep::Verify, ReasonCode::Validation));
    };
    if parent.len() > max_group_name_len {
        return Err(Refusal::new(RefusalStep::Verify, ReasonCode::Validation));
    }
    // Existence-only check on the named parent — no containment rule (parity clause).
    if !lookup.group_exists(parent) {
        return Err(Refusal::new(RefusalStep::Verify, ReasonCode::Validation));
    }
    Ok(MintPlan::ProvisionLeaf {
        parent: parent.to_string(),
    })
}

#[cfg(test)]
#[path = "tests/mint_tests.rs"]
mod tests;
