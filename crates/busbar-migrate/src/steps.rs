// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The chain: `STEPS[v]` takes a format-`v` document to format `v + 1`, over the operator's text.
//! 1.6.0 ships one step, STEPS[0] = 1.5.5 -> 1 (MIGRATE-ON-BOOT §A7 "STEPS[0], enumerated").

use std::path::Path;

use crate::templates::Template;
use crate::{
    absent_auth, absent_store, catalog, legacy_markers, migrate_1_6, overlay, patch, Facts, Refusal,
};

/// What a step reads beside the text, and what it plans besides it.
pub(crate) struct Work<'a> {
    /// config.yaml.
    pub(crate) path: &'a Path,
    /// The boot's facts.
    pub(crate) facts: &'a Facts,
    /// The 1.5.5 overlay 1b selected and read (`None`: a locked config, or not a 1.5.5 source).
    pub(crate) overlay: Option<&'a overlay::Read>,
    /// One line per change, for the boot's log (never a resolved value).
    pub(crate) report: &'a mut Vec<String>,
    /// The new providers catalog, when 1k plans one.
    pub(crate) catalog: Option<catalog::Planned>,
}

/// One step: the format-`v` text in, the format-`v + 1` text out (patch-writer edits only).
pub(crate) type Step = fn(&str, &mut Work<'_>) -> Result<String, Refusal>;

/// Indexed by the format a step reads; `STEPS.len()` is `CONFIG_FORMAT`.
pub(crate) const STEPS: [Step; 1] = [v0];

/// 1.5.5 -> 1, in §A3's order: 1t reads the template and its interpolation; 1a refuses a pre-1.5.5
/// document; 1b and 1c fold the 1.5.5 overlay 1b read into the operator's text (itself a patch
/// edit, checked by proof one), so core's passes read the folded document as template and
/// interpolation alike; 1d runs core's own passes and writes the store and the open posture 1.5.5
/// implied (#358); 1k plans the providers catalog. The result is the patch writer's, over the
/// operator's text, checked by proof one (in the writer) and proof two (interpolation parity); the
/// boot's strict parse (proof three) judges it after the stamp. A document that is not a mapping
/// passes as written, and the stamp and the strict parse refuse it in their own words.
fn v0(text: &str, work: &mut Work<'_>) -> Result<String, Refusal> {
    let template = Template::read(text, work.facts.env, "config.yaml")?;
    legacy_markers::refuse(template.resolved())?;
    let folded;
    let (text, template) = match work.overlay {
        Some(read) => {
            folded = overlay::fold(text, read, work.report)?;
            let template = Template::read(&folded, work.facts.env, "config.yaml")?;
            (folded.as_str(), template)
        }
        None => (text, template),
    };
    let mut after = template.tree().clone();
    if after.is_null() {
        after = busbar_contract::yaml::Value::Map(Vec::new());
    }
    let busbar_contract::yaml::Value::Map(root) = &mut after else {
        return Ok(text.to_owned());
    };
    migrate_1_6::run(root, template.resolved(), work.facts, work.report)?;
    crate::secret_instances::name_modules(root, work.report)?;
    match &work.facts.ephemeral_stores {
        Some(stores) => {
            absent_store::name_the_ephemeral_store(root, template.resolved(), stores, work.report)?;
        }
        None => absent_store::name_the_implied_store(root, template.resolved(), work.report),
    }
    absent_auth::write_open_posture(root, template.resolved(), work.report);
    work.catalog = catalog::plan(
        work.path,
        root,
        template.resolved(),
        work.facts,
        work.report,
    )?;
    let patched = patch::rewrite(text, template.tree(), &after, "config.yaml")?;
    if patched != text {
        template.parity(&patched, &after, work.facts.env, "config.yaml")?;
    }
    Ok(patched)
}

#[cfg(test)]
#[path = "tests/steps_tests.rs"]
mod tests;
