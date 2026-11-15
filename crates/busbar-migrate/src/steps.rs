// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The chain: `STEPS[v]` takes a format-`v` document to format `v + 1`, over the operator's text.
//! 1.6.0 ships one step, STEPS[0] = 1.5.5 -> 1 (MIGRATE-ON-BOOT §A7 "STEPS[0], enumerated").

use crate::{overlay, Refusal};

/// What a step reads besides the text: what step 1 found outside config.yaml.
pub(crate) struct Context<'a> {
    /// The 1.5.5 overlay 1b selected and read (`None`: a locked config, or not a 1.5.5 source).
    pub(crate) overlay: Option<&'a overlay::Read>,
}

/// One step: the format-`v` text in, the format-`v + 1` text out (patch-writer edits only), one
/// report line per change.
pub(crate) type Step = fn(&str, &Context<'_>, &mut Vec<String>) -> Result<String, Refusal>;

/// Indexed by the format a step reads; `STEPS.len()` is `CONFIG_FORMAT`.
pub(crate) const STEPS: [Step; 1] = [v0];

/// 1.5.5 -> 1. A 1.5.5 document whose core sections 1.6.0 reads unchanged passes as written; the
/// boot's strict parse then judges it, and a refusal carries `UPGRADE_FIRST`. 1c folds the
/// overlay 1b read. The passes that convert 1.5.5 shapes 1.6.0 reads differently join here as
/// they land (1a markers before the fold; 1d core passes and the absent store, 1k catalog, 1t
/// templates after it; §A7).
fn v0(text: &str, context: &Context<'_>, report: &mut Vec<String>) -> Result<String, Refusal> {
    match context.overlay {
        Some(read) => overlay::fold(text, read, report),
        None => Ok(text.to_owned()),
    }
}
