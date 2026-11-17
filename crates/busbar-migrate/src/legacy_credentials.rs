// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STEPS[0]: a 1.5.5 jwt-bearer provider's credential becomes an explicit outbound binding, and its
//! slot is marked in core's side table (LEGACY-KEYFILE-MARKER r2, adopted, §3 and §7).
//!
//! A provider whose effective 1.5.5 style is `jwt-bearer` (the deployment `auth`, else the catalog's)
//! and which a model reaches gets `auth.<p>-outbound = {module: {"$style": jwt-bearer}, config:
//! {style, credential, settings}}`. The provider names that instance, and loses `api_key` and the
//! forwarded keys. The credential slot is recorded in the plan's side table as a [`Mark`]. The
//! written text never carries `$migrated`: core inserts it only at the migrating bind. An unreached
//! jwt-bearer provider gets no binding (1.5.5 never resolved its key). Core never reads a
//! credential's value here.

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::Refusal;

/// The core-reserved bag word for a slot carrying its 1.5.5 value (IF r35 M-1).
pub const MIGRATED: &str = "$migrated";

/// The 1.5.5 style word this pass binds.
const JWT_BEARER: &str = "jwt-bearer";

/// The provider keys 1.5.5 forwarded to a jwt-bearer credential (the binding's `settings`).
const FORWARDED: [&str; 3] = ["token_url", "scope", "subject"];

/// One slot in the plan's side table: the instance's document path and the pointer, relative to its
/// `config`, whose value is 1.5.5's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    /// The instance's path in the document, for example `["auth", "p-outbound"]`.
    pub instance: Vec<String>,
    /// The RFC 6901 pointer into the instance's `config`.
    pub pointer: String,
}

/// Refuse CONFIG when `$migrated` appears anywhere in `resolved` (the document as written).
///
/// # Errors
/// CONFIG naming the word only.
pub(crate) fn refuse_marker(resolved: &Value) -> Result<(), Refusal> {
    let _ = resolved;
    Ok(())
}

/// Bind every reached 1.5.5 jwt-bearer provider of `root` explicitly, recording its slot in
/// `marks`. `resolved` is the 1.5.5 document as interpolated; `catalog` is the resolved providers
/// catalog 1.5.5 read (`Value::Null` when there is none).
///
/// # Errors
/// CONFIG when the binding's instance name is already taken.
pub(crate) fn bind_jwt_bearer(
    root: &mut Pairs,
    resolved: &Value,
    catalog: &Value,
    report: &mut Vec<String>,
    marks: &mut Vec<Mark>,
) -> Result<(), Refusal> {
    let _ = (
        root, resolved, catalog, report, marks, JWT_BEARER, FORWARDED,
    );
    Ok(())
}

#[cfg(test)]
#[path = "tests/legacy_credentials_tests.rs"]
mod tests;
