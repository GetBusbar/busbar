// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::auth_axis`.

use std::sync::Arc;

use busbar_contract::abi::auth::{AuthPoints, FACT_DEFAULT_INBOUND_STYLE, FACT_READS_CREDENTIALS};
use busbar_contract::abi::mechanism::door::REWRITE_ALIAS;
use busbar_contract::abi::mechanism::rendering::read;
use busbar_contract::auth_calls::InboundStyle;

use crate::auth_axis::{AuthRows, NO_DOOR};
use crate::dispatch::LinkedRow;
use crate::registry::{LoadablePlugin, RowRefusal};
use crate::sign::Verdict;

/// Boot: names the auth plugin that did not load.
#[cold]
pub(crate) fn load_refused(name: &str, e: &str) -> String {
    format!("auth plugin '{name}': {e}")
}

/// Boot: names why the auth plugin did not load.
#[cold]
pub(crate) fn row_refused(name: &str, e: RowRefusal) -> String {
    match e {
        RowRefusal::Stated(e) | RowRefusal::Bind(e) => load_refused(name, &e),
        RowRefusal::NoDoor => load_refused(name, NO_DOOR),
        RowRefusal::Load(e) => format!("auth plugin '{name}': {e}"),
    }
}

/// Boot: a loaded auth instance keeps its label.
#[cold]
pub(crate) fn instance(label: &str) -> Arc<str> {
    Arc::from(label)
}

/// Config: lists the linked auth modules config may name.
#[cold]
pub(crate) fn linked_names(rows: &AuthRows) -> Vec<String> {
    rows.linked_rows()
        .map(|p| p.manifest.alias.clone())
        .collect()
}

/// Config: the operator claims among the auth `rows`, read from each row's Statement with no
/// dlopen. A row whose Statement does not decode is listed as unreadable, never dropped. One
/// canonical plugin is one claim (two keys of it, or a dropped-in copy of a linked row); the
/// linked row is the one kept, as `cross_claim` keeps it.
#[cold]
pub(crate) fn operator_claims<'a>(
    rows: impl Iterator<Item = &'a LoadablePlugin>,
) -> busbar_contract::auth_calls::OperatorClaims {
    let mut kept: Vec<(bool, busbar_contract::auth_calls::OperatorClaim)> = Vec::new();
    let mut unreadable = Vec::new();
    rows.for_each(|row| {
        let facts = match crate::auth_axis::stated_of(row) {
            Ok(facts) => facts,
            Err(e) => {
                unreadable.push((row.manifest.alias.clone(), e));
                return;
            }
        };
        let Some(principal) = facts.and_then(|f| f.operator_principal) else {
            return;
        };
        let claim = busbar_contract::auth_calls::OperatorClaim {
            provider: row.manifest.alias.clone(),
            canonical: row.manifest.name.clone(),
            principal,
            first_party: row.first_party(),
            version: row.manifest.version.clone(),
            signer: match &row.verdict {
                Verdict::Trusted { publisher, .. } => publisher.clone(),
                Verdict::Allowed { reason, .. } => reason.clone(),
            },
        };
        match kept
            .iter_mut()
            .find(|(_, c)| c.canonical == claim.canonical)
        {
            Some(slot) if row.linked() && !slot.0 => *slot = (true, claim),
            Some(_) => {}
            None => kept.push((row.linked(), claim)),
        }
    });
    busbar_contract::auth_calls::OperatorClaims {
        claims: kept.into_iter().map(|(_, claim)| claim).collect(),
        unreadable,
    }
}

/// Config: lists the credential-reading auth plugins when config is read.
#[cold]
pub(crate) fn credential_readers(rows: &AuthRows) -> Vec<String> {
    rows.auth_rows()
        .filter_map(|row| {
            let facts = rows.stated(row)?;
            (facts.facts & FACT_READS_CREDENTIALS != 0).then(|| row.manifest.alias.clone())
        })
        .collect()
}

/// Config: names an inbound auth style when config is read.
#[cold]
pub(crate) fn inbound_style(row: &LoadablePlugin, points: AuthPoints) -> InboundStyle {
    let mut names = vec![
        row.manifest.name.clone(),
        row.key().to_string(),
        row.manifest.alias.clone(),
    ];
    names.extend(stated_aliases(row));
    names.sort();
    names.dedup();
    InboundStyle {
        module: row.manifest.name.clone(),
        names,
        points,
    }
}

/// Config: finds the default inbound style when config is read.
#[cold]
pub(crate) fn default_inbound_style(rows: &AuthRows) -> Result<Vec<String>, String> {
    let stating: Vec<(String, Vec<String>)> = rows
        .auth_rows()
        .filter_map(|row| {
            let facts = rows.stated(row)?;
            (facts.facts & FACT_DEFAULT_INBOUND_STYLE != 0)
                .then(|| (row.manifest.alias.clone(), facts.carriers))
        })
        .collect();
    match stating.as_slice() {
        [] => Ok(Vec::new()),
        [(_, carriers)] => Ok(carriers.clone()),
        many => {
            let aliases = many.iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>();
            Err(two_default_inbound_styles(&aliases))
        }
    }
}

/// Config: names every auth plugin stating the default inbound style.
#[cold]
pub(crate) fn two_default_inbound_styles(rows: &[&str]) -> String {
    format!(
        "more than one auth plugin states the default inbound style ({}): at most one may; \
         remove all but one",
        rows.join(", ")
    )
}

/// Boot: two auth plugins read the same credential kind.
#[cold]
pub(crate) fn two_readers(alias: &str, other: &str, kind: &str) -> String {
    format!(
        "auth plugins '{alias}' and '{other}' both declare they read the credential kind \
         '{kind}'; one verifier reads a credential kind"
    )
}

/// Boot: names a configured auth module no plugin answers to.
#[cold]
pub(crate) fn no_plugin(module: &str) -> String {
    format!("no `kind: auth` plugin answers to '{module}'")
}

/// Boot: an auth instance's settings did not render.
#[cold]
pub(crate) fn settings_unrendered(error: &serde_json::Error) -> String {
    error.to_string()
}

/// Boot: names the auth plugin that did not open.
#[cold]
pub(crate) fn open_failed(name: &str, e: &str) -> String {
    format!("plugin '{name}' open failed: {e}")
}

/// Config: binding an outbound style renders its settings once.
#[cold]
pub(crate) fn outbound_settings<S: serde::Serialize + ?Sized>(
    settings: &S,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(settings).map_err(|e| e.to_string())
}

/// Config: an auth plugin's stated aliases, read when config names a module.
#[cold]
pub(crate) fn stated_aliases(row: &LoadablePlugin) -> Vec<String> {
    let stated = match row.door() {
        Some(door) => LinkedRow::of_raw(door).ok().map(|r| r.statement),
        None => row.manifest.stated_rendering().ok().flatten(),
    };
    stated
        .and_then(|s| read(&s).ok())
        .map(|r| crate::boot::rewrites(&r, REWRITE_ALIAS).collect())
        .unwrap_or_default()
}
