// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 8: hook attachments.
//!
//! A hook is DEFINED once in the top-level `hooks:` map and ATTACHED by bare name to an ordered
//! list: `pools.hooks` (every pool), `pools.<pool>.hooks`, a plane section's own `hooks`, or one
//! plane instance's `hooks`. `PUT|DELETE /hooks/{name}/attachments/{target}` edits exactly one of
//! those lists, as a whole-list `set` on the document layer, so an edit never depends on a list
//! index and rides the same Store transaction, source binding, shadow check and restart scoping as
//! every other document edit. `HookView.attachments` reads the same lists back.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use busbar_kernel::config::document_patch::DocumentPatch;
use busbar_kernel::state::{App, AppHandle};
use serde_json::{json, Value};

use super::config_document::{apply, DocumentRequest, EditAudit, Planner};
use super::{err_json, err_json_cond, if_match_version, json_body, respond, response_snapshot};
use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::{
    AdminError, HookAttachRequest, HookAttachment, HookPosition, HookPositionWord,
};
use crate::v1::service::AdminService;

/// One attach point, parsed from the `{target}` path segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Point {
    /// `pools`: fires for every pool.
    Pools,
    /// `pools.<pool>`.
    Pool(String),
    /// `<section>`: a plane section's own list.
    Section(String),
    /// `<section>.<instance>`: one plane instance's list.
    Instance(String, String),
}

impl Point {
    pub(super) fn parse(target: &str) -> Result<Self, AdminError> {
        let bad = || {
            AdminError::Validation(format!(
                "invalid attach target `{target}`: expected `pools`, `pools.<pool>`, `<section>` \
                 or `<section>.<instance>`"
            ))
        };
        if target.is_empty() {
            return Err(bad());
        }
        if target == "pools" {
            return Ok(Self::Pools);
        }
        if let Some(pool) = target.strip_prefix("pools.") {
            return if pool.is_empty() {
                Err(bad())
            } else {
                Ok(Self::Pool(pool.to_owned()))
            };
        }
        match target.split_once('.') {
            None => Ok(Self::Section(target.to_owned())),
            Some((section, instance)) if !section.is_empty() && !instance.is_empty() => {
                Ok(Self::Instance(section.to_owned(), instance.to_owned()))
            }
            Some(_) => Err(bad()),
        }
    }

    /// The RFC 6901 pointer to this point's list in the config document.
    pub(super) fn pointer(&self) -> String {
        fn seg(s: &str) -> String {
            s.replace('~', "~0").replace('/', "~1")
        }
        match self {
            Self::Pools => "/pools/hooks".into(),
            Self::Pool(pool) => format!("/pools/{}/hooks", seg(pool)),
            Self::Section(section) => format!("/{}/hooks", seg(section)),
            Self::Instance(section, instance) => {
                format!("/{}/{}/hooks", seg(section), seg(instance))
            }
        }
    }

    /// The error for a point the running configuration does not have.
    fn missing(&self) -> (AdminError, Option<Cond>) {
        match self {
            Self::Pools => (AdminError::Internal, None),
            Self::Pool(pool) => (
                AdminError::not_found(format!("pool `{pool}`")),
                Some(Cond::UnknownResource),
            ),
            Self::Section(section) => (
                AdminError::Validation(format!(
                    "no plane section `{section}` is configured; nothing to attach to"
                )),
                Some(Cond::InvalidConfig),
            ),
            Self::Instance(section, instance) => (
                AdminError::Validation(format!(
                    "`{section}` has no configured instance `{instance}`; nothing to attach to"
                )),
                Some(Cond::InvalidConfig),
            ),
        }
    }
}

fn names(value: Option<&Value>) -> Option<Vec<String>> {
    Some(
        value?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
    )
}

fn section_of<'a>(app: &'a App, key: &str) -> Option<&'a Value> {
    app.configured_view.as_ref()?.sections.get(key)
}

/// The attached hook names at `point` in the running configuration, in firing order; `None` when
/// the configuration has no such point.
pub(super) fn list_at(app: &App, point: &Point) -> Option<Vec<String>> {
    match point {
        Point::Pools => Some(app.global_hooks.clone()),
        Point::Pool(pool) => names(
            section_of(app, "pools")?
                .get("definitions")?
                .get(pool)?
                .get("gates"),
        ),
        Point::Section(section) => names(
            section_of(app, "hook_attachments")?
                .get(section)?
                .get("section"),
        ),
        Point::Instance(section, instance) => names(
            section_of(app, "hook_attachments")?
                .get(section)?
                .get("entries")?
                .get(instance),
        ),
    }
}

/// Every attach point of the running configuration with its list, in a stable order.
fn all_points(app: &App) -> Vec<(Point, Vec<String>)> {
    let mut out = vec![(Point::Pools, app.global_hooks.clone())];
    if let Some(Value::Object(defs)) = section_of(app, "pools").and_then(|p| p.get("definitions")) {
        let mut pools: Vec<_> = defs.keys().collect();
        pools.sort();
        for pool in pools {
            let point = Point::Pool(pool.clone());
            if let Some(list) = list_at(app, &point) {
                out.push((point, list));
            }
        }
    }
    if let Some(Value::Object(sections)) = section_of(app, "hook_attachments") {
        let mut keys: Vec<_> = sections.keys().collect();
        keys.sort();
        for section in keys {
            let point = Point::Section(section.clone());
            if let Some(list) = list_at(app, &point) {
                out.push((point, list));
            }
            let mut instances: Vec<String> = sections[section]
                .get("entries")
                .and_then(Value::as_object)
                .map(|e| e.keys().cloned().collect())
                .unwrap_or_default();
            instances.sort();
            for instance in instances {
                let point = Point::Instance(section.clone(), instance);
                if let Some(list) = list_at(app, &point) {
                    out.push((point, list));
                }
            }
        }
    }
    out
}

/// `HookView.attachments` for `hook`: every list that names it.
pub(crate) fn attachments_of(app: &App, hook: &str) -> Vec<HookAttachment> {
    attachments_in(all_points(app), hook)
}

/// [`attachments_of`] over already-read lists.
pub(super) fn attachments_in(points: Vec<(Point, Vec<String>)>, hook: &str) -> Vec<HookAttachment> {
    points
        .into_iter()
        .filter_map(|(point, list)| {
            let position = list.iter().position(|n| n == hook)?;
            let (target, instance) = match point {
                Point::Pools => ("pools".to_owned(), None),
                Point::Pool(pool) => (format!("pools.{pool}"), None),
                Point::Section(section) => (section, None),
                Point::Instance(section, instance) => {
                    (format!("{section}.{instance}"), Some(instance))
                }
            };
            Some(HookAttachment {
                target,
                instance,
                position: u32::try_from(position).unwrap_or(u32::MAX),
            })
        })
        .collect()
}

/// The list after attaching `hook` at `position`; `None` when the list already reads that way.
/// `last` on an attached hook leaves it where it is, so a repeated attach is a no-op.
pub(super) fn attach(
    list: &[String],
    hook: &str,
    position: HookPosition,
) -> Result<Option<Vec<String>>, AdminError> {
    let attached = list.iter().position(|n| n == hook);
    let mut next: Vec<String> = list.iter().filter(|n| *n != hook).cloned().collect();
    match position {
        HookPosition::Word(HookPositionWord::Last) => {
            if attached.is_some() {
                return Ok(None);
            }
            next.push(hook.to_owned());
        }
        HookPosition::Index(index) => {
            let index = usize::try_from(index).unwrap_or(usize::MAX);
            if index > next.len() {
                return Err(AdminError::Validation(format!(
                    "position {index} is past the end of the list (the last place is {})",
                    next.len()
                )));
            }
            next.insert(index, hook.to_owned());
        }
    }
    Ok((next != list).then_some(next))
}

/// The list after detaching `hook`; `None` when it was not attached.
pub(super) fn detach(list: &[String], hook: &str) -> Option<Vec<String>> {
    list.iter().any(|n| n == hook).then(|| {
        list.iter()
            .filter(|n| *n != hook)
            .cloned()
            .collect::<Vec<_>>()
    })
}

fn whole_list(point: &Point, list: &[String]) -> Result<DocumentRequest, AdminError> {
    DocumentPatch::from_value(json!({"set": {point.pointer(): list}}))
        .map(DocumentRequest::patch)
        .map_err(|error| AdminError::Validation(error.to_string()))
}

/// Everything refused before the transaction opens, each with its own closed reason.
fn admit(app: &App, hook: &str, point: &Point) -> Result<(), (AdminError, Option<Cond>)> {
    if !app.hook_registry.contains_key(hook) {
        return Err((
            AdminError::not_found(format!("hook `{hook}`")),
            Some(Cond::UnknownResource),
        ));
    }
    if app.base_hook_names.contains(hook) {
        return Err((
            AdminError::Conflict(format!(
                "hook `{hook}` is defined in the base config file; edit config.yaml (the API \
                 cannot silently shadow operator file config)"
            )),
            Some(Cond::BaseDefined),
        ));
    }
    if list_at(app, point).is_none() {
        return Err(point.missing());
    }
    Ok(())
}

fn refuse(
    action: &str,
    hook: &str,
    actor: &str,
    error: &AdminError,
    cond: Option<Cond>,
) -> Response {
    super::audit::AUDIT.record_by(
        action,
        &format!("hook:{hook}"),
        super::audit::OUTCOME_REJECTED,
        actor,
    );
    match cond {
        Some(cond) => err_json_cond(error, cond),
        None => err_json(error),
    }
}

async fn edit(
    handle: Arc<AppHandle>,
    principal: busbar_kernel::auth::AuthPrincipal,
    headers: busbar_kernel::inbound::http_projection::AdminHeaders,
    name: String,
    target: String,
    action: &'static str,
    // `Some` attaches at this position, `None` detaches.
    position: Option<HookPosition>,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(expected) => expected,
        Err(response) => return response,
    };
    let point = match Point::parse(&target) {
        Ok(point) => point,
        Err(error) => return refuse(action, &name, &actor, &error, Some(Cond::MalformedBody)),
    };
    if let Err((error, cond)) = admit(&handle.load(), &name, &point) {
        return refuse(action, &name, &actor, &error, cond);
    }
    let audit = EditAudit {
        action,
        resource: format!("hook:{name}"),
        origin: format!("{action} {target} by {actor}"),
        note: format!("{action} hook:{name} {target}"),
    };
    let planned = (point, name.clone());
    let plan: Planner = Box::new(move |app| {
        let (point, hook) = planned;
        let Some(list) = list_at(app, &point) else {
            return Err(point.missing().0);
        };
        let next = match position {
            Some(position) => attach(&list, &hook, position)?,
            None => Some(detach(&list, &hook).ok_or_else(|| {
                AdminError::not_found(format!(
                    "attachment of hook `{hook}` at `{}`",
                    target_of(&point)
                ))
            })?),
        };
        next.map(|next| whole_list(&point, &next)).transpose()
    });
    let committed = match apply(&handle, &actor, expected, audit, plan).await {
        Ok(committed) => committed,
        Err(response) => return *response,
    };
    committed.etag.attach(respond(
        StatusCode::OK,
        AdminService::new(response_snapshot(committed.installed).await)
            .get_hook(&name)
            .await,
    ))
}

fn target_of(point: &Point) -> String {
    match point {
        Point::Pools => "pools".into(),
        Point::Pool(pool) => format!("pools.{pool}"),
        Point::Section(section) => section.clone(),
        Point::Instance(section, instance) => format!("{section}.{instance}"),
    }
}

/// `PUT /hooks/{name}/attachments/{target}`.
pub(crate) async fn put_attachment(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path((name, target)): Path<(String, String)>,
    headers: busbar_kernel::inbound::http_projection::AdminHeaders,
    body: axum::body::Bytes,
) -> Response {
    let request: HookAttachRequest = match json_body(&body, "hook attachment") {
        Ok(request) => request,
        Err(response) => return *response,
    };
    edit(
        handle,
        principal,
        headers,
        name,
        target,
        "hook.attach",
        Some(request.position),
    )
    .await
}

/// `DELETE /hooks/{name}/attachments/{target}`.
pub(crate) async fn delete_attachment(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path((name, target)): Path<(String, String)>,
    headers: busbar_kernel::inbound::http_projection::AdminHeaders,
) -> Response {
    edit(
        handle,
        principal,
        headers,
        name,
        target,
        "hook.detach",
        None,
    )
    .await
}
