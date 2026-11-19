// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `POST /api/v1/admin/agents/{name}/approve`: the operator's second act on an A2A agent. The
//! first is the plane's `connect` verb, which fetches the agent's card, records the sighting and
//! reports its fingerprint; this one approves that fingerprint.
//!
//! Approving is core's and only core's: the trust book is not a plane's to write (IF 12.14). This
//! route is the trust book's own decision (`POST /api/v1/admin/trust/approve`) addressed the way an
//! operator of agents thinks of it: by the agent's name, with the fingerprint `connect` reported.
//! It finds the one trust key that is that agent's card and approves it at that fingerprint, so a
//! card that changed between `connect` and `approve` is refused as stale, never approved unseen.
//! The decision itself is the trust verbs' one path ([`bound::trust_rule_effect`]): the same
//! refusals, the same unknown-outcome receipt, and the kernel's typed audit row as the one row.

use std::sync::atomic::AtomicBool;

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use busbar_core_admin::GovernanceError;
use busbar_kernel::host_services::KernelServices;
use busbar_kernel::trust::book::{KeyRow, Reviewed, Ruling};

use crate::root::units_admin::bound::{self, EffectAnswer};
use crate::root::units_admin::AdminAnswer;

/// The one item an agent offers the trust book (the A2A plane sights it under this name).
pub(crate) const ITEM: &str = "card";

const PREFIX: &str = "/api/v1/admin/agents/";
const SUFFIX: &str = "/approve";

/// The agent a request path names: the one segment between `/agents/` and `/approve`.
pub(crate) fn agent_of(path: &str) -> Option<&str> {
    path.strip_prefix(PREFIX)
        .and_then(|rest| rest.strip_suffix(SUFFIX))
        .filter(|agent| !agent.is_empty() && !agent.contains('/'))
}

/// The fingerprint a body carries: `{"fingerprint": "<64 lowercase hex>"}` and nothing else.
pub(crate) fn fingerprint_of(body: &[u8]) -> Result<String, AdminAnswer> {
    let malformed = |message: &str| bound::trust_refused("malformed_body", message);
    let doc: json::Value =
        json::parse_value(body).map_err(|_| malformed("the body must be JSON `{fingerprint}`"))?;
    let object = doc
        .as_object()
        .ok_or_else(|| malformed("the body must be an object `{fingerprint}`"))?;
    if let Some((member, _)) = object.iter().find(|(member, _)| *member != "fingerprint") {
        return Err(malformed(&format!(
            "unknown member `{member}`: the body is `{{fingerprint}}`"
        )));
    }
    let fingerprint = object
        .get(&"fingerprint")
        .and_then(json::Value::as_str)
        .ok_or_else(|| malformed("fingerprint is required: send the one `connect` reported"))?;
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(malformed(
            "fingerprint is the 64 lowercase hex digits `connect` reported",
        ));
    }
    Ok(fingerprint.to_owned())
}

/// The trust key of `agent`'s card among the book's rows: exactly one row whose counterparty is
/// the agent and whose item is its card. None: the agent's card was never sighted (404). More than
/// one: two plane instances register an agent of that name, and the operator must say which
/// through the trust book's own route (409).
pub(crate) fn card_key(rows: &[KeyRow], agent: &str) -> Result<String, AdminAnswer> {
    let mut cards = rows
        .iter()
        .filter(|row| row.counterparty == agent && row.item.as_deref() == Some(ITEM));
    let Some(found) = cards.next() else {
        return Err(bound::trust_refused(
            "unknown_resource",
            &format!("no card of agent `{agent}` has been sighted: run `connect` first"),
        ));
    };
    if cards.next().is_some() {
        return Err(bound::trust_refused(
            "state_conflict",
            &format!(
                "more than one plane instance registers an agent named `{agent}`: approve its \
                 card's key through POST /api/v1/admin/trust/approve"
            ),
        ));
    }
    Ok(found.key())
}

/// Approve `agent`'s card at the fingerprint the operator reviewed. `audited` reports to the walk
/// whether the kernel wrote this request's typed audit row.
pub(crate) async fn approve(
    kernel: Option<&KernelServices>,
    path: &str,
    body: &[u8],
    actor: &str,
    operation: Option<&str>,
    audited: &AtomicBool,
) -> Result<EffectAnswer, GovernanceError> {
    let unapplied = |answer: AdminAnswer| Ok(EffectAnswer::unapplied(answer));
    let Some(agent) = agent_of(path) else {
        return unapplied(bound::trust_refused(
            "unknown_resource",
            "the path names no agent",
        ));
    };
    let fingerprint = match fingerprint_of(body) {
        Ok(fingerprint) => fingerprint,
        Err(answer) => return unapplied(answer),
    };
    let Some(kernel) = kernel else {
        return unapplied(bound::trust_refused(
            "service_unavailable",
            "native trust custody is not installed on this node",
        ));
    };
    let key = match card_key(&kernel.trust_rows(), agent) {
        Ok(key) => key,
        Err(answer) => return unapplied(answer),
    };
    bound::trust_rule_effect(
        kernel,
        &key,
        Ruling::Approve,
        Reviewed::Seen(&fingerprint),
        actor,
        operation,
        audited,
        |_| {
            json::to_vec(&json::json!({
                "agent": agent,
                "key": key.as_str(),
                "fingerprint": fingerprint.as_str(),
                "state": "approved",
            }))
            .map(|body| bound::raw_json_answer(200, body))
            .map_err(|_| GovernanceError::Store)
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn row(instance: &str, counterparty: &str, item: Option<&str>) -> KeyRow {
        KeyRow {
            instance: instance.into(),
            counterparty: counterparty.into(),
            item: item.map(str::to_owned),
            state: busbar_kernel::trust::book::KeyState::New,
            approved: None,
            seen: Some(FP.into()),
        }
    }

    #[test]
    fn an_agent_approve_path_names_one_agent() {
        assert_eq!(
            agent_of("/api/v1/admin/agents/billing/approve"),
            Some("billing")
        );
        for bad in [
            "/api/v1/admin/agents//approve",
            "/api/v1/admin/agents/a/b/approve",
            "/api/v1/admin/agents/billing/connect",
            "/api/v1/admin/trust/approve",
        ] {
            assert_eq!(agent_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn an_agent_approve_body_is_one_fingerprint() {
        let body = format!(r#"{{"fingerprint":"{FP}"}}"#);
        assert_eq!(fingerprint_of(body.as_bytes()).ok(), Some(FP.to_owned()));
        for bad in [
            "",
            "[]",
            "{}",
            r#"{"fingerprint":"abc"}"#,
            r#"{"fingerprint":7}"#,
            &format!(r#"{{"fingerprint":"{}"}}"#, FP.to_uppercase()),
            &format!(r#"{{"fingerprint":"{FP}","force":true}}"#),
        ] {
            let refused = fingerprint_of(bad.as_bytes()).expect_err(bad);
            assert_eq!(refused.status, 400, "{bad}");
        }
    }

    #[test]
    fn an_agent_approve_names_the_one_card_key() {
        let rows = [
            row("a2a", "billing", None),
            row("a2a", "billing", Some(ITEM)),
            row("a2a", "support", Some(ITEM)),
            row("mcp", "billing", Some("tool")),
        ];
        assert_eq!(card_key(&rows, "billing").ok(), Some("a2a/billing/card".into()));
        assert_eq!(card_key(&rows, "nobody").map_err(|a| a.status), Err(404));
        let two = [
            row("a2a", "billing", Some(ITEM)),
            row("a2a-eu", "billing", Some(ITEM)),
        ];
        assert_eq!(card_key(&two, "billing").map_err(|a| a.status), Err(409));
    }
}
