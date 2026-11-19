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

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use busbar_kernel::host_services::{KernelServices, TrustRefused};
use busbar_kernel::trust::book::{KeyRow, Reviewed, Ruling};

/// The route, as the admin taxonomy names it.
pub(crate) const PATTERN: &str = "/agents/{name}/approve";
/// The one item an agent offers the trust book (the A2A plane sights it under this name).
pub(crate) const ITEM: &str = "card";

/// One answer of the route: its status, the admin envelope's code when refused, and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
    /// The decision was applied (an effect to record and replay).
    pub(crate) applied: bool,
}

fn refused(status: u16, code: &str, message: &str) -> Answer {
    Answer {
        status,
        body: json::to_vec(&json::json!({ "error": { "code": code, "message": message } }))
            .unwrap_or_default(),
        applied: false,
    }
}

/// The fingerprint a body carries: `{"fingerprint": "<64 lowercase hex>"}` and nothing else.
pub(crate) fn fingerprint_of(body: &[u8]) -> Result<String, Answer> {
    let malformed = |message: &str| refused(400, "malformed_body", message);
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
/// the agent and whose item is its card. None: the agent was never connected (404). More than
/// one: two plane instances register an agent of that name, and the operator must say which
/// through the trust book's own route (409).
pub(crate) fn card_key(rows: &[KeyRow], agent: &str) -> Result<String, Answer> {
    let mut cards = rows
        .iter()
        .filter(|row| row.counterparty == agent && row.item.as_deref() == Some(ITEM));
    let Some(found) = cards.next() else {
        return Err(refused(
            404,
            "unknown_resource",
            "no card of that agent has been sighted: run `connect` first",
        ));
    };
    if cards.next().is_some() {
        return Err(refused(
            409,
            "ambiguous_agent",
            "more than one plane instance registers an agent of that name: approve its key \
             through POST /api/v1/admin/trust/approve",
        ));
    }
    Ok(found.key())
}

/// Approve `agent`'s card at the fingerprint the operator reviewed.
pub(crate) async fn approve(
    kernel: &KernelServices,
    agent: &str,
    body: &[u8],
    actor: &str,
    operation: Option<&str>,
) -> Answer {
    let fingerprint = match fingerprint_of(body) {
        Ok(fingerprint) => fingerprint,
        Err(answer) => return answer,
    };
    let key = match card_key(&kernel.trust_rows(), agent) {
        Ok(key) => key,
        Err(answer) => return answer,
    };
    let decided = kernel
        .trust_rule_by(
            &key,
            Ruling::Approve,
            Reviewed::Seen(&fingerprint),
            actor,
            operation,
        )
        .await;
    match decided.result {
        Ok(_) => Answer {
            status: 200,
            body: json::to_vec(&json::json!({
                "agent": agent,
                "fingerprint": fingerprint,
                "state": "approved",
            }))
            .unwrap_or_default(),
            applied: true,
        },
        Err(TrustRefused::NoSuchKey) => refused(
            404,
            "unknown_resource",
            "no card of that agent has been sighted: run `connect` first",
        ),
        Err(TrustRefused::Stale) => refused(
            409,
            "stale_fingerprint",
            "the agent's card is no longer the one reviewed: run `connect` again and approve \
             the fingerprint it reports",
        ),
        Err(TrustRefused::Ambiguous) => refused(
            409,
            "ambiguous_agent",
            "the agent's trust key names more than one row: approve it through \
             POST /api/v1/admin/trust/approve",
        ),
        Err(TrustRefused::NothingSighted) => refused(
            409,
            "nothing_sighted",
            "nothing of that agent has been sighted: run `connect` first",
        ),
        // Every other refusal is the trust book's own (no root, a failed verification, custody
        // unavailable): the operator reads the key's state on GET /api/v1/admin/trust.
        Err(_) => refused(
            503,
            "service_unavailable",
            "the trust book did not apply the approval: read the agent's key on \
             GET /api/v1/admin/trust",
        ),
    }
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
    fn the_body_is_one_fingerprint() {
        let body = format!(r#"{{"fingerprint":"{FP}"}}"#);
        assert_eq!(fingerprint_of(body.as_bytes()), Ok(FP.to_owned()));
        for bad in [
            "",
            "[]",
            "{}",
            r#"{"fingerprint":"abc"}"#,
            r#"{"fingerprint":7}"#,
            &format!(r#"{{"fingerprint":"{}"}}"#, FP.to_uppercase()),
            &format!(r#"{{"fingerprint":"{FP}","force":true}}"#),
        ] {
            let refused = fingerprint_of(bad.as_bytes()).unwrap_err();
            assert_eq!(refused.status, 400, "{bad}");
            assert!(!refused.applied);
        }
    }

    #[test]
    fn the_agents_card_is_one_trust_key() {
        let rows = [
            row("a2a", "billing", None),
            row("a2a", "billing", Some(ITEM)),
            row("a2a", "support", Some(ITEM)),
            row("mcp", "billing", Some("tool")),
        ];
        assert_eq!(
            card_key(&rows, "billing"),
            Ok("a2a/billing/card".to_owned())
        );
        assert_eq!(card_key(&rows, "nobody").unwrap_err().status, 404);
        let two = [
            row("a2a", "billing", Some(ITEM)),
            row("a2a-eu", "billing", Some(ITEM)),
        ];
        assert_eq!(card_key(&two, "billing").unwrap_err().status, 409);
    }
}
