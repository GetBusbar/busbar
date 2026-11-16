// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Route auth, identity and refusals over the plane port (IF §12.11, §12.15; PLANE-DRIVER.md slice 3).
//!
//! [`effective_classes`] picks the class set a route runs under from its `RouteRec.auth` mask and the operator's
//! `routes.<id>.auth`; [`classify`] picks the one class one request runs under (a ticket beside a principal is
//! decided per request); [`admit`] runs that class and answers what `PlaneIn` carries ([`Admitted`]: `auth`,
//! `identity`, `ticket_record`) or the [`ClientRefusal`] the request gets. A refusal is rendered by the plane in
//! its own dialect (`render(RENDER_REFUSAL)`, [`refuse`]); [`plain_refusal`] is core's own text when the plane
//! cannot render it.
//!
//! The verified principal is an input: the data auth chain (`auth/chain_run.rs`) runs before this and hands its
//! outcome in as a [`Principal`]. Tickets come through [`TicketDoor`], which the plane instance's boot binds to
//! `plane_grants::Tickets` under the instance's own caller.

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::fail::failed::F_UNAVAILABLE;
use busbar_plugin_abi::fail::refused::{
    R_AUTH_REQUIRED, R_BAD_CREDENTIAL, R_EXPIRED, R_POLICY, R_REPLAYED,
};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{
    AUTH_OPERATOR, AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_SIGNED_INGRESS, AUTH_TICKET,
    RENDER_REFUSAL,
};
use busbar_plugin_abi::records::{tag as g, Reply, Writer};
use busbar_plugin_loader::encode::plane::encode_refusal;
use busbar_plugin_loader::ports::plane::PlaneIn;
use busbar_plugin_loader::ports::PortError;

use super::port_session::{render, Calls, Effects, SessionError, ToClient};
use crate::plane_grants::{TicketAdmitted, TicketDenied};
use crate::refusal::{ClientRefusal, RefusalMap};

/// The route's mask or the operator's `routes.<id>.auth` names no usable class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassConfig;

/// The effective class set (§12.11): the operator's choice when it lies inside `mask` and is not empty, else the
/// lowest bit of `mask`, plus `AUTH_TICKET` when `mask` holds both `AUTH_PRINCIPAL` and `AUTH_TICKET`.
pub fn effective_classes(mask: u32, configured: Option<u32>) -> Result<u32, ClassConfig> {
    if mask == 0 {
        return Err(ClassConfig);
    }
    match configured {
        Some(set) if set != 0 && set & !mask == 0 => Ok(set),
        Some(_) => Err(ClassConfig),
        None => {
            let lowest = mask & mask.wrapping_neg();
            let both = AUTH_PRINCIPAL | AUTH_TICKET;
            Ok(if mask & both == both {
                lowest | AUTH_TICKET
            } else {
                lowest
            })
        }
    }
}

/// The tickets one plane instance admits.
pub trait TicketDoor: Send + Sync {
    /// Pure: the credential holds core's ticket marker.
    fn is_ticket(&self, credential: &str) -> bool;
    fn admit<'a>(
        &'a self,
        audience: &'a str,
        credential: &'a str,
        now_s: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>>;
}

/// A door for a route that has no credential header (a line): nothing is a ticket.
pub struct NoTickets;

impl TicketDoor for NoTickets {
    fn is_ticket(&self, _credential: &str) -> bool {
        false
    }

    fn admit<'a>(
        &'a self,
        _audience: &'a str,
        _credential: &'a str,
        _now_s: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        Box::pin(async { Err(TicketDenied::Invalid) })
    }
}

/// The one class this request runs under. A set of {PRINCIPAL, TICKET} reads the request's credential: a ticket
/// runs TICKET, anything else PRINCIPAL. Any other set runs its lowest bit.
#[must_use]
pub fn classify(effective: u32, bearer: Option<&str>, tickets: &dyn TicketDoor) -> u32 {
    if effective.count_ones() <= 1 {
        return effective;
    }
    let both = AUTH_PRINCIPAL | AUTH_TICKET;
    if effective & both == both && effective & !both == 0 {
        return if bearer.is_some_and(|b| tickets.is_ticket(b)) {
            AUTH_TICKET
        } else {
            AUTH_PRINCIPAL
        };
    }
    effective & effective.wrapping_neg()
}

/// The `Authorization: Bearer` credential among `headers` (name case-insensitive, scheme case-insensitive).
pub fn bearer<'a>(mut headers: impl Iterator<Item = (&'a str, &'a [u8])>) -> Option<&'a str> {
    headers.find_map(|(name, value)| {
        if !name.eq_ignore_ascii_case("authorization") {
            return None;
        }
        let value = std::str::from_utf8(value).ok()?;
        let (scheme, rest) = value.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
    })
}

/// What the data auth chain made of the request's credential.
#[derive(Clone, Copy, Debug)]
pub enum Principal<'a> {
    /// Verified: the ID_SUBJECT, ID_GROUP*, ID_CLAIM* records (`Identity::identity_records`).
    Verified(&'a [u8]),
    /// No credential, or every auth instance answered NOT_MINE.
    Anonymous,
    /// An auth instance refused it: its kind code.
    Rejected(u32),
}

/// What the request carries into admission.
#[derive(Clone, Copy, Debug)]
pub struct Credentials<'a> {
    pub bearer: Option<&'a str>,
    pub principal: Principal<'a>,
    /// An operator principal is present (AUTH_OPERATOR).
    pub operator: bool,
    /// The route's webhook signature check: `Some(verified)`, `None` when it was not run.
    pub signed: Option<bool>,
}

/// An admitted request: the class it ran under and what the plane is handed.
pub struct Admitted {
    pub auth: u32,
    pub identity: Vec<u8>,
    ticket_record: Option<SecureVec>,
}

/// The class and the identity's length: the identity bytes and the ticket record are credentials-adjacent and
/// never print.
impl std::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted")
            .field("auth", &self.auth)
            .field("identity_len", &self.identity.len())
            .finish_non_exhaustive()
    }
}

impl Admitted {
    /// `PlaneReq.ticket_record`: non-empty only for a ticket that carried one.
    #[must_use]
    pub fn ticket_record(&self) -> &[u8] {
        self.ticket_record.as_deref().unwrap_or_default()
    }
}

/// One ID_SUBJECT record: the identity of a principal core verified outside the auth chain (a line carrier's).
#[must_use]
pub fn subject_identity(subject: &str) -> Vec<u8> {
    let mut w = Reply::with_capacity(16 + subject.len());
    // A Reply refuses only past its 16 MiB cap; a subject is bounded far below it.
    let put = w.put_text(g::ID_SUBJECT, subject);
    debug_assert!(put.is_ok(), "a subject identity fits a Reply");
    w.as_bytes().to_vec()
}

fn ticket_refusal(route: u32, denied: TicketDenied, refusals: &dyn RefusalMap) -> ClientRefusal {
    match denied {
        TicketDenied::Invalid => refusals.for_core(route, R_BAD_CREDENTIAL),
        TicketDenied::Expired => refusals.for_core(route, R_EXPIRED),
        TicketDenied::Replayed => refusals.for_core(route, R_REPLAYED),
        // The store could not be reached: fail closed as an unavailable backend, never as a credential verdict.
        TicketDenied::Unavailable => refusals.for_port(
            route,
            &PortError::Failed {
                code: F_UNAVAILABLE,
                text: "ticket store unavailable".into(),
                retry_after_s: None,
                backend_status: None,
                error: None,
            },
        ),
    }
}

/// Runs the class `classify` picked and answers `PlaneIn`'s auth, identity and ticket record, or the refusal.
/// A ticket refusal is final: it is never retried as PRINCIPAL.
pub async fn admit(
    route: u32,
    effective: u32,
    creds: &Credentials<'_>,
    tickets: &dyn TicketDoor,
    refusals: &dyn RefusalMap,
    audience: &str,
    now_s: u64,
) -> Result<Admitted, ClientRefusal> {
    let class = classify(effective, creds.bearer, tickets);
    let admitted = |identity: Vec<u8>| Admitted {
        auth: class,
        identity,
        ticket_record: None,
    };
    match class {
        AUTH_PRINCIPAL => match creds.principal {
            Principal::Verified(id) => Ok(admitted(id.to_vec())),
            Principal::Anonymous => Err(refusals.for_core(route, R_AUTH_REQUIRED)),
            Principal::Rejected(code) => Err(refusals.for_auth(route, code)),
        },
        AUTH_OPTIONAL => match creds.principal {
            Principal::Verified(id) => Ok(admitted(id.to_vec())),
            Principal::Anonymous => Ok(admitted(Vec::new())),
            Principal::Rejected(code) => Err(refusals.for_auth(route, code)),
        },
        AUTH_PUBLIC => Ok(admitted(Vec::new())),
        AUTH_TICKET => {
            let Some(credential) = creds.bearer else {
                return Err(refusals.for_core(route, R_AUTH_REQUIRED));
            };
            match tickets.admit(audience, credential, now_s).await {
                Ok(t) => Ok(Admitted {
                    auth: class,
                    identity: t.identity.identity_records().to_vec(),
                    ticket_record: t.record.filter(|r| !r.is_empty()),
                }),
                Err(denied) => Err(ticket_refusal(route, denied, refusals)),
            }
        }
        AUTH_SIGNED_INGRESS => {
            if creds.signed == Some(true) {
                Ok(admitted(Vec::new()))
            } else {
                Err(refusals.for_core(route, R_BAD_CREDENTIAL))
            }
        }
        AUTH_OPERATOR => {
            if !creds.operator {
                return Err(refusals.for_core(route, R_POLICY));
            }
            match creds.principal {
                Principal::Verified(id) => Ok(admitted(id.to_vec())),
                _ => Ok(admitted(Vec::new())),
            }
        }
        // An empty or unknown set cannot come out of `effective_classes`.
        _ => Err(refusals.for_core(route, R_POLICY)),
    }
}

/// Core's own rendering of a refusal: the status, its text as `text/plain`, and the end.
#[must_use]
pub fn plain_refusal(refusal: &ClientRefusal) -> Vec<ToClient> {
    vec![
        ToClient::Head {
            status: refusal.status,
            fields: vec![(
                b"content-type".to_vec(),
                b"text/plain; charset=utf-8".to_vec(),
            )],
        },
        ToClient::Body(refusal.text.as_bytes().to_vec()),
        ToClient::End,
    ]
}

/// The client items of a refusal: the plane renders it in its dialect (`render(RENDER_REFUSAL)`, arg = one
/// REFUSAL record); when it cannot (it failed, broke the answer's shape, or the record would not encode), core's
/// own [`plain_refusal`] is used.
pub fn refuse<K: Calls + ?Sized>(
    calls: &K,
    req: &PlaneIn<'_>,
    refusal: &ClientRefusal,
    effects: &dyn Effects,
) -> Vec<ToClient> {
    let mut arg = Reply::new();
    if encode_refusal(&mut arg, refusal.status, refusal.code, &refusal.text).is_err() {
        return plain_refusal(refusal);
    }
    match render(calls, req, RENDER_REFUSAL, arg.as_bytes(), effects) {
        Ok(items) if !items.is_empty() => items,
        Ok(_) => plain_refusal(refusal),
        Err(error) => {
            tracing::warn!(
                ?error,
                "a plane could not render a refusal; core's text is used"
            );
            plain_refusal(refusal)
        }
    }
}

/// `render(RENDER_CATALOG)` for a ROUTE_CATALOG route: arg = one CAT_MODEL per model.
pub fn catalog<K: Calls + ?Sized>(
    calls: &K,
    req: &PlaneIn<'_>,
    models: &[&str],
    effects: &dyn Effects,
) -> Result<Vec<ToClient>, SessionError> {
    let mut arg = Reply::new();
    busbar_plugin_loader::encode::plane::encode_catalog(&mut arg, models)
        .map_err(|_| SessionError::Encode)?;
    render(
        calls,
        req,
        busbar_plugin_abi::plane::RENDER_CATALOG,
        arg.as_bytes(),
        effects,
    )
}

#[cfg(test)]
#[path = "tests/port_auth_tests.rs"]
mod tests;
