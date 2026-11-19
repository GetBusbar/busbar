// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ticket verifier of the native path: step 2 of a route whose admission is
//! [`Admission::Ticket`] (`VerifyBy::TicketOrChain`).
//!
//! A ticket is core's own credential, minted for a principal that was verified and judged on the
//! issuance route. Core's ticket store ([`crate::plane_grants::Tickets`]) seals what a ticket is
//! for: the plane image, the plane instance's configured name, the audience (the door it opens),
//! its subject, its expiry and its single use. That is not yet who may spend it: a subject is a
//! name, and money, limits and scope are judged against a key. This module binds the two halves.
//!
//! * At the mint ([`IssuerBound::mint`]) the issuer's governed key, the door and the expiry are
//!   written into the row core keeps for the ticket, around the plane's own record. The mint is
//!   refused when no verified principal of that subject is being served on the minting instance
//!   (issuance is an authenticated act), the ticket is always single-use, and its life is held
//!   under [`TICKET_LIFE_MAX_S`] and the issuer key's own expiry.
//! * At the door ([`IssuerBound::redeem`]) the seal is opened and the row taken (one request on
//!   any replica wins), the door and expiry are checked again from the row, and the issuer is
//!   asked for as it stands NOW. The key the request runs under is the standing one, never the
//!   one the row remembers: a ticket admits what its issuer can do at the moment it is spent,
//!   and nothing once the issuer is disabled, deleted, expired, rotated or unbound.
//!
//! [`NativeTicketVerifier::verify`] is what the listener calls. Its answer is the fact the
//! admission table reads ([`Verified::Ticket`], [`Verified::Denied`], [`Verified::Unavailable`]):
//! every refusal of a presented ticket is the one 401, the reason goes to the log, and a ticket
//! store that cannot answer is the 503. A presented ticket that is refused never falls through to
//! the route's chain.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use busbar_contract::records::VirtualKey;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_ports::auth::Identity;

use super::admission_table::{Admission, Facts, Verified, VerifyBy};
use super::route_record::{RouteRecord, Who};
use crate::host_services::Standing;
use crate::plane_driver::port_intents::Namespace;
use crate::plane_grants::{TicketAdmitted, TicketDenied, TicketMint, Tickets};
use crate::plugin_records::RecordsDenied;

/// The longest a native ticket lives, seconds. A mint that asks for more is given this much (the
/// expiry core answers is the one the plane tells its client).
pub const TICKET_LIFE_MAX_S: u64 = 600;

/// The most unredeemed tickets one issuer key holds on one node: the 1.6 ticket custody's
/// per-key bound (`TICKET_CUSTODY_PER_KEY`, ed9b07727e), whose test refused the 257th.
pub const TICKETS_PER_KEY_MAX: usize = 256;

/// The most unredeemed tickets one node holds across every key: the 1.6 ticket custody's node
/// bound (`TICKET_CUSTODY_CAP`, ed9b07727e). Sixteen saturated keys fill a node.
pub const TICKETS_PER_NODE_MAX: usize = 4_096;

/// The door of a native ticket route: the audience a ticket is minted for when its plane states
/// none (IF §8.6 `MT_AUDIENCE`: "the route class it is good for, `ticket`") and the audience every
/// ticket route's desk redeems under. One text for both sides: a ticket minted for any other
/// audience opens no ticket route.
pub const TICKET_DOOR: &str = "ticket";

/// The largest record a plane may store with a ticket (IF §12.11 `MAX_TICKET_RECORD`), less the
/// room the issuer binding takes in the same row.
pub const PLANE_RECORD_MAX: usize = 65_536 - BINDING_ROOM;

/// The room kept for the issuer binding in a ticket's row.
const BINDING_ROOM: usize = 16_384;

/// The mark of a row that carries an issuer binding, and its layout version.
const BINDING_MARK: &[u8; 4] = b"bbi1";

/// Whether this module is the verifier of `by`: the table selects it for exactly one way of
/// verifying. Written with no catch-all arm, so a new way of verifying must say here whether a
/// ticket has any part in it.
pub const fn selected_by(by: VerifyBy) -> bool {
    match by {
        VerifyBy::TicketOrChain => true,
        VerifyBy::Nobody
        | VerifyBy::Chain
        | VerifyBy::ChainIfPresented
        | VerifyBy::Signature
        | VerifyBy::AdminChain => false,
    }
}

/// The verified principals being served on each plane instance: who a mint made now is for.
///
/// The listener enters the request's subject and governed key when a principal's request has
/// passed key policy on a seat, and holds the guard for the life of that request's serve. A mint
/// names only its subject; the key it binds is the one entered here. Two requests that state the
/// same subject under different keys (two providers naming one subject) make that subject's mint
/// ambiguous, and an ambiguous mint is refused.
#[derive(Default)]
pub struct Issuers {
    held: Mutex<HashMap<(u64, Box<str>), Held>>,
}

struct Held {
    key: Arc<VirtualKey>,
    count: usize,
    ambiguous: bool,
}

fn same_key(a: &VirtualKey, b: &VirtualKey) -> bool {
    a.id == b.id && a.generation_hash == b.generation_hash
}

impl Issuers {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// `subject`, verified and judged as `key`, is being served on plane instance `instance`.
    pub fn enter(self: &Arc<Self>, instance: u64, subject: &str, key: &Arc<VirtualKey>) -> Serving {
        let at = (instance, Box::<str>::from(subject));
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.entry(at.clone())
            .and_modify(|entry| {
                entry.count += 1;
                if !same_key(&entry.key, key) {
                    entry.ambiguous = true;
                }
            })
            .or_insert_with(|| Held {
                key: Arc::clone(key),
                count: 1,
                ambiguous: false,
            });
        Serving {
            book: Arc::clone(self),
            at,
        }
    }

    /// The key a mint for `subject` on `instance` is bound to; `None` when no such principal is
    /// being served there, or two are under different keys.
    fn issuer(&self, instance: u64, subject: &str) -> Option<Arc<VirtualKey>> {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        // The lookup key borrows nothing from the map: the subject is boxed once per mint.
        held.get(&(instance, Box::<str>::from(subject)))
            .filter(|entry| !entry.ambiguous)
            .map(|entry| Arc::clone(&entry.key))
    }
}

/// One principal's request being served: while it lives, a mint for its subject on its plane
/// instance is bound to its key.
pub struct Serving {
    book: Arc<Issuers>,
    at: (u64, Box<str>),
}

impl Drop for Serving {
    fn drop(&mut self) {
        let mut held = self
            .book
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = held.get_mut(&self.at) {
            entry.count -= 1;
            // The ambiguity lasts until every request of that subject has ended: which key a
            // mint made in between would have bound cannot be said.
            if entry.count == 0 {
                held.remove(&self.at);
            }
        }
    }
}

/// What a ticket's row says of its issue, beside the plane's own record.
struct Binding {
    /// The issuer's governed key, as it was judged when the ticket was minted.
    key: VirtualKey,
    /// The audience the ticket was minted for: the door it opens.
    door: String,
    expires_at: u64,
}

impl Binding {
    /// The row: the mark, the expiry, the door, the key record, then the plane's record.
    fn seal(&self, plane_record: &[u8]) -> Option<Vec<u8>> {
        let key = serde_json::to_vec(&self.key).ok()?;
        let door = self.door.as_bytes();
        if key.len() + door.len() + BINDING_MARK.len() + 8 + 2 + 4 > BINDING_ROOM
            || plane_record.len() > PLANE_RECORD_MAX
        {
            return None;
        }
        let mut row = Vec::with_capacity(
            BINDING_MARK.len() + 8 + 2 + door.len() + 4 + key.len() + plane_record.len(),
        );
        row.extend_from_slice(BINDING_MARK);
        row.extend_from_slice(&self.expires_at.to_be_bytes());
        row.extend_from_slice(&u16::try_from(door.len()).ok()?.to_be_bytes());
        row.extend_from_slice(door);
        row.extend_from_slice(&u32::try_from(key.len()).ok()?.to_be_bytes());
        row.extend_from_slice(&key);
        row.extend_from_slice(plane_record);
        Some(row)
    }

    /// The binding of `row` and the plane's record after it; `None` for a row no bound mint wrote.
    fn open(row: &[u8]) -> Option<(Self, &[u8])> {
        let rest = row.strip_prefix(BINDING_MARK.as_slice())?;
        let (expires_at, rest) = rest.split_at_checked(8)?;
        let expires_at = u64::from_be_bytes(expires_at.try_into().ok()?);
        let (len, rest) = rest.split_at_checked(2)?;
        let (door, rest) =
            rest.split_at_checked(usize::from(u16::from_be_bytes([len[0], len[1]])))?;
        let door = std::str::from_utf8(door).ok()?.to_owned();
        let (len, rest) = rest.split_at_checked(4)?;
        let len = usize::try_from(u32::from_be_bytes(len.try_into().ok()?)).ok()?;
        let (key, plane_record) = rest.split_at_checked(len)?;
        let key: VirtualKey = serde_json::from_slice(key).ok()?;
        Some((
            Self {
                key,
                door,
                expires_at,
            },
            plane_record,
        ))
    }
}

/// Whether `key` may act at `now`: enabled, not deleted, not past its stored expiry.
fn stands(key: &VirtualKey, now_s: u64) -> bool {
    key.enabled && key.deleted_at.is_none() && key.expires_at.is_none_or(|until| now_s < until)
}

/// A redeemed ticket: who it admits, as what, and the record its plane stored with it.
pub struct Redeemed {
    /// The ticket's subject and scope: what the plane is given in place of the credential.
    pub identity: Identity,
    /// The plane's own record, handed to exactly this request; `None` when it stored none.
    pub record: Option<SecureVec>,
    /// The issuer's governed key as it stands now: what money, limits and scope are judged on.
    pub key: Arc<VirtualKey>,
}

/// The door of bound tickets: what [`NativeTicketVerifier`] redeems through.
pub trait Redeem: Send + Sync {
    /// Pure: the credential holds core's ticket marker.
    fn is_ticket(&self, credential: &str) -> bool;
    fn redeem<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        door: &'a str,
        credential: &'a str,
        now_s: u64,
    ) -> BoxFut<'a, Result<Redeemed, TicketDenied>>;
}

/// Core's ticket store with the issuer bound into every ticket it mints. It is a [`Tickets`], so
/// it stands wherever the plain store stood: a plane's MINT goes through [`IssuerBound::mint`]
/// and no door can redeem a ticket around the issuer check.
pub struct IssuerBound<T> {
    inner: T,
    issuers: Arc<Issuers>,
    standing: Standing,
    clock: fn() -> u64,
}

impl<T: Tickets> IssuerBound<T> {
    /// `inner`: the sealed store. `issuers`: the principals being served. `standing`: a key as
    /// it stands now, or `None` when it no longer does. `clock`: UNIX seconds, the store's own.
    pub fn new(inner: T, issuers: Arc<Issuers>, standing: Standing, clock: fn() -> u64) -> Self {
        Self {
            inner,
            issuers,
            standing,
            clock,
        }
    }

    async fn redeem_bound(
        &self,
        plane: &Caller<'_>,
        door: &str,
        credential: &str,
        now_s: u64,
    ) -> Result<Redeemed, TicketDenied> {
        // The seal, the plane image and instance, the audience, the expiry and the single take
        // of the row are the store's. A ticket that fails any of them never reaches the issuer.
        let TicketAdmitted { identity, record } =
            self.inner.admit(plane, door, credential, now_s).await?;
        let Some(row) = record else {
            // A ticket with no row was minted around the binding: it names nobody who may spend
            // it. Never admitted on a subject alone.
            tracing::warn!(
                plane = plane.name,
                "ticket refused: it carries no issuer binding"
            );
            return Err(TicketDenied::Invalid);
        };
        let Some((binding, plane_record)) = Binding::open(&row[..]) else {
            tracing::warn!(
                plane = plane.name,
                "ticket refused: its issuer binding does not read"
            );
            return Err(TicketDenied::Invalid);
        };
        if binding.door != door {
            tracing::info!(
                plane = plane.name,
                "ticket refused: minted for another door"
            );
            return Err(TicketDenied::Invalid);
        }
        if now_s >= binding.expires_at {
            return Err(TicketDenied::Expired);
        }
        let issued = Arc::new(binding.key);
        // The issuer as it stands now. The row's key is only the question; the answer is what
        // the request runs under, so a ticket can never carry more than its issuer has today.
        let Some(current) = (self.standing)(&issued, now_s) else {
            tracing::info!(
                plane = plane.name,
                key = %issued.id,
                "ticket refused: its issuer no longer stands"
            );
            return Err(TicketDenied::Invalid);
        };
        if !same_key(&current, &issued) || !stands(&current, now_s) {
            tracing::info!(
                plane = plane.name,
                key = %issued.id,
                "ticket refused: its issuer was rotated, disabled, deleted or has expired"
            );
            return Err(TicketDenied::Invalid);
        }
        Ok(Redeemed {
            identity,
            record: (!plane_record.is_empty()).then(|| SecureVec::from(plane_record)),
            key: current,
        })
    }
}

impl<T: Tickets> Tickets for IssuerBound<T> {
    fn mint<'a>(
        &'a self,
        who: &'a Caller<'_>,
        m: TicketMint<'a>,
    ) -> BoxFut<'a, Result<(Box<str>, u64), RecordsDenied>> {
        Box::pin(async move {
            let now_s = (self.clock)();
            let Some(key) = self.issuers.issuer(who.instance, m.subject) else {
                tracing::warn!(
                    plane = who.name,
                    "ticket not minted: no verified principal of its subject is being served \
                     on this plane instance, or two are under different keys"
                );
                return Err(RecordsDenied::Invalid);
            };
            if !stands(&key, now_s) {
                tracing::info!(plane = who.name, key = %key.id, "ticket not minted: its issuer does not stand");
                return Err(RecordsDenied::Invalid);
            }
            // The life asked for, under the ceiling and under the issuer key's own expiry.
            let mut ttl_s = m.ttl_s.min(TICKET_LIFE_MAX_S);
            if let Some(until) = key.expires_at {
                ttl_s = ttl_s.min(until.saturating_sub(now_s));
            }
            if ttl_s == 0 {
                return Err(RecordsDenied::Invalid);
            }
            if m.record.len() > PLANE_RECORD_MAX {
                return Err(RecordsDenied::TooLarge);
            }
            let binding = Binding {
                key: (*key).clone(),
                door: m.audience.to_owned(),
                expires_at: now_s.saturating_add(ttl_s),
            };
            let row = SecureVec::from(binding.seal(m.record).ok_or(RecordsDenied::TooLarge)?);
            let minted = self
                .inner
                .mint(
                    who,
                    TicketMint {
                        ttl_s,
                        // Single use, whatever the plane asked: one ticket admits one request.
                        once: true,
                        record: &row[..],
                        // Every field named: nothing of the mint passes unread.
                        subject: m.subject,
                        scope: m.scope,
                        audience: m.audience,
                        prefix: m.prefix,
                    },
                )
                .await?;
            // The issuance is recorded with who it is for and how long it lives, never its text.
            tracing::info!(
                plane = who.name,
                key = %key.id,
                expires_at = minted.1,
                "ticket minted"
            );
            Ok(minted)
        })
    }

    fn is_ticket(&self, credential: &str) -> bool {
        self.inner.is_ticket(credential)
    }

    /// The plane driver's own door ([`crate::plane_driver::port_serve::TicketGate`]) redeems
    /// through the same checks; it is handed the plane's record and never the row.
    fn admit<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        audience: &'a str,
        credential: &'a str,
        now_s: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        Box::pin(async move {
            let redeemed = self
                .redeem_bound(plane, audience, credential, now_s)
                .await?;
            Ok(TicketAdmitted {
                identity: redeemed.identity,
                record: redeemed.record,
            })
        })
    }
}

impl<T: Tickets> Redeem for IssuerBound<T> {
    fn is_ticket(&self, credential: &str) -> bool {
        self.inner.is_ticket(credential)
    }

    fn redeem<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        door: &'a str,
        credential: &'a str,
        now_s: u64,
    ) -> BoxFut<'a, Result<Redeemed, TicketDenied>> {
        Box::pin(async move { self.redeem_bound(plane, door, credential, now_s).await })
    }
}

/// What a request's head presents to a ticket route.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Presented<'a> {
    /// No `Authorization: Bearer` credential that is a ticket: the route's chain judges the
    /// request, where its record admits a principal.
    NoTicket,
    /// One ticket, and no other `authorization` line beside it.
    Ticket(&'a str),
    /// A ticket beside another `authorization` line: which one the caller means cannot be said,
    /// and a ticket is never spent on a guess.
    Ambiguous,
}

/// The credential never prints.
impl std::fmt::Debug for Presented<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoTicket => "NoTicket",
            Self::Ticket(_) => "Ticket(..)",
            Self::Ambiguous => "Ambiguous",
        })
    }
}

/// What `headers` present to `door`. Every `authorization` line is read, not the first.
pub fn presented<'a>(
    headers: impl Iterator<Item = (&'a str, &'a [u8])>,
    door: &dyn Redeem,
) -> Presented<'a> {
    let mut lines = 0usize;
    let mut ticket = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("authorization") {
            continue;
        }
        lines += 1;
        let Ok(value) = std::str::from_utf8(value) else {
            continue;
        };
        let Some((scheme, credential)) = value.split_once(' ') else {
            continue;
        };
        let credential = credential.trim();
        if scheme.eq_ignore_ascii_case("bearer") && door.is_ticket(credential) {
            if ticket.is_some() {
                return Presented::Ambiguous;
            }
            ticket = Some(credential);
        }
    }
    match ticket {
        None => Presented::NoTicket,
        Some(credential) if lines == 1 => Presented::Ticket(credential),
        Some(_) => Presented::Ambiguous,
    }
}

/// Why a presented ticket was not admitted. The caller is told none of it: every reason but
/// [`TicketRefused::Unavailable`] is the one 401, and that one is the 503.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketRefused {
    /// The route's record admits no ticket.
    RouteTakesNoTicket,
    /// A ticket beside another credential.
    Ambiguous,
    /// The seal does not open; another plane, instance or door; no issuer binding; the issuer no
    /// longer stands.
    Invalid,
    Expired,
    /// The ticket already admitted a request, on this replica or another.
    Replayed,
    /// The ticket store could not be reached. Not a denial.
    Unavailable,
}

impl TicketRefused {
    /// The reason, for the log. It names no credential and no key.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::RouteTakesNoTicket => "the route admits no ticket",
            Self::Ambiguous => "a ticket was presented beside another credential",
            Self::Invalid => "the ticket is not one this door admits",
            Self::Expired => "the ticket has expired",
            Self::Replayed => "the ticket was already used",
            Self::Unavailable => "the ticket store could not answer",
        }
    }

    /// The fact the admission table reads.
    pub const fn verified(self) -> Verified {
        match self {
            Self::Unavailable => Verified::Unavailable,
            Self::RouteTakesNoTicket
            | Self::Ambiguous
            | Self::Invalid
            | Self::Expired
            | Self::Replayed => Verified::Denied,
        }
    }

    const fn of(denied: TicketDenied) -> Self {
        match denied {
            TicketDenied::Invalid => Self::Invalid,
            TicketDenied::Expired => Self::Expired,
            TicketDenied::Replayed => Self::Replayed,
            TicketDenied::Unavailable => Self::Unavailable,
        }
    }
}

/// A request a ticket admitted. Only [`NativeTicketVerifier::verify`] makes one: the serving code
/// that opens the unit takes its key from here and from nowhere else.
pub struct TicketVerified {
    redeemed: Redeemed,
    /// The plane instance whose door admitted it.
    instance: u64,
}

impl TicketVerified {
    /// The issuer's governed key as it stands now: the principal of the unit.
    pub fn key(&self) -> &Arc<VirtualKey> {
        &self.redeemed.key
    }

    /// What the plane is given in place of the credential: the ticket's subject and scope.
    pub fn identity(&self) -> &Identity {
        &self.redeemed.identity
    }

    /// `PlaneReq.ticket_record`: the record the plane stored at the mint; empty when it stored none.
    pub fn ticket_record(&self) -> &[u8] {
        self.redeemed.record.as_deref().unwrap_or_default()
    }

    /// The plane instance whose door admitted the ticket.
    pub fn instance(&self) -> u64 {
        self.instance
    }

    /// The fact the admission table reads.
    pub const fn verified(&self) -> Verified {
        Verified::Ticket
    }
}

/// The key and the record never print.
impl std::fmt::Debug for TicketVerified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketVerified")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

/// Step 2's answer on a ticket route.
#[derive(Debug)]
pub enum TicketJudged {
    /// No ticket is presented: the route's chain judges the request if its record admits a
    /// principal, and nobody does if it admits a ticket alone.
    NoTicket,
    Admitted(TicketVerified),
    Refused(TicketRefused),
}

impl TicketJudged {
    /// What the admission table is told of this request. `presented`: a credential carrier of the
    /// route's chain is on the head (it changes the code recorded, never the answer). With no
    /// ticket presented the verify step is left to the chain: `verified` is `None`, unless the
    /// record admits a ticket alone, where a request with none is not verified.
    pub fn facts(&self, record: &RouteRecord, presented: bool) -> Facts {
        let ticket_presented = !matches!(self, Self::NoTicket);
        let mut facts = Facts::arrived(presented, ticket_presented);
        facts.verified = match self {
            Self::Admitted(admitted) => Some(admitted.verified()),
            Self::Refused(refused) => Some(refused.verified()),
            Self::NoTicket if record.who.has(Who::PRINCIPAL) => None,
            Self::NoTicket => Some(Verified::Denied),
        };
        facts
    }
}

/// The ticket verifier of one plane instance's ticket routes.
pub struct NativeTicketVerifier {
    door: Arc<dyn Redeem>,
    who: Namespace,
    /// The audience this instance's ticket routes redeem under.
    audience: Box<str>,
}

impl NativeTicketVerifier {
    /// `door`: the bound store. `who`: the plane instance (a ticket another instance minted does
    /// not open). `audience`: what a ticket must have been minted for to open these routes.
    pub fn new(door: Arc<dyn Redeem>, who: Namespace, audience: &str) -> Self {
        Self {
            door,
            who,
            audience: audience.into(),
        }
    }

    /// Whether a route with this admission is this verifier's.
    pub fn serves(admission: Admission) -> bool {
        admission == Admission::Ticket
    }

    /// What the head presents to this door, before anything is spent.
    pub fn presented<'a>(
        &self,
        headers: impl Iterator<Item = (&'a str, &'a [u8])>,
    ) -> Presented<'a> {
        presented(headers, &*self.door)
    }

    /// Judge the head of a request on a route whose record is `record`. A ticket is spent only
    /// here, only once, and only when it is the one credential on the head.
    pub async fn verify<'a>(
        &self,
        record: &RouteRecord,
        headers: impl Iterator<Item = (&'a str, &'a [u8])>,
        now_s: u64,
    ) -> TicketJudged {
        let credential = match self.presented(headers) {
            Presented::NoTicket => return TicketJudged::NoTicket,
            Presented::Ambiguous => return self.refused(TicketRefused::Ambiguous),
            Presented::Ticket(credential) => credential,
        };
        // A ticket on a route that admits none is not read as one by any other verifier either:
        // it is refused here, unspent.
        if !record.who.has(Who::TICKET) {
            return self.refused(TicketRefused::RouteTakesNoTicket);
        }
        let plane = self.who.caller();
        match self
            .door
            .redeem(&plane, &self.audience, credential, now_s)
            .await
        {
            Ok(redeemed) => TicketJudged::Admitted(TicketVerified {
                redeemed,
                instance: self.who.instance,
            }),
            Err(denied) => self.refused(TicketRefused::of(denied)),
        }
    }

    fn refused(&self, refused: TicketRefused) -> TicketJudged {
        match refused {
            TicketRefused::Unavailable => tracing::warn!(
                plane = &*self.who.name,
                reason = refused.reason(),
                "ticket not judged"
            ),
            _ => tracing::info!(
                plane = &*self.who.name,
                reason = refused.reason(),
                "ticket refused"
            ),
        }
        TicketJudged::Refused(refused)
    }
}

/// One plane instance's ticket desk: the door its ticket routes redeem at, and the book its
/// served principals are entered in so that a mint made during their request is bound to their
/// key. Built at boot, once per plane instance, only where core's ticket store is open.
pub struct TicketDesk {
    verifier: NativeTicketVerifier,
    issuers: Arc<Issuers>,
}

impl TicketDesk {
    /// `door`: the bound store. `who`: the plane instance. `issuers`: the book the same store
    /// mints from. The audience is [`TICKET_DOOR`], and no other.
    pub fn new(door: Arc<dyn Redeem>, who: Namespace, issuers: Arc<Issuers>) -> Arc<Self> {
        Arc::new(Self {
            verifier: NativeTicketVerifier::new(door, who, TICKET_DOOR),
            issuers,
        })
    }

    /// The verifier of this instance's ticket routes.
    pub fn verifier(&self) -> &NativeTicketVerifier {
        &self.verifier
    }

    /// The plane instance this desk is of: the instance a MINT is made as.
    pub fn instance(&self) -> u64 {
        self.verifier.who.instance
    }

    /// `subject`, verified by its route's chain and judged as `key`, is being served on this
    /// instance: until the guard drops, a mint for that subject is bound to that key.
    pub fn serving(&self, subject: &str, key: &Arc<VirtualKey>) -> Serving {
        self.issuers.enter(self.verifier.who.instance, subject, key)
    }
}

#[cfg(test)]
#[path = "tests/native_ticket_tests.rs"]
mod tests;
