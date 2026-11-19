// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Inbound admission as one decision. A route's record names its admission; the admission names
//! one sequence of steps; [`decide`] walks that sequence over what is known of the request and
//! answers with the next step to run, the one refusal, or the authority to serve. The listener
//! runs steps and asks again; it holds no order of its own. A step the record does not need is
//! skipped here, by the record, never by a code path in the listener.
//!
//! [`plan`] is written as a `match` with no catch-all arm: an admission with no sequence does not
//! compile. [`Authority`] is what the serving code is built from, and only [`decide`] yields one.

use busbar_plugin_abi::fail::refused::{
    R_AUTH_REQUIRED, R_BAD_CREDENTIAL, R_BUDGET, R_DENIED, R_INVALID, R_NO_ROUTE, R_POLICY,
    R_RATE_LIMITED, R_REPLAYED, R_UNSUPPORTED,
};

use super::route_record::{Money, RouteClass, RouteRecord, Who};

/// The admission a record names (design C4). `Internal` routes are never on a listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Admission {
    /// A principal's request whose name core's walk judges under the record's walk kind; scope,
    /// limits and money run inside the serve, at the plane's FORWARD.
    Walk,
    /// A principal's request whose resources the plane selects and core judges before serving.
    Selected,
    /// A principal's request judged against nothing.
    PrincipalOnly,
    /// A listing core builds from what the key may see; the plane only renders it.
    Catalog,
    Public,
    /// The chain runs only when a credential is presented.
    Optional,
    /// A core ticket, or a key where the record admits both.
    Ticket,
    /// The sender's signature over a bounded body.
    SignedIngress,
    /// Everything through money on the HTTP head, then the 101.
    Upgrade,
    Operator,
    Internal,
}

/// The admission of a record that passed [`RouteRecord::validate`].
pub fn admission_of(record: &RouteRecord) -> Admission {
    match record.class {
        RouteClass::Admin => Admission::Operator,
        RouteClass::Line | RouteClass::Recovery => Admission::Internal,
        RouteClass::Upgrade => Admission::Upgrade,
        RouteClass::Catalog => Admission::Catalog,
        RouteClass::Data => {
            if record.who.is(Who::PUBLIC) {
                Admission::Public
            } else if record.who.is(Who::OPTIONAL) {
                Admission::Optional
            } else if record.who.is(Who::SIGNED_INGRESS) {
                Admission::SignedIngress
            } else if record.who.has(Who::TICKET) {
                Admission::Ticket
            } else if !record.scope.selected.is_empty() {
                Admission::Selected
            } else if record.scope.walk.is_some() {
                Admission::Walk
            } else {
                Admission::PrincipalOnly
            }
        }
    }
}

/// The steps of the one sequence (design C3), in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// 2: verify the caller on the head.
    Verify,
    /// 3: the key the identity earns is valid now.
    Policy,
    /// 4: read the body under the cap.
    Body,
    /// 5: judge the key against what the request names.
    Scope,
    /// 6: group frozen, concurrency, windows.
    Limits,
    /// 7: open the unit, price known, budget held.
    Unit,
    /// The upgrade request is one, and a transport can carry it.
    Upgrade,
}

/// How step 2 verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerifyBy {
    Nobody,
    /// The route's chain (on no route, the data chain).
    Chain,
    /// The chain when a credential is presented, else nobody.
    ChainIfPresented,
    /// A ticket when one is presented, else the chain if the record admits a principal.
    TicketOrChain,
    /// The sender's signature, over the bounded body read before it.
    Signature,
    AdminChain,
}

/// When step 4 runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyAt {
    /// After the caller is verified (every route but a signed one).
    AfterVerify,
    /// Before verification, at most the size the verifier signs.
    BoundedBeforeVerify,
    /// The body is not taken before the answer (an upgrade's head).
    Never,
}

/// Where steps 5 to 7 run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JudgedAt {
    Nowhere,
    /// By core, before the plane is called.
    BeforeServe,
    /// Inside the serve, at the plane's FORWARD, before the first byte goes upstream.
    InWalk,
}

/// What a success is built from. The listener's serving code takes one of these and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Authority {
    /// A unit is open and money admitted: the plane's `request`, settled once.
    Billed,
    /// A unit is open; scope, limits and money are admitted at the plane's FORWARD.
    Walk,
    /// Verified and recorded; no unit, no limit counted.
    Unbilled,
    /// Core's list of what the key may see, rendered by the plane; no unit.
    Catalog,
    Public,
    Operator,
    /// Everything on the head admitted: the 101 may be written.
    Upgrade,
}

/// One admission's sequence. Every field is a statement; `decide` reads nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub verify: VerifyBy,
    pub policy: bool,
    pub body: BodyAt,
    pub scope: JudgedAt,
    /// Limits and money go together, and only where money moves.
    pub money: JudgedAt,
    pub upgrade: bool,
    pub serves: Authority,
}

/// The sequence of an admission on a route whose record says `money`. `None`: no client reaches it.
pub fn plan(admission: Admission, money: Money) -> Option<Plan> {
    let billed = |at: JudgedAt| match money {
        Money::Unit => at,
        Money::None => JudgedAt::Nowhere,
    };
    let served = |unit: Authority| match money {
        Money::Unit => unit,
        Money::None => Authority::Unbilled,
    };
    Some(match admission {
        // 0 1 2 3 4 . 7(open) 8[5 6 7] 9 10
        Admission::Walk => Plan {
            verify: VerifyBy::Chain,
            policy: true,
            body: BodyAt::AfterVerify,
            scope: JudgedAt::InWalk,
            money: billed(JudgedAt::InWalk),
            upgrade: false,
            serves: served(Authority::Walk),
        },
        // 0 1 2 3 4 5 6 7 8 9 10
        Admission::Selected => Plan {
            verify: VerifyBy::Chain,
            policy: true,
            body: BodyAt::AfterVerify,
            scope: JudgedAt::BeforeServe,
            money: billed(JudgedAt::BeforeServe),
            upgrade: false,
            serves: served(Authority::Billed),
        },
        // 0 1 2 3 4 [6 7] 8 [9] 10
        Admission::PrincipalOnly => Plan {
            verify: VerifyBy::Chain,
            policy: true,
            body: BodyAt::AfterVerify,
            scope: JudgedAt::Nowhere,
            money: billed(JudgedAt::BeforeServe),
            upgrade: false,
            serves: served(Authority::Billed),
        },
        // 0 1 2 3 5 8(render) 10
        Admission::Catalog => Plan {
            verify: VerifyBy::Chain,
            policy: true,
            body: BodyAt::AfterVerify,
            scope: JudgedAt::BeforeServe,
            money: JudgedAt::Nowhere,
            upgrade: false,
            serves: Authority::Catalog,
        },
        // 0 1 8 10
        Admission::Public => Plan {
            verify: VerifyBy::Nobody,
            policy: false,
            body: BodyAt::AfterVerify,
            scope: JudgedAt::Nowhere,
            money: JudgedAt::Nowhere,
            upgrade: false,
            serves: Authority::Public,
        },
        // 0 1 [2 3] 8 10
        Admission::Optional => Plan {
            verify: VerifyBy::ChainIfPresented,
            policy: true,
            body: BodyAt::AfterVerify,
            scope: JudgedAt::Nowhere,
            money: JudgedAt::Nowhere,
            upgrade: false,
            serves: Authority::Unbilled,
        },
        // 0 1 2(ticket) 4 6 7 8 9 10
        Admission::Ticket => Plan {
            verify: VerifyBy::TicketOrChain,
            policy: true,
            body: BodyAt::AfterVerify,
            scope: JudgedAt::Nowhere,
            money: billed(JudgedAt::BeforeServe),
            upgrade: false,
            serves: served(Authority::Billed),
        },
        // 0 1 4(bounded) 2 8 10
        Admission::SignedIngress => Plan {
            verify: VerifyBy::Signature,
            policy: false,
            body: BodyAt::BoundedBeforeVerify,
            scope: JudgedAt::Nowhere,
            money: JudgedAt::Nowhere,
            upgrade: false,
            serves: Authority::Unbilled,
        },
        // 0 1 2 3 5 6 7, then 101
        Admission::Upgrade => Plan {
            verify: VerifyBy::Chain,
            policy: true,
            body: BodyAt::Never,
            scope: JudgedAt::BeforeServe,
            money: billed(JudgedAt::BeforeServe),
            upgrade: true,
            serves: Authority::Upgrade,
        },
        // 0 1 2 scope, rate, 8 10: the admin chain's own walk judges scope and rate.
        Admission::Operator => Plan {
            verify: VerifyBy::AdminChain,
            policy: false,
            body: BodyAt::AfterVerify,
            scope: JudgedAt::Nowhere,
            money: JudgedAt::Nowhere,
            upgrade: false,
            serves: Authority::Operator,
        },
        Admission::Internal => return None,
    })
}

/// What steps 0 and 1 found.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Target<'a> {
    Route(&'a RouteRecord),
    /// The path is a route's; the method is not. `allow`: the methods the path does accept.
    WrongMethod {
        allow: u32,
    },
    /// No mounted route (an unknown path, or a declared route this configuration does not mount).
    NoRoute,
}

/// Step 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Gate {
    Open,
    Full,
    Draining,
}

/// Step 2's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verified {
    /// A principal. `shared`: the subject is one every such caller shares (`anonymous`). It gates no
    /// route: a route that keeps state per caller keys an anonymous caller's state by the handle its
    /// session states (`plane_driver::port_intents::handle_scope`), never by the shared subject.
    Identity {
        shared: bool,
    },
    Ticket,
    Signature,
    Operator,
    /// No member of the chain accepted the credential, or none was presented.
    Denied,
    /// The verifier could not answer (unreachable, timed out). Not a denial.
    Unavailable,
}

/// Step 3's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Policy {
    Valid,
    /// The identity earns no key, or the key is past its stored expiry or deleted: not verified.
    NoKey,
    /// The key is disabled or revoked.
    Disabled,
    /// The credential was already seen.
    Replayed,
}

/// Step 4's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyRead {
    Taken,
    /// The declared or received length is over the cap.
    OverCap,
    /// The body does not match the digest the credential signed.
    DigestMismatch,
    Trailers,
}

/// Step 5's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScopeJudged {
    Permitted,
    Denied,
}

/// Step 6's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limits {
    Within,
    GroupFrozen,
    GroupUnknown,
    InFlight,
    Window { retry_after_s: u32 },
}

/// Step 7's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unit {
    Admitted,
    /// The money record cannot be written.
    Unwritable,
    Unpriced,
    BudgetSpent {
        retry_after_s: Option<u32>,
    },
}

/// The upgrade step's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpgradeAsked {
    Carried,
    NotAnUpgrade,
    NoTransport,
}

/// What is known of one request. `None`: that step has not run. Steps report here; [`decide`]
/// reads them in the sequence's order, whatever order they were filled in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub gate: Gate,
    /// A credential carrier of the route (or of the data chain, on no route) is on the head.
    pub presented: bool,
    /// A core ticket is on the head.
    pub ticket_presented: bool,
    pub verified: Option<Verified>,
    pub policy: Option<Policy>,
    pub body: Option<BodyRead>,
    pub scope: Option<ScopeJudged>,
    pub limits: Option<Limits>,
    pub unit: Option<Unit>,
    pub upgrade: Option<UpgradeAsked>,
}

impl Facts {
    /// A request that passed step 0 with nothing else known.
    pub const fn arrived(presented: bool, ticket_presented: bool) -> Self {
        Self {
            gate: Gate::Open,
            presented,
            ticket_presented,
            verified: None,
            policy: None,
            body: None,
            scope: None,
            limits: None,
            unit: None,
            upgrade: None,
        }
    }
}

/// Who writes a refusal's body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyBy {
    Core,
    /// The plane renders core's record in its dialect; core's shape when it cannot.
    Plane,
}

/// The one refusal table (design C7). Core decides every row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// Row 1.
    GatewayFull,
    /// Row 2. `presented` picks the recorded code; the bytes do not differ.
    Unverified { presented: bool },
    /// Row 2a.
    VerifierUnavailable,
    /// Row 3.
    KeyDisabled,
    /// Row 4.
    NoRoute,
    /// Row 5.
    WrongMethod { allow: u32 },
    /// Row 6.
    BodyTooLarge,
    /// Row 7: answered exactly as row 2 is.
    DigestMismatch,
    /// Row 8.
    Trailers,
    /// Row 10.
    ScopeDenied,
    /// Row 12.
    Unpriced,
    /// Row 13.
    GroupFrozen,
    /// Row 14.
    GroupUnknown,
    /// Row 15.
    InFlight,
    /// Row 16.
    Window { retry_after_s: u32 },
    /// Row 17.
    BudgetSpent { retry_after_s: Option<u32> },
    /// Row 18.
    MoneyUnavailable,
    /// Row 19.
    Replayed,
    /// Row 20, first half.
    NotAnUpgrade,
    /// Row 20, second half.
    NoUpgradeTransport,
    /// Row 22.
    Draining,
}

/// One row of the table: what core fixes about a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    /// The row's number in design C7.
    pub row: &'static str,
    pub status: u16,
    pub code: u32,
    pub by: BodyBy,
    /// A dialect may choose the status (row 17 only); `status` is core's own shape.
    pub dialect_status: bool,
    /// The `Retry-After` seconds, where the row has a figure to state.
    pub retry_after_s: Option<u32>,
    /// The row sends `WWW-Authenticate`.
    pub challenge: bool,
    /// The methods mask of an `Allow` header.
    pub allow: Option<u32>,
    /// Core's text, where core writes the body. Rows the plane renders carry the governance
    /// text built where the group and window are known.
    pub text: Option<&'static str>,
    /// The row writes an audit record. A shed request has no route, caller or unit to record.
    pub audited: bool,
}

/// The refusal code of a request core could not serve for want of capacity or a dependency. The
/// refused vocabulary has no "unavailable" word; R_POLICY is what the native path already records
/// for its 503 (`native_data.rs` `refuse`).
const UNAVAILABLE: u32 = R_POLICY;

pub const TEXT_FULL: &str = "The gateway is at capacity. Please retry shortly.";
pub const TEXT_UNVERIFIED: &str = "authentication required";
pub const TEXT_UNAVAILABLE: &str = "service temporarily unavailable";
pub const TEXT_NO_ROUTE: &str = "the requested resource was not found";
pub const TEXT_WRONG_METHOD: &str = "method not allowed for this resource";
pub const TEXT_TOO_LARGE: &str = "request too large";
pub const TEXT_TRAILERS: &str = "request trailers are not accepted";
pub const TEXT_DENIED: &str = "Your API key does not have permission to access this resource.";
pub const TEXT_DISABLED: &str = "This API key is disabled.";
pub const TEXT_REPLAYED: &str = "this request was already received";
pub const TEXT_NOT_AN_UPGRADE: &str = "this route accepts only a websocket upgrade request";
pub const TEXT_NO_WEBSOCKET: &str = "no transport on this listener can carry a websocket upgrade";

impl Refusal {
    /// The row. `verified`: the caller was verified before this refusal, so a plane may render it;
    /// before verification core writes every body and no plugin code runs.
    pub const fn row(self, verified: bool) -> Row {
        let plane = if verified {
            BodyBy::Plane
        } else {
            BodyBy::Core
        };
        let base = Row {
            row: "",
            status: 0,
            code: 0,
            by: BodyBy::Core,
            dialect_status: false,
            retry_after_s: None,
            challenge: false,
            allow: None,
            text: None,
            audited: true,
        };
        match self {
            Self::GatewayFull => Row {
                row: "1",
                status: 503,
                code: UNAVAILABLE,
                retry_after_s: Some(1),
                text: Some(TEXT_FULL),
                audited: false,
                ..base
            },
            Self::Unverified { presented } => Row {
                row: "2",
                status: 401,
                code: if presented {
                    R_BAD_CREDENTIAL
                } else {
                    R_AUTH_REQUIRED
                },
                challenge: true,
                text: Some(TEXT_UNVERIFIED),
                ..base
            },
            Self::VerifierUnavailable => Row {
                row: "2a",
                status: 503,
                code: UNAVAILABLE,
                text: Some(TEXT_UNAVAILABLE),
                ..base
            },
            Self::KeyDisabled => Row {
                row: "3",
                status: 403,
                code: R_POLICY,
                text: Some(TEXT_DISABLED),
                ..base
            },
            Self::NoRoute => Row {
                row: "4",
                status: 404,
                code: R_NO_ROUTE,
                text: Some(TEXT_NO_ROUTE),
                ..base
            },
            Self::WrongMethod { allow } => Row {
                row: "5",
                status: 405,
                code: R_INVALID,
                allow: Some(allow),
                text: Some(TEXT_WRONG_METHOD),
                ..base
            },
            Self::BodyTooLarge => Row {
                row: "6",
                status: 413,
                code: R_INVALID,
                by: plane,
                text: Some(TEXT_TOO_LARGE),
                ..base
            },
            Self::DigestMismatch => Row {
                row: "7",
                status: 401,
                code: R_BAD_CREDENTIAL,
                challenge: true,
                text: Some(TEXT_UNVERIFIED),
                ..base
            },
            Self::Trailers => Row {
                row: "8",
                status: 400,
                code: R_INVALID,
                text: Some(TEXT_TRAILERS),
                ..base
            },
            Self::ScopeDenied => Row {
                row: "10",
                status: 403,
                code: R_DENIED,
                by: plane,
                text: Some(TEXT_DENIED),
                ..base
            },
            Self::Unpriced => Row {
                row: "12",
                status: 400,
                code: R_INVALID,
                by: plane,
                ..base
            },
            Self::GroupFrozen => Row {
                row: "13",
                status: 403,
                code: R_POLICY,
                by: plane,
                ..base
            },
            Self::GroupUnknown => Row {
                row: "14",
                status: 403,
                code: R_POLICY,
                by: plane,
                ..base
            },
            Self::InFlight => Row {
                row: "15",
                status: 429,
                code: R_RATE_LIMITED,
                by: plane,
                ..base
            },
            Self::Window { retry_after_s } => Row {
                row: "16",
                status: 429,
                code: R_RATE_LIMITED,
                by: plane,
                retry_after_s: Some(retry_after_s),
                ..base
            },
            Self::BudgetSpent { retry_after_s } => Row {
                row: "17",
                status: 402,
                code: R_BUDGET,
                by: plane,
                dialect_status: true,
                retry_after_s,
                ..base
            },
            Self::MoneyUnavailable => Row {
                row: "18",
                status: 503,
                code: UNAVAILABLE,
                by: plane,
                text: Some(TEXT_UNAVAILABLE),
                ..base
            },
            Self::Replayed => Row {
                row: "19",
                status: 409,
                code: R_REPLAYED,
                text: Some(TEXT_REPLAYED),
                ..base
            },
            Self::NotAnUpgrade => Row {
                row: "20",
                status: 400,
                code: R_INVALID,
                by: plane,
                text: Some(TEXT_NOT_AN_UPGRADE),
                ..base
            },
            Self::NoUpgradeTransport => Row {
                row: "20",
                status: 501,
                code: R_UNSUPPORTED,
                by: plane,
                text: Some(TEXT_NO_WEBSOCKET),
                ..base
            },
            Self::Draining => Row {
                row: "22",
                status: 503,
                code: UNAVAILABLE,
                text: Some(TEXT_UNAVAILABLE),
                audited: false,
                ..base
            },
        }
    }
}

/// [`decide`]'s answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Run this step, report its fact, ask again.
    Run(Step),
    /// Answer this refusal. `verified`: the caller was verified first ([`Refusal::row`]).
    Refuse {
        refusal: Refusal,
        verified: bool,
    },
    Serve(Authority),
}

const fn refuse(refusal: Refusal, verified: bool) -> Decision {
    Decision::Refuse { refusal, verified }
}

/// Whether step 2 runs the verifier at all on this request, and so whether steps 2 and 3 apply.
const fn verifies(by: VerifyBy, facts: &Facts) -> bool {
    match by {
        VerifyBy::Nobody => false,
        VerifyBy::ChainIfPresented => facts.presented,
        VerifyBy::Chain | VerifyBy::TicketOrChain | VerifyBy::Signature | VerifyBy::AdminChain => {
            true
        }
    }
}

fn body_step(facts: &Facts, verified: bool) -> Option<Decision> {
    Some(match facts.body {
        None => Decision::Run(Step::Body),
        Some(BodyRead::Taken) => return None,
        Some(BodyRead::OverCap) => refuse(Refusal::BodyTooLarge, verified),
        Some(BodyRead::DigestMismatch) => refuse(Refusal::DigestMismatch, false),
        Some(BodyRead::Trailers) => refuse(Refusal::Trailers, verified),
    })
}

/// The decision. `target`: what the match found. The order below is the product's order; nothing
/// else decides which refusal a request with several faults receives.
pub fn decide(target: Target<'_>, facts: &Facts) -> Decision {
    // Step 0.
    match facts.gate {
        Gate::Open => {}
        Gate::Full => return refuse(Refusal::GatewayFull, false),
        Gate::Draining => return refuse(Refusal::Draining, false),
    }
    // Step 1. On no route the data chain judges the caller, so a caller that is not verified
    // receives the one answer every route gives and learns nothing about which routes exist.
    let record = match target {
        Target::Route(record) => record,
        Target::NoRoute | Target::WrongMethod { .. } => {
            return match (facts.verified, facts.policy) {
                (None, _) => Decision::Run(Step::Verify),
                (Some(Verified::Unavailable), _) => refuse(Refusal::VerifierUnavailable, false),
                (Some(Verified::Identity { .. }), None) => Decision::Run(Step::Policy),
                (Some(Verified::Identity { .. }), Some(Policy::Valid)) => match target {
                    Target::WrongMethod { allow } => refuse(Refusal::WrongMethod { allow }, true),
                    Target::NoRoute | Target::Route(_) => refuse(Refusal::NoRoute, true),
                },
                (Some(Verified::Identity { .. }), Some(Policy::Disabled)) => {
                    refuse(Refusal::KeyDisabled, true)
                }
                (Some(Verified::Identity { .. }), Some(Policy::Replayed)) => {
                    refuse(Refusal::Replayed, false)
                }
                (Some(Verified::Identity { .. }), Some(Policy::NoKey))
                | (
                    Some(
                        Verified::Denied
                        | Verified::Ticket
                        | Verified::Signature
                        | Verified::Operator,
                    ),
                    _,
                ) => refuse(
                    Refusal::Unverified {
                        presented: facts.presented,
                    },
                    false,
                ),
            };
        }
    };
    let admission = admission_of(record);
    let Some(plan) = plan(admission, record.money) else {
        // No client reaches an internal route: it is answered as an unknown path is.
        return decide(Target::NoRoute, facts);
    };
    // A signed route's body is read, bounded, before its signature can be judged.
    if plan.body == BodyAt::BoundedBeforeVerify {
        if let Some(decision) = body_step(facts, false) {
            return decision;
        }
    }
    // Steps 2 and 3.
    let verified = verifies(plan.verify, facts);
    if verified {
        let unverified = refuse(
            Refusal::Unverified {
                presented: facts.presented || facts.ticket_presented,
            },
            false,
        );
        let identity = match facts.verified {
            None => return Decision::Run(Step::Verify),
            Some(Verified::Unavailable) => return refuse(Refusal::VerifierUnavailable, false),
            Some(Verified::Denied) => return unverified,
            Some(identity) => identity,
        };
        // The verifier's answer must be one this route's record admits.
        let admitted = match (plan.verify, identity) {
            (VerifyBy::Chain | VerifyBy::ChainIfPresented, Verified::Identity { .. }) => true,
            (VerifyBy::TicketOrChain, Verified::Ticket) => true,
            (VerifyBy::TicketOrChain, Verified::Identity { .. }) => record.who.has(Who::PRINCIPAL),
            (VerifyBy::Signature, Verified::Signature) => true,
            (VerifyBy::AdminChain, Verified::Operator) => true,
            _ => false,
        };
        if !admitted {
            return unverified;
        }
        // A ticket was minted for a key already judged; a signature and an operator earn no key.
        if plan.policy && matches!(identity, Verified::Identity { .. }) {
            match facts.policy {
                None => return Decision::Run(Step::Policy),
                Some(Policy::Valid) => {}
                Some(Policy::NoKey) => return unverified,
                Some(Policy::Disabled) => return refuse(Refusal::KeyDisabled, true),
                Some(Policy::Replayed) => return refuse(Refusal::Replayed, false),
            }
        }
    }
    // From here the caller is verified wherever the record asked for it.
    let known = verified;
    // The upgrade request is judged before anything is counted against the key.
    if plan.upgrade {
        match facts.upgrade {
            None => return Decision::Run(Step::Upgrade),
            Some(UpgradeAsked::Carried) => {}
            Some(UpgradeAsked::NotAnUpgrade) => return refuse(Refusal::NotAnUpgrade, known),
            Some(UpgradeAsked::NoTransport) => return refuse(Refusal::NoUpgradeTransport, known),
        }
    }
    // Step 4.
    if plan.body == BodyAt::AfterVerify {
        if let Some(decision) = body_step(facts, known) {
            return decision;
        }
    }
    // Step 5, where core judges before the plane is called.
    if plan.scope == JudgedAt::BeforeServe {
        match facts.scope {
            None => return Decision::Run(Step::Scope),
            Some(ScopeJudged::Permitted) => {}
            Some(ScopeJudged::Denied) => return refuse(Refusal::ScopeDenied, known),
        }
    }
    // Steps 6 and 7, where they run before the serve. On a walk the unit is opened here (the
    // money record must be writable before the plane is called) and the rest is judged at FORWARD
    // by [`decide_forward`].
    match plan.money {
        JudgedAt::Nowhere => {}
        JudgedAt::BeforeServe => {
            if let Some(decision) = limits_step(facts, known) {
                return decision;
            }
            if let Some(decision) = unit_step(facts, known) {
                return decision;
            }
        }
        JudgedAt::InWalk => match facts.unit {
            None => return Decision::Run(Step::Unit),
            Some(Unit::Unwritable) => return refuse(Refusal::MoneyUnavailable, known),
            Some(Unit::Admitted | Unit::Unpriced | Unit::BudgetSpent { .. }) => {}
        },
    }
    Decision::Serve(plan.serves)
}

fn limits_step(facts: &Facts, verified: bool) -> Option<Decision> {
    Some(match facts.limits {
        None => Decision::Run(Step::Limits),
        Some(Limits::Within) => return None,
        Some(Limits::GroupFrozen) => refuse(Refusal::GroupFrozen, verified),
        Some(Limits::GroupUnknown) => refuse(Refusal::GroupUnknown, verified),
        Some(Limits::InFlight) => refuse(Refusal::InFlight, verified),
        Some(Limits::Window { retry_after_s }) => {
            refuse(Refusal::Window { retry_after_s }, verified)
        }
    })
}

fn unit_step(facts: &Facts, verified: bool) -> Option<Decision> {
    Some(match facts.unit {
        None => Decision::Run(Step::Unit),
        Some(Unit::Admitted) => return None,
        Some(Unit::Unwritable) => refuse(Refusal::MoneyUnavailable, verified),
        Some(Unit::Unpriced) => refuse(Refusal::Unpriced, verified),
        Some(Unit::BudgetSpent { retry_after_s }) => {
            refuse(Refusal::BudgetSpent { retry_after_s }, verified)
        }
    })
}

/// What the walk knows at the plane's FORWARD on an [`Authority::Walk`] request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardFacts {
    pub scope: ScopeJudged,
    /// The price of the resolved name is known.
    pub priced: bool,
    pub limits: Limits,
    pub unit: Unit,
}

/// Steps 5 to 7 inside the serve, in order, before the first byte goes upstream: scope, then the
/// price, then limits and money in one step. `Ok`: forward. A name that is not configured is the
/// plane's own 404 (row 11) and is found between scope and price by the walk itself.
pub fn decide_forward(money: Money, facts: &ForwardFacts) -> Result<(), Refusal> {
    if facts.scope == ScopeJudged::Denied {
        return Err(Refusal::ScopeDenied);
    }
    if money == Money::None {
        return Ok(());
    }
    if !facts.priced {
        return Err(Refusal::Unpriced);
    }
    match facts.limits {
        Limits::Within => {}
        Limits::GroupFrozen => return Err(Refusal::GroupFrozen),
        Limits::GroupUnknown => return Err(Refusal::GroupUnknown),
        Limits::InFlight => return Err(Refusal::InFlight),
        Limits::Window { retry_after_s } => return Err(Refusal::Window { retry_after_s }),
    }
    match facts.unit {
        Unit::Admitted => Ok(()),
        Unit::Unwritable => Err(Refusal::MoneyUnavailable),
        Unit::Unpriced => Err(Refusal::Unpriced),
        Unit::BudgetSpent { retry_after_s } => Err(Refusal::BudgetSpent { retry_after_s }),
    }
}

/// What the operator's configuration offers a declared route (design C6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offered {
    /// Some opened auth instance reads the route's credential header (or the chain's own).
    pub verifier_reads_header: bool,
    /// A transport on the listener can carry an upgrade.
    pub upgrade_transport: bool,
    /// Core's ticket store is open (a signing key is configured): a ticket can be minted and redeemed.
    pub ticket_store: bool,
    /// A signature verifier is configured for the route.
    pub signature_verifier: bool,
    /// The route's challenge names a public URL and none is configured.
    pub challenge_unresolved: bool,
}

/// Why a declared route is not mounted. Every reason is the operator's configuration; "no path
/// admits this class" is not a reason this type can state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotMounted {
    NoVerifierReadsItsHeader,
    NoUpgradeTransport,
    NoSignatureVerifier,
    NoTicketStore,
    NoPublicUrlForItsChallenge,
    /// A line or recovery route: no client reaches it, by design.
    Internal,
}

impl NotMounted {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoVerifierReadsItsHeader => {
                "no configured auth instance reads this route's credential header"
            }
            Self::NoUpgradeTransport => "no transport on this listener can carry an upgrade",
            Self::NoSignatureVerifier => "no signature verifier is configured for this route",
            Self::NoTicketStore => {
                "the route admits a ticket and no signing key is configured to mint one"
            }
            Self::NoPublicUrlForItsChallenge => {
                "the route's challenge names the plane's public URL and none is configured"
            }
            Self::Internal => "internal route: not reachable from a listener",
        }
    }
}

/// Whether a declared route is mounted under this configuration. A route that is not is answered
/// as an unknown path is, logged once at boot and on every apply, and listed by the admin API.
pub fn mounted(record: &RouteRecord, offered: Offered) -> Result<Admission, NotMounted> {
    let admission = admission_of(record);
    let Some(plan) = plan(admission, record.money) else {
        return Err(NotMounted::Internal);
    };
    match plan.verify {
        VerifyBy::Nobody | VerifyBy::AdminChain => {}
        VerifyBy::Chain | VerifyBy::ChainIfPresented => {
            if !offered.verifier_reads_header {
                return Err(NotMounted::NoVerifierReadsItsHeader);
            }
        }
        // A ticket is core's own; the chain is needed only where a key is also admitted.
        VerifyBy::TicketOrChain => {
            if !offered.ticket_store {
                return Err(NotMounted::NoTicketStore);
            }
            if record.who.has(Who::PRINCIPAL) && !offered.verifier_reads_header {
                return Err(NotMounted::NoVerifierReadsItsHeader);
            }
        }
        VerifyBy::Signature => {
            if !offered.signature_verifier {
                return Err(NotMounted::NoSignatureVerifier);
            }
        }
    }
    if plan.upgrade && !offered.upgrade_transport {
        return Err(NotMounted::NoUpgradeTransport);
    }
    if offered.challenge_unresolved {
        return Err(NotMounted::NoPublicUrlForItsChallenge);
    }
    Ok(admission)
}

impl Refusal {
    /// The row of the table a governance block is answered by: the one place a limit, a frozen
    /// or unknown group, a drain and a full settlement backlog get their status and code. The
    /// words stay the governance book's (they name the group and the window); the status is
    /// this row's, except where the row lets a dialect choose (a spent budget).
    pub fn of_blocked(blocked: &crate::governance::LimitBlocked) -> Refusal {
        use crate::governance::LimitBlocked;
        let seconds = |retry_after: &Option<u64>| {
            retry_after.map(|seconds| u32::try_from(seconds).unwrap_or(u32::MAX))
        };
        match blocked {
            LimitBlocked::Limit {
                metric: "budget",
                retry_after,
                ..
            } => Refusal::BudgetSpent {
                retry_after_s: seconds(retry_after),
            },
            LimitBlocked::Limit {
                metric: "concurrent",
                ..
            } => Refusal::InFlight,
            LimitBlocked::Limit { retry_after, .. } => match seconds(retry_after) {
                Some(retry_after_s) => Refusal::Window { retry_after_s },
                // A window that never rolls states no wait: nothing to retry after.
                None => Refusal::InFlight,
            },
            LimitBlocked::Disabled(_) => Refusal::GroupFrozen,
            // The operator's fault, and it must not invite retries: 403, never 429 (decision 13f).
            LimitBlocked::MissingGroup(_) => Refusal::GroupUnknown,
            LimitBlocked::Draining => Refusal::Draining,
            // Finished units await settlement and no more may be opened: the money record cannot
            // take another unit now.
            LimitBlocked::CustodyFull { .. } => Refusal::MoneyUnavailable,
        }
    }
}
