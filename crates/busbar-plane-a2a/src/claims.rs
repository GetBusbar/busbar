//! The claims this plane makes over arriving bytes.
//!
//! A claim is the only way a plane names a transport, and it names it as a claim — never as a
//! connection. Each claim carries exactly ONE selector, which is why the surface below is a list
//! rather than a handful of route patterns: a boot that has to decide whether two claims could match
//! the same bytes cannot do it through an unexplained disjunction.
//!
//! The list is in most-specific-first order. Within one plane the claims are an ordered set with
//! most-specific-wins precedence, so an exact path sitting above a pattern that would also match it
//! is expected and is not a boot refusal; the overlap rule is what stops two DIFFERENT planes
//! claiming one request, and ordering is what settles a contest inside this one.
//!
//! ## Where the paths come from
//!
//! The two mount points are read from the codec crate's own constants rather than written again
//! here, so there is exactly one answer to "where does this protocol live". The route shapes BELOW
//! those mount points are spelled out, because the codec builds them by formatting rather than by
//! naming a constant per route, and a formatted string is not something a constant can borrow. The
//! tests pin every one of them against the codec's own route table.

use busbar_contract::grammar::{Claim, PathSeg, Selector};

/// The request transport every one of this plane's document claims is made against.
pub const TRANSPORT_HTTP: &str = "http";

/// The framed transport the newer binding of this protocol is made against.
pub const TRANSPORT_GRPC: &str = "grpc";

/// The credential scheme this plane's authenticated claims sit under.
///
/// One scheme with alternatives, not several schemes: which alternative a unit uses is the
/// authenticate step's answer, and a plane may only narrow within the set declared here.
const SCHEME: &str = "a2a-inbound";

/// The alternatives a unit may be narrowed to.
///
/// One: the bearer form an authenticated caller presents.
///
/// There is no anonymous form. There used to be one, invented as a scheme alternative because a
/// claim could not say "these units carry no credential" any other way — and a scheme alternative
/// meaning "none" is exactly what makes the authenticate step's narrowing check toothless, because
/// narrowing DOWN to it would pass. This protocol's three deliberately open surfaces say it in the
/// one place it belongs instead: their own claims declare no scheme.
const SCHEME_ALTS: &[&str] = &["bearer"];

/// Build one claim over a selector on the document transport.
const fn http(selector: Selector) -> Claim {
    Claim {
        transport: TRANSPORT_HTTP,
        selector,
        scheme: Some(SCHEME),
        scheme_alternatives: SCHEME_ALTS,
        // No idempotency location is declared. The codec reads no client-supplied idempotency key
        // today, and declaring one here would change the shape of every request that reaches an
        // agent, which is precisely the behaviour this crate is not allowed to change.
        idempotency: None,
    }
}

/// Build one claim over a selector on the framed transport.
const fn grpc(selector: Selector) -> Claim {
    Claim {
        transport: TRANSPORT_GRPC,
        selector,
        scheme: Some(SCHEME),
        scheme_alternatives: SCHEME_ALTS,
        idempotency: None,
    }
}

/// Build one document-transport claim whose units carry no credential at all.
///
/// Not "a scheme called anonymous": no scheme. The claim admits the anonymous principal without
/// consulting one, which is what a deliberately open surface actually is.
const fn open_http(selector: Selector) -> Claim {
    Claim {
        transport: TRANSPORT_HTTP,
        selector,
        scheme: None,
        scheme_alternatives: &[],
        idempotency: None,
    }
}

/// The single-message surface.
const P_MESSAGE_SEND: &str = "/a2a/message:send";

/// The streamed-message surface.
const P_MESSAGE_STREAM: &str = "/a2a/message:stream";

/// The task collection.
const P_TASKS: &str = "/a2a/tasks";

/// The extended-card surface.
const P_EXTENDED_CARD: &str = "/a2a/extendedAgentCard";

/// The callback an agent this node dialled posts back to.
const P_PUSH: &str = "/a2a/push";

/// The plane's own request surface, and the same surface with a trailing separator.
const P_ROOT: &str = "/a2a";

/// The same surface written with the trailing separator some clients send.
const P_ROOT_SLASH: &str = "/a2a/";

/// The discovery document naming the resource this protocol is protected as.
const P_METADATA: &str = "/.well-known/oauth-protected-resource/a2a";

/// The discovery document carrying the agent's own card.
const P_CARD: &str = "/.well-known/agent-card.json";

/// One task, by identifier.
const PAT_TASK: &[PathSeg] = &[PathSeg::Lit("a2a"), PathSeg::Lit("tasks"), PathSeg::Var];

/// A task's push-notification configurations, as a collection.
const PAT_TASK_PUSH: &[PathSeg] = &[
    PathSeg::Lit("a2a"),
    PathSeg::Lit("tasks"),
    PathSeg::Var,
    PathSeg::Lit("pushNotificationConfigs"),
];

/// One of a task's push-notification configurations.
const PAT_TASK_PUSH_ONE: &[PathSeg] = &[
    PathSeg::Lit("a2a"),
    PathSeg::Lit("tasks"),
    PathSeg::Var,
    PathSeg::Lit("pushNotificationConfigs"),
    PathSeg::Var,
];

/// One agent of the catalogue, by identifier.
const PAT_AGENT: &[PathSeg] = &[PathSeg::Lit("a2a"), PathSeg::Lit("agents"), PathSeg::Var];

/// One method of the framed binding's one service.
const PAT_GRPC: &[PathSeg] = &[PathSeg::Lit("lf.a2a.v1.A2AService"), PathSeg::Var];

/// The claims, most specific first.
///
/// The order is the order the codec mounts its routes in, which is the order a request is matched
/// in today. Keeping the two the same is what makes "this plane claims exactly what the codec
/// serves" a checkable sentence rather than a hopeful one.
pub const CLAIMS: &[Claim] = &[
    // The two unauthenticated discovery documents. Exact paths, and the tightest thing here.
    // They declare no scheme, which is how a claim says its units carry no credential.
    open_http(Selector::ExactPath(P_METADATA)),
    open_http(Selector::ExactPath(P_CARD)),
    // The unauthenticated callback surface, declared the same way.
    open_http(Selector::ExactPath(P_PUSH)),
    // The document binding's named operations, exact before patterned.
    http(Selector::ExactPath(P_MESSAGE_SEND)),
    http(Selector::ExactPath(P_MESSAGE_STREAM)),
    http(Selector::ExactPath(P_EXTENDED_CARD)),
    http(Selector::ExactPath(P_TASKS)),
    // One task's configurations, deepest pattern first.
    http(Selector::PathPattern(PAT_TASK_PUSH_ONE)),
    http(Selector::PathPattern(PAT_TASK_PUSH)),
    http(Selector::PathPattern(PAT_TASK)),
    // One agent of the catalogue.
    http(Selector::PathPattern(PAT_AGENT)),
    // The plane's own request surface, both spellings, loosest of the document claims.
    http(Selector::ExactPath(P_ROOT)),
    http(Selector::ExactPath(P_ROOT_SLASH)),
    // The framed binding: one service, one method segment.
    grpc(Selector::PathPattern(PAT_GRPC)),
];

#[cfg(test)]
#[path = "tests/claims.rs"]
mod tests;
