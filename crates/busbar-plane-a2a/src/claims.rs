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
mod tests {
    use super::{CLAIMS, P_ROOT, SCHEME_ALTS, TRANSPORT_GRPC, TRANSPORT_HTTP};
    use busbar_contract::grammar::Selector;

    /// The mount points are the codec's own, not a second opinion.
    ///
    /// This is the pin the module header promises: if the codec ever moves this protocol's mount,
    /// the claim that says where it lives goes red here rather than quietly claiming an empty path.
    #[test]
    fn the_mount_points_are_the_codecs_own() {
        assert_eq!(P_ROOT, busbar_a2a_codec::MOUNT_PATH);
        // The framed binding's mount is one path segment, and the claim spells it as that one
        // segment followed by the method.
        assert_eq!(busbar_a2a_codec::GRPC_MOUNT_PATH, "/lf.a2a.v1.A2AService");
    }

    /// This plane's registry key is the codec's own.
    #[test]
    fn the_plane_key_is_the_codecs_own() {
        assert_eq!(
            <crate::A2aPlane as busbar_contract::plane::PlaneMeta>::KEY,
            busbar_a2a_codec::PLANE_KEY
        );
    }

    /// Every claim names one of the two declared transports and nothing else.
    #[test]
    fn every_claim_names_a_declared_transport() {
        for claim in CLAIMS {
            assert!(
                claim.transport == TRANSPORT_HTTP || claim.transport == TRANSPORT_GRPC,
                "a claim names the undeclared transport {}",
                claim.transport
            );
        }
    }

    /// Every claim either declares the one scheme and its alternatives, or declares none.
    ///
    /// A plane may narrow to an alternative its claim declares and to nothing else, so a claim that
    /// declared a narrower set than its siblings would refuse a unit its siblings admit, for no
    /// reason a reader could find. The three open surfaces are the other case: no scheme, and
    /// therefore no alternatives — the emptiness is what makes the narrowing check meaningful,
    /// because there is nothing there to narrow DOWN to.
    #[test]
    fn every_claim_declares_one_scheme_or_none() {
        let mut open = 0usize;
        for claim in CLAIMS {
            match claim.scheme {
                Some(scheme) => {
                    assert_eq!(scheme, super::SCHEME);
                    assert_eq!(claim.scheme_alternatives, SCHEME_ALTS);
                }
                None => {
                    open += 1;
                    assert!(claim.is_anonymous());
                    assert!(claim.scheme_alternatives.is_empty());
                }
            }
        }
        assert_eq!(open, 3, "the three open surfaces are exactly three");
    }

    /// No declared alternative is the word "anonymous".
    ///
    /// The absence of a credential is a property of the CLAIM, not one more thing a plane may
    /// narrow to. This is the assertion that keeps the invented alternative from coming back.
    #[test]
    fn no_alternative_stands_in_for_having_no_credential() {
        for claim in CLAIMS {
            assert!(!claim.scheme_alternatives.contains(&"anonymous"));
        }
    }

    /// No claim declares an idempotency location.
    #[test]
    fn no_claim_declares_idempotency() {
        for claim in CLAIMS {
            assert!(claim.idempotency.is_none());
        }
    }

    /// The claim list matches the route table the codec actually mounts.
    ///
    /// The route table is built inside the codec crate and is not reachable as a value from here, so
    /// this reads the codec's own source and asserts that every path literal it mounts is one this
    /// plane claims. A route the codec serves and this plane does not claim would arrive and find no
    /// plane; a claim with no route behind it would take bytes nothing can answer.
    #[test]
    fn every_mounted_route_is_claimed() {
        let sources = concat!(
            include_str!("../../busbar-a2a/src/a2a/rest.rs"),
            include_str!("../../busbar-a2a/src/a2a/receive.rs"),
            include_str!("../../busbar-a2a/src/a2a/serve.rs"),
            include_str!("../../busbar-a2a/src/a2a/card.rs"),
            include_str!("../../busbar-a2a/src/a2a/pushback.rs"),
            include_str!("../../busbar-a2a/src/a2a/grpc.rs"),
        );
        // Each row is the route as this plane claims it, beside the fragment the codec's own source
        // composes it from. The codec builds most of its paths by formatting a mount constant into a
        // template, so the fragment is the template rather than the finished string: what is being
        // pinned is that the codec still spells this route, not that it spells it as one literal.
        let mounted: [(&str, &str); 11] = [
            ("/a2a/message:send", r#"{mount}/message:send"#),
            ("/a2a/message:stream", r#"{mount}/message:stream"#),
            ("/a2a/tasks", r#"{mount}/tasks"#),
            ("/a2a/tasks/{id}", r#"{mount}/tasks/{{id}}"#),
            (
                "/a2a/tasks/{id}/pushNotificationConfigs",
                r#"{mount}/tasks/{{id}}/pushNotificationConfigs"#,
            ),
            (
                "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}",
                r#"{mount}/tasks/{{id}}/pushNotificationConfigs/{{config_id}}"#,
            ),
            ("/a2a/extendedAgentCard", r#"{mount}/extendedAgentCard"#),
            (
                "/.well-known/oauth-protected-resource/a2a",
                "/.well-known/oauth-protected-resource/a2a",
            ),
            (
                "/.well-known/agent-card.json",
                "/.well-known/agent-card.json",
            ),
            ("/a2a/agents/{agent_id}", r#"{}/agents/{{agent_id}}"#),
            ("/a2a/push", r#"PUSH_PATH_SUFFIX: &str = "/push""#),
        ];
        for (path, fragment) in mounted {
            assert!(
                sources.contains(fragment),
                "the codec no longer spells {path} as {fragment}, so the claim for it is stale"
            );
            assert!(
                claims_match(path),
                "the codec mounts {path} and this plane claims nothing that matches it"
            );
        }
        // The framed binding is one service and one method segment, composed from the same constant.
        assert!(sources.contains(r#"format!("{}/{{method}}", super::serve::GRPC_MOUNT_PATH)"#));
        assert!(claims_match("/lf.a2a.v1.A2AService/{method}"));
    }

    /// Whether some claim of this plane matches a mounted route shape.
    ///
    /// A brace-delimited segment in the codec's spelling stands for any one segment, so it is
    /// compared against a variable segment rather than against a literal.
    fn claims_match(path: &str) -> bool {
        CLAIMS.iter().any(|c| match c.selector {
            Selector::ExactPath(p) => p == path,
            Selector::PathPattern(pattern) => pattern_matches(pattern, path),
            _ => false,
        })
    }

    /// Whether a segment pattern matches a route shape, treating a braced segment as a variable.
    fn pattern_matches(pattern: &[busbar_contract::grammar::PathSeg], path: &str) -> bool {
        use busbar_contract::grammar::PathSeg;
        let mut segments = path.split('/').filter(|s| !s.is_empty());
        for seg in pattern {
            match seg {
                PathSeg::Tail => return true,
                PathSeg::Lit(lit) => match segments.next() {
                    Some(s) if s == *lit => {}
                    _ => return false,
                },
                PathSeg::Var => match segments.next() {
                    Some(s) if s.starts_with('{') && s.ends_with('}') => {}
                    _ => return false,
                },
            }
        }
        segments.next().is_none()
    }

    /// The order is most-specific-first: no exact path sits below a pattern that would match it.
    ///
    /// Within one plane the claims are an ordered set and the first match wins, so a pattern placed
    /// above an exact path it covers would swallow that path's units and the exact claim would never
    /// be reached.
    #[test]
    fn no_pattern_sits_above_an_exact_path_it_covers() {
        for (i, later) in CLAIMS.iter().enumerate() {
            let Selector::ExactPath(exact) = later.selector else {
                continue;
            };
            for earlier in &CLAIMS[..i] {
                if let Selector::PathPattern(pattern) = earlier.selector {
                    assert!(
                        !concrete_matches(pattern, exact),
                        "a pattern above {exact} would swallow it"
                    );
                }
            }
        }
    }

    /// Whether a segment pattern matches a concrete path.
    fn concrete_matches(pattern: &[busbar_contract::grammar::PathSeg], path: &str) -> bool {
        use busbar_contract::grammar::PathSeg;
        let mut segments = path.split('/').filter(|s| !s.is_empty());
        for seg in pattern {
            match seg {
                PathSeg::Tail => return true,
                PathSeg::Lit(lit) => match segments.next() {
                    Some(s) if s == *lit => {}
                    _ => return false,
                },
                PathSeg::Var => {
                    if segments.next().is_none() {
                        return false;
                    }
                }
            }
        }
        segments.next().is_none()
    }
}
