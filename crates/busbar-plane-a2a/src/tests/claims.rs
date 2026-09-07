//! Tests for `claims.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

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
/// Every path is a VALUE, composed by the codec's own [`mounted_route`] join. This read the
/// SERVER half's source once — six `include_str!`s over `../../busbar-a2a/src/a2a/*.rs`,
/// searched for `format!` template fragments — which coupled this crate to a sibling its
/// manifest does not name, so the plane could be neither built nor deleted on its own. Worse
/// than the coupling, the substring search could only ever say the fragment still APPEARS
/// somewhere in six files, not that it is what gets mounted. Both halves now join one set of
/// suffixes to one mount: a route the server serves and this plane does not claim would arrive
/// and find no plane, and a claim with no route behind it would take bytes nothing can answer.
#[test]
fn every_mounted_route_is_claimed() {
    for suffix in busbar_a2a_codec::MOUNTED_ROUTE_SUFFIXES {
        let path = busbar_a2a_codec::mounted_route(suffix);
        assert!(
            claims_match(&path),
            "the codec mounts {path} and this plane claims nothing that matches it"
        );
    }
    // The two well-known paths are properties of the ORIGIN and so are not under the mount.
    for path in [
        busbar_a2a_codec::METADATA_PATH,
        busbar_a2a_codec::WELL_KNOWN_CARD_PATH,
    ] {
        assert!(
            claims_match(path),
            "the codec mounts {path} and this plane claims nothing that matches it"
        );
    }
    // busbar's own push callback: the mount joined to the suffix a delivery is posted to.
    assert!(claims_match(&busbar_a2a_codec::mounted_route(
        busbar_a2a_codec::PUSH_PATH_SUFFIX
    )));
    // The framed binding is one service and one method segment, composed from the same constant.
    assert!(claims_match(&format!(
        "{}/{{method}}",
        busbar_a2a_codec::GRPC_MOUNT_PATH
    )));
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
