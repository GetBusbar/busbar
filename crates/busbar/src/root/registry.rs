// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot seal: seven transports, five planes, and the two checks that answer before a listener
//! is bound.
//!
//! ## Why the claims travel separately
//!
//! A plane declares its claims as an associated constant, which is the right shape — the claims are
//! the plane's own words, fixed at compile time, and a selector derived from configuration would be
//! a plane deciding at boot what it is for. But an associated constant cannot be read through a
//! trait object, and the registry stores `Arc<dyn Plugin>`. So the claims reach the check as a
//! second slice, built here, because this is the only place that knows both a plane's type and the
//! string that names it. That pairing is done by hand and nothing checks it, which is exactly why
//! the pairing is written once, in one table, rather than spread across the boot path.
//!
//! ## The two checks, and what each catches
//!
//! `check_claims` is the cross-plane overlap rule: within one plane, claims are an ordered pattern
//! set with most-specific-wins precedence, so two of a plane's own claims may overlap; across
//! planes they may not, because there would be no principled way to decide which plane owns the
//! bytes. It is answered at boot, with both claims named, rather than at the first request.
//!
//! `check_composition` is the transport rule, in both directions: every layer a transport declares
//! it can be built over must be registered, and every layer the root actually built it over must be
//! one it declares. Neither half implies the other — a transport can declare a layer nobody
//! registered, and a root can compose a transport over a layer it never declared.
//!
//! ## The declared claim set does not seal today, and this is where that is measured
//!
//! Running the check over the five planes as they stand is a refusal, and not by a narrow margin:
//! **209 of the cross-plane pairs overlap** — 90 across selector families and 119 within the path
//! family. Both numbers follow from the overlap rule as the design writes it. Cross-family pairs
//! overlap conservatively, because a request has both a path and a header and nothing proves they
//! cannot coincide. Within the path family, a `PathContains` or `PathSuffix` claim overlaps any
//! other claim on that family, which is stated as the rule and is what makes the reference plane's
//! protocol-detection ladder — `PathContains("/v1/messages")`, `PathSuffix("/v1/embeddings")` and
//! the rest — collide with every other plane's mounted routes.
//!
//! Nothing here papers over that. `seal` calls the check and returns the refusal, which is the
//! behaviour the design asks for; the tests below pin both counts, so the numbers move visibly when
//! the claim declarations are reconciled, and the reconciliation itself belongs to the planes and
//! the claim grammar rather than to the root. A root that skipped the check to get a node running
//! would be choosing which plane owns a request by accident of registration order, which is the one
//! thing the check exists to prevent.
//!
//! ## The shape that would pass both checks and still refuse every connection
//!
//! Two of the seven transports have a constructor that yields a serviceable transport and a
//! constructor that does not. `WsTransport::new()` and `GrpcTransport::new()` produce transports
//! whose listen, accept and dial all fail; only `over(lower)` is serviceable. A root that forgot the
//! composition would register, pass `check_composition` — because `composed_over()` returns `None`
//! and the check reads a declaration — and then refuse every connection. That is why the two are
//! built through `over` here and why the registered rows record what they were actually built over.

use std::sync::Arc;

use busbar_contract::plane::PlaneMeta;
use busbar_contract::transport::TransportMeta;
use busbar_contract::{check_composition, CompositionError, Plugin, Registered, Transport};
use busbar_kernel::registry::{
    check_claims, precedence_order, ClaimConflict, PlaneClaim, Registry,
};
use busbar_plane_a2a::A2aPlane;
use busbar_plane_admin::AdminPlane;
use busbar_plane_llm::LlmPlane;
use busbar_plane_mcp::McpPlane;
use busbar_plane_voice::VoicePlane;
use busbar_transport_grpc::GrpcTransport;
use busbar_transport_http::{ClientSettings, HttpTransport};
use busbar_transport_sse::SseTransport;
use busbar_transport_stdio::StdioTransport;
use busbar_transport_tcp::TcpTransport;
use busbar_transport_tls::TlsTransport;
use busbar_transport_ws::WsTransport;

/// Why a node will not boot.
///
/// Every arm is a statement about the composition, not about a request: an operator sees it once,
/// at start-up, with both offending names in the message, and the process does not go on to serve.
#[derive(Debug)]
pub enum BootRefusal {
    /// Two planes claim bytes that could both match.
    ClaimOverlap(Box<ClaimConflict>),
    /// A transport declares a layer nobody registered, or was built over one it does not declare.
    Composition(CompositionError),
    /// A plane claims bytes on a transport no crate in the tree provides.
    ///
    /// The design lists thirteen transports and seven exist. What the root owes is that a claim on
    /// one of the missing six is a refusal an operator sees at boot, with the plane and the
    /// transport named — never a silent 404 at the first request that would have matched it.
    UnregisteredClaimTransport {
        /// The plane that made the claim.
        plane: &'static str,
        /// The transport it claimed on.
        transport: &'static str,
    },
    /// The registry itself refused an entry.
    Registry(busbar_kernel::registry::RegistryError),
}

impl std::fmt::Display for BootRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaimOverlap(conflict) => write!(f, "{conflict}"),
            Self::Composition(err) => write!(f, "{err}"),
            Self::UnregisteredClaimTransport { plane, transport } => write!(
                f,
                "plane `{plane}` claims on transport `{transport}`, which no crate provides"
            ),
            Self::Registry(err) => write!(f, "{err:?}"),
        }
    }
}

impl std::error::Error for BootRefusal {}

/// The composed transports the root keeps a concrete handle on.
///
/// The registry holds every transport as an `Arc<dyn Plugin>`, which is all the registry needs. The
/// root needs more than that in two places: the TLS transport is the sink the transport-key unit
/// registers a resolved config into, and the HTTP transport is the concrete lower layer SSE is
/// composed over. Holding them here is the difference between a stack that is declared and a stack
/// that is wired.
pub struct ComposedTransports {
    /// The bottom layer.
    pub tcp: Arc<TcpTransport>,
    /// The TLS layer, and the sink a provisioned listener's config lands in.
    pub tls: Arc<TlsTransport>,
    /// The HTTP layer, and the concrete lower layer SSE takes.
    pub http: Arc<HttpTransport>,
    /// Server-sent events over HTTP.
    pub sse: Arc<SseTransport>,
    /// WebSocket, built over HTTP — never over nothing.
    pub ws: Arc<WsTransport>,
    /// gRPC, built over HTTP — never over nothing.
    pub grpc: Arc<GrpcTransport>,
    /// The process's own standard streams.
    pub stdio: Arc<StdioTransport>,
}

/// What the boot seal produced: a registry nothing may add to after it, and the claim order every
/// arriving connection is matched against.
pub struct BootRegistry {
    /// The registry, at the generation the checks were answered against.
    pub registry: Registry,
    /// Every plane's claims, paired with the plane that made them.
    pub claims: Vec<PlaneClaim>,
    /// Indices into `claims`, most specific first, ties broken by declaration order so the walk is
    /// stable across boots.
    pub precedence: Vec<usize>,
    /// Every transport as the composition check read it.
    pub registered: Vec<Registered>,
    /// The concrete handles the root keeps.
    pub transports: ComposedTransports,
}

/// Every plane's claims, paired with the key that names the plane.
///
/// This is the pairing nothing else in the tree can do: `<LlmPlane as PlaneMeta>::CLAIMS` needs the
/// type and `"llm"` needs the string, and only a composition root holds both.
#[must_use]
pub fn plane_claims() -> Vec<PlaneClaim> {
    fn claims_of<P: PlaneMeta>() -> impl Iterator<Item = PlaneClaim> {
        P::CLAIMS.iter().map(|claim| PlaneClaim {
            plane: P::KEY,
            claim: *claim,
        })
    }

    claims_of::<LlmPlane>()
        .chain(claims_of::<McpPlane>())
        .chain(claims_of::<A2aPlane>())
        .chain(claims_of::<VoicePlane>())
        .chain(claims_of::<AdminPlane>())
        .collect()
}

/// Build the seven transports, bottom-up, composing the two that are only serviceable composed.
///
/// Registration order is the build order for a reason: `check_composition` resolves a declared
/// layer against what is registered, so a layer must exist before anything that names it.
fn compose_transports(client_settings: ClientSettings) -> ComposedTransports {
    let tcp = Arc::new(TcpTransport::new());
    let tls = Arc::new(TlsTransport::new());
    let http = Arc::new(HttpTransport::new(client_settings));
    let sse = Arc::new(SseTransport::new(Arc::clone(&http)));
    let ws = Arc::new(WsTransport::over(Arc::clone(&http) as Arc<dyn Transport>));
    let grpc = Arc::new(GrpcTransport::over(Arc::clone(&http) as Arc<dyn Transport>));
    let stdio = Arc::new(StdioTransport::new());
    ComposedTransports {
        tcp,
        tls,
        http,
        sse,
        ws,
        grpc,
        stdio,
    }
}

/// Every transport as the composition check reads it: what it declares, and what it was actually
/// built over.
///
/// Nothing here is derived from the objects themselves. `composed_over` is the root's own statement
/// about what it did, because a check that re-derived its own inputs would agree with itself for
/// free.
fn registered_rows() -> Vec<Registered> {
    vec![
        Registered {
            key: TcpTransport::KEY,
            composes_over: TcpTransport::COMPOSES_OVER,
            composed_over: None,
        },
        Registered {
            key: TlsTransport::KEY,
            composes_over: TlsTransport::COMPOSES_OVER,
            // TLS takes its lower layer's connection at `adopt`, per connection, rather than at
            // construction: there is no lower layer to record here.
            composed_over: None,
        },
        Registered {
            key: HttpTransport::KEY,
            composes_over: HttpTransport::COMPOSES_OVER,
            // Which of TCP or TLS carries a given HTTP listener is the listener's configuration,
            // not a property of the transport object.
            composed_over: None,
        },
        Registered {
            key: SseTransport::KEY,
            composes_over: SseTransport::COMPOSES_OVER,
            composed_over: Some(HttpTransport::KEY),
        },
        Registered {
            key: WsTransport::KEY,
            composes_over: WsTransport::COMPOSES_OVER,
            composed_over: Some(HttpTransport::KEY),
        },
        Registered {
            key: GrpcTransport::KEY,
            composes_over: GrpcTransport::COMPOSES_OVER,
            composed_over: Some(HttpTransport::KEY),
        },
        Registered {
            key: StdioTransport::KEY,
            composes_over: StdioTransport::COMPOSES_OVER,
            composed_over: None,
        },
    ]
}

/// Register every axis and answer both boot checks.
///
/// Transports go in bottom-up and planes over them, then the claims are checked across planes and
/// ordered within them, then the composition is checked in both directions. Nothing binds a
/// listener until all of it has answered.
///
/// # Errors
///
/// Two planes claim bytes that could both match; a transport declares a layer nobody registered or
/// was built over one it does not declare; or the registry refused an entry.
pub fn seal(client_settings: ClientSettings) -> Result<BootRegistry, BootRefusal> {
    let transports = compose_transports(client_settings);
    let registry = register_all(&transports)?;

    let claims = plane_claims();
    check_claims(&claims).map_err(BootRefusal::ClaimOverlap)?;
    let precedence = precedence_order(&claims);

    let registered = registered_rows();
    check_composition(&registered).map_err(BootRefusal::Composition)?;
    check_claim_transports(&claims, &registered)?;

    Ok(BootRegistry {
        registry,
        claims,
        precedence,
        registered,
        transports,
    })
}

/// Every claim names a transport the root actually registered.
///
/// Neither of the two checks the kernel and the contract own covers this. `check_claims` compares
/// claims to each other and never looks at what is registered; `check_composition` reads the
/// transports and never looks at the claims. The gap between them is a plane claiming bytes on a
/// transport that does not exist, which would otherwise be discovered as a request that matched
/// nothing — so the root closes it, at boot, naming both sides.
///
/// # Errors
///
/// A claim names a transport no registered row provides.
fn check_claim_transports(
    claims: &[PlaneClaim],
    registered: &[Registered],
) -> Result<(), BootRefusal> {
    for claim in claims {
        if !registered.iter().any(|r| r.key == claim.claim.transport) {
            return Err(BootRefusal::UnregisteredClaimTransport {
                plane: claim.plane,
                transport: claim.claim.transport,
            });
        }
    }
    Ok(())
}

/// Put every transport and every plane into one registry, transports first.
///
/// Registration order is the build order, because `check_composition` resolves a declared layer
/// against what is registered and a layer must exist before anything that names it.
///
/// # Errors
///
/// The registry refused an entry — a duplicate key, or a kind it does not take.
fn register_all(transports: &ComposedTransports) -> Result<Registry, BootRefusal> {
    let mut registry = Registry::new();

    for transport in [
        Arc::clone(&transports.tcp) as Arc<dyn Plugin>,
        Arc::clone(&transports.tls) as Arc<dyn Plugin>,
        Arc::clone(&transports.http) as Arc<dyn Plugin>,
        Arc::clone(&transports.sse) as Arc<dyn Plugin>,
        Arc::clone(&transports.ws) as Arc<dyn Plugin>,
        Arc::clone(&transports.grpc) as Arc<dyn Plugin>,
        Arc::clone(&transports.stdio) as Arc<dyn Plugin>,
    ] {
        registry
            .register(transport)
            .map_err(BootRefusal::Registry)?;
    }

    for plane in [
        Arc::new(LlmPlane::EMPTY) as Arc<dyn Plugin>,
        Arc::new(McpPlane::EMPTY) as Arc<dyn Plugin>,
        Arc::new(A2aPlane::EMPTY) as Arc<dyn Plugin>,
        Arc::new(VoicePlane::EMPTY) as Arc<dyn Plugin>,
        Arc::new(AdminPlane::new()) as Arc<dyn Plugin>,
    ] {
        registry.register(plane).map_err(BootRefusal::Registry)?;
    }

    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_kernel::registry::PluginKind;

    /// Every transport and every plane goes into one registry, and both counts are what the design
    /// says they are. This is the half of the seal that does not depend on the claims.
    #[test]
    fn seven_transports_and_five_planes_register() {
        let transports = compose_transports(ClientSettings::default());
        let registry = register_all(&transports).expect("nothing collides on a key");
        assert_eq!(registry.count(PluginKind::Transport), 7);
        assert_eq!(registry.count(PluginKind::Plane), 5);
        for key in ["tcp", "tls", "http", "sse", "ws", "grpc", "stdio"] {
            assert!(
                registry.resolve(PluginKind::Transport, key).is_some(),
                "transport `{key}` is not registered"
            );
        }
        for key in ["llm", "mcp", "a2a", "voice", "admin"] {
            assert!(
                registry.resolve(PluginKind::Plane, key).is_some(),
                "plane `{key}` is not registered"
            );
        }
    }

    /// The measured claim total, one row per plane. It is pinned as a number because the number is
    /// what a reader checks the design's own table against; a plane that gains or loses a claim
    /// should have to say so here.
    #[test]
    fn the_planes_declare_forty_nine_claims() {
        let claims = plane_claims();
        let count = |plane: &str| claims.iter().filter(|c| c.plane == plane).count();
        assert_eq!(count("llm"), 25);
        assert_eq!(count("mcp"), 4);
        assert_eq!(count("a2a"), 14);
        assert_eq!(count("voice"), 5);
        assert_eq!(count("admin"), 1);
        assert_eq!(claims.len(), 49);
    }

    /// **The finding.** The forty-nine claims as declared do not seal, and the check refuses the
    /// boot rather than picking a winner. Both counts are pinned so the numbers move visibly when
    /// the claim declarations are reconciled — this test is expected to fail on that day, and its
    /// failure is the signal, not a regression.
    ///
    /// The two numbers come apart deliberately. The cross-family pairs are the conservative arm of
    /// the totality rule: a request has both a path and a header, so nothing proves a header claim
    /// and a path claim cannot coincide. The same-family pairs are the substantive half — a
    /// `PathContains` or `PathSuffix` claim overlaps any other claim on the path family, and the
    /// reference plane's protocol-detection ladder is built out of exactly those two forms.
    #[test]
    fn the_declared_claims_do_not_seal_and_the_boot_refuses() {
        use busbar_kernel::grammar::family;

        let claims = plane_claims();
        let mut cross_family = 0usize;
        let mut same_family = 0usize;
        for (i, left) in claims.iter().enumerate() {
            for right in &claims[i + 1..] {
                if left.plane == right.plane || left.claim.transport != right.claim.transport {
                    continue;
                }
                if !busbar_kernel::registry::overlaps(&left.claim.selector, &right.claim.selector) {
                    continue;
                }
                if family(&left.claim.selector) == family(&right.claim.selector) {
                    same_family += 1;
                } else {
                    cross_family += 1;
                }
            }
        }
        assert_eq!(cross_family, 90);
        assert_eq!(same_family, 119);

        match seal(ClientSettings::default()) {
            Err(BootRefusal::ClaimOverlap(_)) => {}
            Err(other) => panic!("expected a claim overlap, got {other}"),
            Ok(_) => panic!("the declared claims collide; the seal must refuse"),
        }
    }

    /// Every claim is ordered, most specific first, and the order is a permutation of the claims —
    /// no claim is dropped from the walk and none is tried twice. Read off the claim slice directly,
    /// because the seal cannot get far enough to produce one.
    #[test]
    fn the_precedence_order_is_a_permutation_of_every_claim() {
        let claims = plane_claims();
        let mut seen = precedence_order(&claims);
        seen.sort_unstable();
        assert_eq!(seen, (0..claims.len()).collect::<Vec<_>>());
    }

    /// And it is an order, not a shuffle: specificity never increases as the walk goes on, so the
    /// first claim that matches is the most specific one that could have.
    #[test]
    fn the_precedence_order_is_most_specific_first() {
        use busbar_kernel::grammar::specificity;

        let claims = plane_claims();
        let order = precedence_order(&claims);
        for pair in order.windows(2) {
            let earlier = specificity(&claims[pair[0]].claim.selector);
            let later = specificity(&claims[pair[1]].claim.selector);
            assert!(earlier >= later, "{earlier} came before {later}");
        }
    }

    /// The refusal is the point of the check. A sixth plane that claims a path the admin plane
    /// already owns is a composition nobody can resolve, and the node says so at boot with both
    /// planes named rather than picking a winner at the first request.
    #[test]
    fn a_planted_cross_plane_overlap_refuses_at_boot() {
        let admin = plane_claims()
            .into_iter()
            .find(|c| c.plane == "admin")
            .expect("the admin plane claims one path");
        let impostor = PlaneClaim {
            plane: "impostor",
            claim: admin.claim,
        };
        // A clean two-claim base, so the refusal that comes back is the one that was planted and
        // not one the declared set already carries.
        let conflict =
            check_claims(&[admin, impostor]).expect_err("two planes cannot own one path");
        let planes = [conflict.left.plane, conflict.right.plane];
        assert!(planes.contains(&"admin"));
        assert!(planes.contains(&"impostor"));
    }

    /// A plane's own claims may overlap: within one plane they are an ordered pattern set with
    /// most-specific-wins precedence, and that is what makes a catch-all tail legal beneath a
    /// specific route. Only the cross-plane case is a refusal.
    #[test]
    fn a_planes_own_claims_may_overlap() {
        let claims = plane_claims();
        let admin = claims
            .iter()
            .find(|c| c.plane == "admin")
            .expect("the admin plane claims one path")
            .clone();
        let doubled = vec![admin.clone(), admin];
        assert!(check_claims(&doubled).is_ok());
    }

    /// The shipped stack composes: every layer the seven transports declare is registered, and the
    /// three that were actually built over a lower layer were built over one they declare. This is
    /// the composition half of the seal, and it passes today.
    #[test]
    fn the_shipped_transport_stack_composes() {
        let rows = registered_rows();
        assert!(check_composition(&rows).is_ok());
        let composed_over = |key: &str| {
            rows.iter()
                .find(|r| r.key == key)
                .expect("registered")
                .composed_over
        };
        // The two transports whose `new()` yields something that refuses every connection are the
        // two that must be built through `over`, and the rows say they were.
        assert_eq!(composed_over("ws"), Some("http"));
        assert_eq!(composed_over("grpc"), Some("http"));
        assert_eq!(composed_over("sse"), Some("http"));
    }

    /// The other direction of the composition rule: a transport built over a layer it does not
    /// declare describes a node nobody is running, and the check says so.
    #[test]
    fn an_undeclared_composition_refuses_at_boot() {
        let mut rows = registered_rows();
        let stdio = rows
            .iter_mut()
            .find(|r| r.key == StdioTransport::KEY)
            .expect("stdio is registered");
        stdio.composed_over = Some(TcpTransport::KEY);

        let err = check_composition(&rows).expect_err("stdio composes over nothing");
        assert_eq!(
            err,
            CompositionError::UndeclaredComposition {
                transport: "stdio",
                used: "tcp",
            }
        );
    }

    /// And the first direction: a declared layer that no registered transport provides.
    #[test]
    fn an_unregistered_layer_refuses_at_boot() {
        let rows = vec![Registered {
            key: "sse",
            composes_over: &["http"],
            composed_over: None,
        }];
        let err = check_composition(&rows).expect_err("nothing registered http");
        assert_eq!(
            err,
            CompositionError::UnregisteredLayer {
                transport: "sse",
                layer: "http",
            }
        );
    }

    /// A guard against a claim slice that quietly names a plane the registry never took: the
    /// pairing in `plane_claims` is done by hand, so the one thing worth asserting about it is that
    /// every key it produces is a key the registry actually resolves.
    #[test]
    fn every_claimed_plane_key_is_a_registered_plane() {
        let transports = compose_transports(ClientSettings::default());
        let registry = register_all(&transports).expect("nothing collides on a key");
        for claim in &plane_claims() {
            assert!(
                registry.resolve(PluginKind::Plane, claim.plane).is_some(),
                "claim names plane `{}`, which is not registered",
                claim.plane
            );
        }
    }

    /// **The second finding.** The other side of the same pairing: a claim on a transport no crate
    /// provides. The design lists thirteen transports and seven exist; the voice plane claims on
    /// `twilio-media`, which is one of the six with no crate in the tree. The check is the root's
    /// because neither the kernel's claim check nor the contract's composition check can see both
    /// halves, and the answer it gives is a refusal at boot with both names in it.
    ///
    /// Called directly rather than through `seal`, because the claim overlap answers first today.
    #[test]
    fn a_claim_on_a_transport_with_no_crate_refuses_at_boot() {
        let refusal = check_claim_transports(&plane_claims(), &registered_rows())
            .expect_err("`twilio-media` has no crate");
        assert!(matches!(
            refusal,
            BootRefusal::UnregisteredClaimTransport {
                plane: "voice",
                transport: "twilio-media",
            }
        ));
    }

    /// And the same check, over the claims of the four planes whose transports all exist: nothing
    /// there names a transport the root did not register, so the gap is exactly one plane wide.
    #[test]
    fn every_other_planes_claims_name_a_registered_transport() {
        let registered = registered_rows();
        for claim in plane_claims().iter().filter(|c| c.plane != "voice") {
            assert!(
                registered.iter().any(|r| r.key == claim.claim.transport),
                "claim of plane `{}` names transport `{}`, which is not registered",
                claim.plane,
                claim.claim.transport
            );
        }
    }
}
