// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot seal: seven transports, the planes' declared claims, and the checks that answer before a
//! listener is bound.
//!
//! ## What the claim check reads, and what it does not
//!
//! Stated first, because the name "claim overlap check" promises more than this file can keep. The
//! claims compared here are each plane's DECLARED claims — `PlaneMeta::CLAIMS`, the pure plane
//! crate's own compile-time words. The paths a request is actually routed on are a different
//! object: each installed `busbar_kernel::plane::registry::PlaneDecl`'s `claims` hook, evaluated over
//! the plane's runtime object at app build, is what `build_dispatch` mounts, and nothing here reads
//! it. So a clean seal says the declarations do not tie; it does not say two planes' LIVE, configured
//! routes cannot collide. That second check belongs where the live claims are folded
//! (`build_dispatch`), which is not this file, and until it exists a live collision is resolved by
//! whatever that fold does with it rather than refused at boot.
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
//! `seal_claims` is the cross-plane overlap rule. Within one plane, claims are an ordered pattern
//! set with most-specific-wins precedence, so two of a plane's own claims may overlap and are not
//! compared here. Across planes, an overlap is a question the same order answers: where the two
//! claims sit at different precedence the more specific one takes the bytes, and the pair is
//! RESOLVED — recorded, with the winner named. Where the precedence ties there is no principled way
//! to decide which plane owns the bytes, and that is the REFUSAL, answered at boot with both claims
//! named rather than at the first request. Claims whose scheme sets are disjoint never overlap at
//! all: one request carries one credential.
//!
//! `check_composition` is the transport rule, in both directions: every layer a transport declares
//! it can be built over must be registered, and every layer the root actually built it over must be
//! one it declares. Neither half implies the other — a transport can declare a layer nobody
//! registered, and a root can compose a transport over a layer it never declared.
//!
//! ## The declared claim set seals, and this is where that is measured
//!
//! **164 of the cross-plane pairs overlap** — 100 across selector families and 64 within the path
//! family. Both numbers follow from the overlap rule as the design writes it, and neither is a
//! rounding of the other. (The decision plane joining the seal, item 251, added eleven: its two
//! exact paths against every header claim, and its `/v1/models` against the llm plane's
//! `v1/models/<tail>` pattern — which the order settles in the exact path's favour.)
//!
//! The 90 are the conservative arm, and they are conservative because a request really does carry
//! both a path and a header: `HeaderPresent("x-api-key")` and `ExactPath("/mcp")` can be true of one
//! arrival, so an overlap is the honest answer rather than a limitation. The 63 are what is left
//! inside the path family once the grammar reads a suffix and a substring as the segment
//! constraints they are: a suffix pins a pattern's last segments, a substring carrying slashes asks
//! for consecutive whole ones, and a pattern with a literal in the way cannot produce a path that
//! satisfies either. That reading is what took the path-family count from 119 to 65, and naming the
//! audio surface one path at a time rather than as a prefix — so that the two one-shot audio
//! operations belong to the plane the inventory gives them to, instead of being described by two
//! planes at once — took it from 65 to 63, and the decision plane's `/v1/models` made it 64. Of the
//! 64, 24 involve a pattern ending in a tail (which
//! can supply whatever the fragment asks for), 24 are a fragment landing inside a pattern's
//! variable segment, and 16 are two fragment forms that can be satisfied at once by writing a path
//! with both. Every one of them is a real shape, not a gap in the reasoning.
//!
//! All 164 are settled by the sealed order, and none of them is a refusal. That is not the check
//! being softened: every one of the 164 is a pair whose two claims sit at different precedence, so
//! the order already says which plane takes bytes both describe, and the pair is recorded in
//! `resolved` with its winner named. The tests below pin the count at 164, the refusal count at
//! zero and the sealed order itself, so a declaration change that turns a resolved pair into a tie —
//! the shape nothing can decide — has to say so here. A root that skipped the check to get a node
//! running would be choosing which plane's DECLARATION owns a shape by accident of registration
//! order, which is the one thing the check exists to prevent — for the declarations. See the section
//! above for the live routes it does not reach.
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
use busbar_core_admin::admin_codec::AdminPlane;
use busbar_kernel::registry::{seal_claims, ClaimConflict, PlaneClaim, Registry, ResolvedOverlap};
use busbar_plane_a2a::A2aPlane;
use busbar_plane_llm::LlmPlane;
use busbar_plane_mcp::McpPlane;
#[cfg(feature = "plane-voice")]
use busbar_plane_streaming::StreamingPlane;
use busbar_transport_grpc::GrpcTransport;
use busbar_transport_http::{ClientSettings, HttpTransport};
use busbar_transport_sse::SseTransport;
use busbar_transport_stdio::StdioTransport;
use busbar_transport_tcp::TcpTransport;
use busbar_transport_tls::TlsTransport;
// The WS transport is the voice plane's edge and the one transport that leaves with its plane, so
// its crate — and everything below it — is compiled only when voice is.
#[cfg(feature = "plane-voice")]
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
    /// The breaker and egress units' hand-kept metric label banks disagree on a label both carry,
    /// so one breaker disposition would reach the scrape under two label values.
    LabelDrift(crate::root::adapters::LabelDrift),
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
            Self::LabelDrift(drift) => write!(f, "{drift}"),
        }
    }
}

impl std::error::Error for BootRefusal {}

/// The composed transports the root keeps a concrete handle on.
///
/// The registry holds every transport as an `Arc<dyn Plugin>`, which is all the registry needs. The
/// root needs more than that in one place: the HTTP transport is the concrete lower layer SSE is
/// composed over. Holding them here is the difference between a stack that is declared and a stack
/// that is wired.
pub struct ComposedTransports {
    /// The bottom layer.
    pub tcp: Arc<TcpTransport>,
    /// The TLS layer.
    pub tls: Arc<TlsTransport>,
    /// The HTTP layer, and the concrete lower layer SSE takes.
    pub http: Arc<HttpTransport>,
    /// Server-sent events over HTTP.
    pub sse: Arc<SseTransport>,
    /// WebSocket, built over HTTP — never over nothing.
    #[cfg(feature = "plane-voice")]
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
    /// Every cross-plane pair that could both match and was settled by that order, with the winning
    /// claim named. Not a warning list: it is the record of which plane owns a shape two planes both
    /// describe, answered once at boot rather than per request.
    pub resolved: Vec<ResolvedOverlap>,
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

    // Declaration order is what breaks precedence ties, so the planes are appended in the order the
    // table has always read: llm, mcp, a2a, voice, admin. Voice's row is present exactly when its
    // crate edge is — a claim from a plane this build does not register would name a plane, and a
    // transport, that no request could ever reach.
    let mut claims: Vec<PlaneClaim> = claims_of::<LlmPlane>()
        .chain(claims_of::<McpPlane>())
        .chain(claims_of::<A2aPlane>())
        .collect();
    #[cfg(feature = "plane-voice")]
    claims.extend(claims_of::<StreamingPlane>());
    // The decision plane (#48's fifth) is appended after the four it joined, for the same reason
    // voice is gated: its claims are in the seal exactly when its crate edge is in the build.
    #[cfg(feature = "plane-decision")]
    claims.extend(claims_of::<busbar_plane_decision::DecisionPlane>());
    claims.extend(claims_of::<AdminPlane>());
    claims
}

/// Build the seven transports, bottom-up, composing the two that are only serviceable composed.
///
/// Registration order is the build order for a reason: `check_composition` resolves a declared
/// layer against what is registered, so a layer must exist before anything that names it.
fn compose_transports(client_settings: ClientSettings) -> ComposedTransports {
    // The same number the door refuses a body at. A WebSocket message is assembled from
    // continuation frames before anything above the transport sees it, so the ceiling has to be
    // stated at the handshake or it is not stated at all — and a node that refuses a body of a
    // given size over HTTP has no basis for holding a larger one over a socket it upgraded.
    #[cfg(feature = "plane-voice")]
    let max_message_bytes = client_settings.request_body_max_bytes;
    let tcp = Arc::new(TcpTransport::new());
    let tls = Arc::new(TlsTransport::new());
    let http = Arc::new(HttpTransport::new(client_settings));
    let sse = Arc::new(SseTransport::new(Arc::clone(&http)));
    #[cfg(feature = "plane-voice")]
    let ws = Arc::new(WsTransport::over_with_max_message_bytes(
        Arc::clone(&http) as Arc<dyn Transport>,
        max_message_bytes,
    ));
    let grpc = Arc::new(GrpcTransport::over(Arc::clone(&http) as Arc<dyn Transport>));
    let stdio = Arc::new(StdioTransport::new());
    ComposedTransports {
        tcp,
        tls,
        http,
        sse,
        #[cfg(feature = "plane-voice")]
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
    let mut rows = vec![
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
    ];
    // WS goes in beside the others when the voice plane is compiled, and leaves with it: a row for a
    // transport this build does not carry would be the root stating a composition it did not make.
    #[cfg(feature = "plane-voice")]
    rows.push(Registered {
        key: WsTransport::KEY,
        composes_over: WsTransport::COMPOSES_OVER,
        composed_over: Some(HttpTransport::KEY),
    });
    rows.push(Registered {
        key: GrpcTransport::KEY,
        composes_over: GrpcTransport::COMPOSES_OVER,
        composed_over: Some(HttpTransport::KEY),
    });
    rows.push(Registered {
        key: StdioTransport::KEY,
        composes_over: StdioTransport::COMPOSES_OVER,
        composed_over: None,
    });
    rows
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
    let sealed = seal_claims(&claims);
    if let Some(refused) = sealed.refused.first() {
        return Err(BootRefusal::ClaimOverlap(Box::new(ClaimConflict {
            left: claims[refused.left].clone(),
            right: claims[refused.right].clone(),
            reason: refused.reason,
        })));
    }

    let registered = registered_rows();
    check_composition(&registered).map_err(BootRefusal::Composition)?;
    check_claim_transports(&claims, &registered)?;
    // The two units' metric label banks are duplicate literals kept in step by hand; this is the
    // one boot check that compares them, and it runs here because this is the check every boot
    // passes through. A drift refuses the boot naming both spellings, rather than splitting one
    // breaker disposition into two label values on the scrape.
    crate::root::adapters::check_label_banks().map_err(BootRefusal::LabelDrift)?;

    Ok(BootRegistry {
        registry,
        claims,
        precedence: sealed.order,
        resolved: sealed.resolved,
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

    let mut to_register = vec![
        Arc::clone(&transports.tcp) as Arc<dyn Plugin>,
        Arc::clone(&transports.tls) as Arc<dyn Plugin>,
        Arc::clone(&transports.http) as Arc<dyn Plugin>,
        Arc::clone(&transports.sse) as Arc<dyn Plugin>,
    ];
    #[cfg(feature = "plane-voice")]
    to_register.push(Arc::clone(&transports.ws) as Arc<dyn Plugin>);
    to_register.push(Arc::clone(&transports.grpc) as Arc<dyn Plugin>);
    to_register.push(Arc::clone(&transports.stdio) as Arc<dyn Plugin>);
    for transport in to_register {
        registry
            .register(transport)
            .map_err(BootRefusal::Registry)?;
    }

    let mut planes = vec![
        Arc::new(LlmPlane::EMPTY) as Arc<dyn Plugin>,
        Arc::new(McpPlane::EMPTY) as Arc<dyn Plugin>,
        Arc::new(A2aPlane::EMPTY) as Arc<dyn Plugin>,
    ];
    // The voice plane goes in with its own crate edge and leaves with it. It is the only plane that
    // claims bytes on `ws`, so registering it in a build with no WS transport would be the root
    // mounting a plane whose claims name a layer this binary does not carry.
    #[cfg(feature = "plane-voice")]
    planes.push(Arc::new(StreamingPlane::EMPTY) as Arc<dyn Plugin>);
    #[cfg(feature = "plane-decision")]
    planes.push(Arc::new(busbar_plane_decision::DecisionPlane::EMPTY) as Arc<dyn Plugin>);
    planes.push(Arc::new(AdminPlane::new()) as Arc<dyn Plugin>);
    for plane in planes {
        registry.register(plane).map_err(BootRefusal::Registry)?;
    }

    Ok(registry)
}

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
