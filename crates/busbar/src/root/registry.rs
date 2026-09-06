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
//! **155 of the cross-plane pairs overlap** — 90 across selector families and 65 within the path
//! family. Both numbers follow from the overlap rule as the design writes it, and neither is a
//! rounding of the other.
//!
//! The 90 are the conservative arm, and they are conservative because a request really does carry
//! both a path and a header: `HeaderPresent("x-api-key")` and `ExactPath("/mcp")` can be true of one
//! arrival, so an overlap is the honest answer rather than a limitation. The 65 are what is left
//! inside the path family once the grammar reads a suffix and a substring as the segment
//! constraints they are: a suffix pins a pattern's last segments, a substring carrying slashes asks
//! for consecutive whole ones, and a pattern with a literal in the way cannot produce a path that
//! satisfies either. That reading is what took the path-family count from 119 to 65. Of the 65, 23
//! involve a pattern ending in a tail (which can supply whatever the fragment asks for), 24 are a
//! fragment landing inside a pattern's variable segment, and 18 are two fragment forms that can be
//! satisfied at once by writing a path with both. Every one of them is a real shape, not a gap in
//! the reasoning.
//!
//! All 155 are settled by the sealed order, and none of them is a refusal. That is not the check
//! being softened: every one of the 155 is a pair whose two claims sit at different precedence, so
//! the order already says which plane takes bytes both describe, and the pair is recorded in
//! `resolved` with its winner named. The tests below pin the count at 155, the refusal count at
//! zero and the sealed order itself, so a declaration change that turns a resolved pair into a tie —
//! the shape nothing can decide — has to say so here. A root that skipped the check to get a node
//! running would be choosing which plane owns a request by accident of registration order, which is
//! the one thing the check exists to prevent.
//!
//! ## The shape that would pass both checks and still refuse every connection
//!
//! Two of the seven transports have a constructor that yields a serviceable transport and a
//! constructor that does not. `WsTransport::new()` and `GrpcTransport::new()` produce transports
//! whose listen, accept and dial all fail; only `over(lower)` is serviceable. A root that forgot the
//! composition would register, pass `check_composition` — because `composed_over()` returns `None`
//! and the check reads a declaration — and then refuse every connection. That is why the two are
//! built through `over` here and why the registered rows record what they were actually built over.
//!
//! ## One key, two compositions
//!
//! Seven keys register, and eight instances are built: `ws` is composed twice. It adds no
//! encryption of its own — it upgrades whatever stream the layer below gives up — so an in-band
//! upgrade arriving on `http` and a `wss://` dial that must stand on `tls` are two different
//! stacks, and the transport refuses a secure target over a cleartext lower layer rather than put a
//! plain upgrade on a wire the caller was told was encrypted. The registry seals by key and cannot
//! hold both, so the dial-side instance is the root's own handle and
//! [`ComposedTransports::dialer`] is where a destination's scheme picks between them.

use std::sync::Arc;

use busbar_contract::plane::PlaneMeta;
use busbar_contract::transport::TransportMeta;
use busbar_contract::{
    check_composition, CompositionError, Plugin, Registered, Transport, UpstreamAddress,
};
use busbar_kernel::registry::{seal_claims, ClaimConflict, PlaneClaim, Registry, ResolvedOverlap};
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
    /// WebSocket for ingress, built over HTTP — never over nothing. This is the instance an in-band
    /// upgrade arrives on, and the one registered under the `ws` key.
    pub ws: Arc<WsTransport>,
    /// WebSocket for a secure dial, built over TLS — the same key, composed a second way.
    ///
    /// Not registered: the registry seals by key and there is one `ws` entry. This instance is the
    /// root's own handle, reached through [`ComposedTransports::dialer`], because the composition a
    /// `wss://` destination needs is not the composition an upgrade arrives on and one instance
    /// cannot be both.
    pub ws_tls: Arc<WsTransport>,
    /// gRPC, built over HTTP — never over nothing.
    pub grpc: Arc<GrpcTransport>,
    /// The process's own standard streams.
    pub stdio: Arc<StdioTransport>,
}

impl ComposedTransports {
    /// The instance that dials a destination which named `key`, given where the dial lands.
    ///
    /// Every key but `ws` has one instance and this is a lookup. `ws` is the exception the registry
    /// cannot express: the registry seals by key, so exactly one `ws` may register, but a `ws://`
    /// upgrade arrives on `http` while a `wss://` dial is only honest over `tls` — the transport
    /// itself refuses a secure target over a cleartext lower layer rather than downgrade it. Those
    /// are two compositions of one key, and the choice between them is the destination's scheme,
    /// which is a fact of the dial rather than of the registry.
    #[must_use]
    pub fn dialer(&self, key: &str, address: &UpstreamAddress) -> Option<Arc<dyn Transport>> {
        let secure = address
            .authority()
            .is_some_and(|authority| authority.starts_with("wss://"));
        Some(match key {
            TcpTransport::KEY => Arc::clone(&self.tcp) as Arc<dyn Transport>,
            TlsTransport::KEY => Arc::clone(&self.tls) as Arc<dyn Transport>,
            HttpTransport::KEY => Arc::clone(&self.http) as Arc<dyn Transport>,
            SseTransport::KEY => Arc::clone(&self.sse) as Arc<dyn Transport>,
            <WsTransport as TransportMeta>::KEY if secure => {
                Arc::clone(&self.ws_tls) as Arc<dyn Transport>
            }
            <WsTransport as TransportMeta>::KEY => Arc::clone(&self.ws) as Arc<dyn Transport>,
            GrpcTransport::KEY => Arc::clone(&self.grpc) as Arc<dyn Transport>,
            StdioTransport::KEY => Arc::clone(&self.stdio) as Arc<dyn Transport>,
            _ => return None,
        })
    }
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
    // The same number the door refuses a body at. A WebSocket message is assembled from
    // continuation frames before anything above the transport sees it, so the ceiling has to be
    // stated at the handshake or it is not stated at all — and a node that refuses a body of a
    // given size over HTTP has no basis for holding a larger one over a socket it upgraded.
    let max_message_bytes = client_settings.request_body_max_bytes;
    let tcp = Arc::new(TcpTransport::new());
    let tls = Arc::new(TlsTransport::new());
    let http = Arc::new(HttpTransport::new(client_settings));
    let sse = Arc::new(SseTransport::new(Arc::clone(&http)));
    let ws = Arc::new(WsTransport::over_with_max_message_bytes(
        Arc::clone(&http) as Arc<dyn Transport>,
        max_message_bytes,
    ));
    // The dial-side composition of the same key. `ws` adds no encryption of its own, so a `wss://`
    // target is only honest when the layer below is the one that encrypts — the transport refuses
    // the dial otherwise rather than put a cleartext upgrade on a wire the caller was told was
    // secure. Every realtime upstream this deployment reaches is `wss`, so without this instance
    // the refusal is the whole voice plane's answer.
    let ws_tls = Arc::new(WsTransport::over_with_max_message_bytes(
        Arc::clone(&tls) as Arc<dyn Transport>,
        max_message_bytes,
    ));
    let grpc = Arc::new(GrpcTransport::over(Arc::clone(&http) as Arc<dyn Transport>));
    let stdio = Arc::new(StdioTransport::new());
    ComposedTransports {
        tcp,
        tls,
        http,
        sse,
        ws,
        ws_tls,
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
    use busbar_contract::grammar::{Claim, Selector};
    use busbar_kernel::registry::{check_claims, claims_overlap, ConflictReason, PluginKind};

    /// The sealed walk over the forty-eight declared claims, most specific first.
    ///
    /// Pinned as text rather than as indices so that a diff of it reads as a routing change. See
    /// the test that reads it for what a change to this array means.
    const SEALED_ORDER: &[&str] = &[
        "mcp ExactPath(\"/.well-known/oauth-protected-resource/mcp\")",
        "a2a ExactPath(\"/.well-known/oauth-protected-resource/a2a\")",
        "a2a ExactPath(\"/.well-known/agent-card.json\")",
        "a2a ExactPath(\"/a2a/extendedAgentCard\")",
        "a2a ExactPath(\"/a2a/message:stream\")",
        "a2a ExactPath(\"/a2a/message:send\")",
        "a2a ExactPath(\"/a2a/tasks\")",
        "a2a ExactPath(\"/a2a/push\")",
        "a2a ExactPath(\"/a2a/\")",
        "mcp ExactPath(\"/mcp\")",
        "mcp ExactPath(\"/mcp\")",
        "a2a ExactPath(\"/a2a\")",
        "a2a PathPattern([Lit(\"a2a\"), Lit(\"tasks\"), Var, Lit(\"pushNotificationConfigs\"), Var])",
        "a2a PathPattern([Lit(\"a2a\"), Lit(\"tasks\"), Var, Lit(\"pushNotificationConfigs\")])",
        "admin PathPattern([Lit(\"api\"), Lit(\"v1\"), Lit(\"admin\"), Tail])",
        "llm PathPattern([Lit(\"model\"), Var, Lit(\"invoke\")])",
        "a2a PathPattern([Lit(\"a2a\"), Lit(\"tasks\"), Var])",
        "a2a PathPattern([Lit(\"a2a\"), Lit(\"agents\"), Var])",
        "llm PathPattern([Lit(\"v1\"), Lit(\"models\"), Tail])",
        "llm PathPattern([Lit(\"v1beta\"), Lit(\"models\"), Tail])",
        "a2a PathPattern([Lit(\"lf.a2a.v1.A2AService\"), Var])",
        "llm HeaderPrefix(\"authorization\", \"AWS4-HMAC-SHA256\")",
        "llm HeaderPresent(\"anthropic-version\")",
        "llm HeaderPresent(\"anthropic-beta\")",
        "llm HeaderPresent(\"x-goog-api-key\")",
        "llm HeaderPresent(\"x-api-key\")",
        "voice PathSuffix(\"/v1/audio/transcriptions\")",
        "llm PathContains(\":streamGenerateContent\")",
        "llm PathSuffix(\"/v1/chat/completions\")",
        "llm PathContains(\":batchEmbedContents\")",
        "voice PathContains(\"BidiGenerateContent\")",
        "voice PathSuffix(\"/v1/audio/speech\")",
        "llm PathContains(\":generateContent\")",
        "llm PathSuffix(\"/v1/moderations\")",
        "llm PathSuffix(\"/v1/embeddings\")",
        "llm PathSuffix(\"/v1/responses\")",
        "llm PathContains(\":embedContent\")",
        "voice PathSuffix(\"/v1/realtime\")",
        "llm PathContains(\"/v1/messages\")",
        "llm PathContains(\"/v1/images/\")",
        "llm PathSuffix(\"/v2/rerank\")",
        "llm PathContains(\"/v1/audio/\")",
        "llm PathSuffix(\"/v2/embed\")",
        "llm PathContains(\"/converse\")",
        "llm PathSuffix(\"/v2/chat\")",
        "llm PathSuffix(\"/v1/chat\")",
        "llm PathContains(\":predict\")",
        "mcp StreamName(\"mcp\")",
    ];

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
    fn the_planes_declare_forty_eight_claims() {
        let claims = plane_claims();
        let count = |plane: &str| claims.iter().filter(|c| c.plane == plane).count();
        assert_eq!(count("llm"), 25);
        assert_eq!(count("mcp"), 4);
        assert_eq!(count("a2a"), 14);
        assert_eq!(count("voice"), 4);
        assert_eq!(count("admin"), 1);
        assert_eq!(claims.len(), 48);
    }

    /// The measured overlap, split the way the rule splits it. Both counts are pinned because both
    /// are what a reader checks the design's own account against.
    ///
    /// The two numbers come apart deliberately. The cross-family pairs are the conservative arm of
    /// the totality rule: a request has both a path and a header, so nothing proves a header claim
    /// and a path claim cannot coincide. The same-family pairs are the substantive half, and they
    /// are the half a tighter grammar moves: reading a suffix and a substring as the segment
    /// constraints they are, rather than as fragments that overlap anything, takes them from 119 to
    /// 65 without ever answering "disjoint" for a pair one arrival satisfies.
    #[test]
    fn one_hundred_and_fifty_five_cross_plane_pairs_overlap() {
        use busbar_kernel::grammar::family;

        let claims = plane_claims();
        let mut cross_family = 0usize;
        let mut same_family = 0usize;
        for (i, left) in claims.iter().enumerate() {
            for right in &claims[i + 1..] {
                if left.plane == right.plane || !claims_overlap(&left.claim, &right.claim) {
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
        assert_eq!(same_family, 65);
    }

    /// What the 65 path-family overlaps that remain actually ARE, one class at a time.
    ///
    /// A count alone cannot say whether an overlap is a real shape or a gap in the reasoning, and
    /// that distinction is the whole reason to tighten a grammar rather than to relax a check. So
    /// each remaining pair is put in the class that explains it, and the classes are exhaustive:
    ///
    /// * a pattern that ends in a TAIL, against a fragment — the tail can spell whatever the
    ///   fragment asks for, so a path satisfying both is written by filling the tail in;
    /// * a pattern with a VARIABLE segment, against a fragment that fits inside one segment — the
    ///   variable takes any single segment, and a fragment with no slash of its own is one;
    /// * two FRAGMENT forms — a suffix and a substring — which are satisfied together by writing a
    ///   path that ends the one way and contains the other.
    ///
    /// A pair that fits none of these would be the interesting one: a conservative answer with no
    /// account of itself. There is none, and the assertion is that there is none.
    #[test]
    fn every_remaining_path_overlap_is_a_shape_and_not_a_gap() {
        use busbar_contract::grammar::PathSeg;
        use busbar_kernel::grammar::family;

        let claims = plane_claims();
        let (mut tail, mut variable, mut fragments) = (0usize, 0usize, 0usize);
        let ends_in_tail = |s: &Selector| matches!(s, Selector::PathPattern(p) if matches!(p.last(), Some(PathSeg::Tail)));
        let has_variable = |s: &Selector| matches!(s, Selector::PathPattern(p) if p.iter().any(|g| matches!(g, PathSeg::Var)));
        let is_fragment =
            |s: &Selector| matches!(s, Selector::PathSuffix(_) | Selector::PathContains(_));

        for (i, left) in claims.iter().enumerate() {
            for right in &claims[i + 1..] {
                if left.plane == right.plane
                    || !claims_overlap(&left.claim, &right.claim)
                    || family(&left.claim.selector) != family(&right.claim.selector)
                {
                    continue;
                }
                let (a, b) = (&left.claim.selector, &right.claim.selector);
                if ends_in_tail(a) || ends_in_tail(b) {
                    tail += 1;
                } else if (has_variable(a) && is_fragment(b)) || (has_variable(b) && is_fragment(a))
                {
                    variable += 1;
                } else if is_fragment(a) && is_fragment(b) {
                    fragments += 1;
                } else {
                    panic!("{a:?} and {b:?} overlap for no reason this file can name");
                }
            }
        }
        assert_eq!(tail, 23);
        assert_eq!(variable, 24);
        assert_eq!(fragments, 18);
    }

    /// **The finding, answered.** Every one of those 155 overlaps is settled by the sealed order,
    /// and none of them is a refusal.
    ///
    /// The resolved count is pinned against the overlap count above, so the two cannot drift apart
    /// silently: a pair that stops being resolved has either stopped overlapping or become a tie,
    /// and each of those is a different thing to have to explain. The refusal list is pinned empty,
    /// which is the whole claim of this file — the declared set of five planes seals.
    #[test]
    fn every_cross_plane_overlap_is_resolved_by_precedence_and_none_refuses() {
        let claims = plane_claims();
        let sealed = seal_claims(&claims);

        assert_eq!(sealed.resolved.len(), 155);
        assert!(
            sealed.refused.is_empty(),
            "the declared claims do not seal: {:?}",
            sealed.refused
        );

        // The winner of a resolved pair is one of its two sides, and it is the side the order puts
        // first. Said as a property rather than as 209 assertions.
        let rank = |i: usize| {
            sealed
                .order
                .iter()
                .position(|c| *c == i)
                .expect("the order is a permutation")
        };
        for pair in &sealed.resolved {
            assert!(pair.winner == pair.left || pair.winner == pair.right);
            let loser = pair.left + pair.right - pair.winner;
            assert!(
                rank(pair.winner) < rank(loser),
                "the winner of {pair:?} is not the one the order tries first"
            );
        }
    }

    /// The sealed order of the forty-eight, written out.
    ///
    /// A snapshot, and deliberately a verbose one: the walk every arriving connection is matched
    /// against is the thing this file produces, and a change to it is a change to which plane
    /// answers which request. Each row is the plane and the selector, so a diff of this array reads
    /// as a routing change rather than as a permutation of opaque indices. A claim added, removed or
    /// respelled has to update it, on purpose, with the new order visible in the same diff.
    #[test]
    fn the_sealed_order_of_the_forty_eight_claims_is_pinned() {
        let claims = plane_claims();
        let sealed = seal_claims(&claims);
        let walk: Vec<String> = sealed
            .order
            .iter()
            .map(|i| format!("{} {:?}", claims[*i].plane, claims[*i].claim.selector))
            .collect();
        assert_eq!(walk, SEALED_ORDER, "the sealed claim order moved");
    }

    /// The refusal is still the point of the check. Two planes claiming one path at the same
    /// precedence is a composition nobody can resolve — the order has nothing to say about it — and
    /// the node says so at boot with both planes named rather than picking a winner at the first
    /// request.
    #[test]
    fn a_planted_equal_precedence_collision_refuses_at_boot() {
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
        let sealed = seal_claims(&[admin, impostor]);
        assert!(sealed.resolved.is_empty());
        assert_eq!(sealed.refused.len(), 1);
        assert_eq!(sealed.refused[0].reason, ConflictReason::EqualPrecedence);
    }

    /// And the other half of the same rule: the same two planes, one of them naming a tighter
    /// selector, is not a refusal at all. The exact path is more specific than the pattern that
    /// swallows it, so the order decides, the pair is recorded, and the boot goes on.
    #[test]
    fn a_planted_overlap_at_different_precedence_resolves_rather_than_refusing() {
        let admin = plane_claims()
            .into_iter()
            .find(|c| c.plane == "admin")
            .expect("the admin plane claims one path");
        let mut tighter = admin.claim;
        tighter.selector = Selector::ExactPath("/api/v1/admin/keys");
        let claims = vec![
            admin,
            PlaneClaim {
                plane: "impostor",
                claim: tighter,
            },
        ];
        let sealed = seal_claims(&claims);
        assert!(sealed.refused.is_empty());
        assert_eq!(sealed.resolved.len(), 1);
        assert_eq!(
            sealed.resolved[0].winner, 1,
            "the exact path is the tighter"
        );
    }

    /// Two claims whose scheme sets share nothing never overlap, however alike their selectors read:
    /// one request carries one credential, and no credential answers both sets. Planted on the one
    /// selector pair that is otherwise the hardest collision there is — the same exact path.
    #[test]
    fn claims_with_disjoint_scheme_sets_do_not_collide() {
        let one = PlaneClaim {
            plane: "one",
            claim: Claim {
                transport: "http",
                selector: Selector::ExactPath("/shared"),
                scheme: Some("one-key"),
                scheme_alternatives: &["bearer"],
                idempotency: None,
            },
        };
        let two = PlaneClaim {
            plane: "two",
            claim: Claim {
                transport: "http",
                selector: Selector::ExactPath("/shared"),
                scheme: Some("two-key"),
                scheme_alternatives: &["request-signature"],
                idempotency: None,
            },
        };
        assert!(one.claim.selector.overlaps(&two.claim.selector));
        assert!(!claims_overlap(&one.claim, &two.claim));
        let sealed = seal_claims(&[one.clone(), two.clone()]);
        assert!(sealed.refused.is_empty());
        assert!(sealed.resolved.is_empty());

        // And the moment one alternative is shared, the same pair is the collision it looks like.
        let mut shared = two;
        shared.claim.scheme_alternatives = &["bearer"];
        assert_eq!(seal_claims(&[one, shared]).refused.len(), 1);
    }

    /// Every claim is ordered, most specific first, and the order is a permutation of the claims —
    /// no claim is dropped from the walk and none is tried twice.
    #[test]
    fn the_precedence_order_is_a_permutation_of_every_claim() {
        let claims = plane_claims();
        let mut seen = seal_claims(&claims).order;
        seen.sort_unstable();
        assert_eq!(seen, (0..claims.len()).collect::<Vec<_>>());
    }

    /// And it is an order, not a shuffle: specificity never increases as the walk goes on, so the
    /// first claim that matches is the most specific one that could have.
    #[test]
    fn the_precedence_order_is_most_specific_first() {
        use busbar_kernel::grammar::specificity;

        let claims = plane_claims();
        let order = seal_claims(&claims).order;
        for pair in order.windows(2) {
            let earlier = specificity(&claims[pair[0]].claim.selector);
            let later = specificity(&claims[pair[1]].claim.selector);
            assert!(earlier >= later, "{earlier} came before {later}");
        }
    }

    /// The one-answer form of the same check, over the two claims the planted collision uses: a
    /// caller that only needs to know whether a set seals gets the first refusal, with both planes
    /// named in the message an operator reads.
    #[test]
    fn the_one_answer_form_names_both_planes() {
        let admin = plane_claims()
            .into_iter()
            .find(|c| c.plane == "admin")
            .expect("the admin plane claims one path");
        let impostor = PlaneClaim {
            plane: "impostor",
            claim: admin.claim,
        };
        let conflict =
            check_claims(&[admin, impostor]).expect_err("two planes cannot own one path");
        let planes = [conflict.left.plane, conflict.right.plane];
        assert!(planes.contains(&"admin"));
        assert!(planes.contains(&"impostor"));
        assert!(conflict.to_string().contains("equal precedence"));
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

    /// **The second finding, now closed on the declaration side and kept alive on the check side.**
    /// The other side of the pairing above: a claim on a transport no crate provides. The design
    /// lists thirteen transports and seven exist, and the voice plane used to claim its telephony
    /// dialect on one of the six that do not — which made the seal refuse, so no node built on this
    /// root could boot at all.
    ///
    /// The claim is gone (the plane's own claim table says why, and what has to land before it comes
    /// back). The CHECK is not: it is the only thing in the tree that reads a claim and a registered
    /// transport at the same time, and a check deleted along with the one claim that tripped it
    /// would leave the next such claim to be discovered as a request that matched nothing. So it is
    /// exercised here against a claim built for the purpose, on a transport deliberately not one of
    /// the seven.
    #[test]
    fn a_claim_on_a_transport_with_no_crate_refuses_at_boot() {
        let telephony = vec![PlaneClaim {
            plane: "voice",
            claim: Claim {
                transport: "twilio-media",
                selector: Selector::PrefixOneLevel("/twilio"),
                scheme: Some("voice-key"),
                scheme_alternatives: &["twilio-signature"],
                idempotency: None,
            },
        }];
        let refusal = check_claim_transports(&telephony, &registered_rows())
            .expect_err("`twilio-media` has no crate");
        assert!(matches!(
            refusal,
            BootRefusal::UnregisteredClaimTransport {
                plane: "voice",
                transport: "twilio-media",
            }
        ));
    }

    /// And the whole boot, end to end, now that nothing declares a claim the root cannot place: the
    /// seal answers. This is the assertion the previous shape of the test above could not make —
    /// the claims sealed, and the one transport gap was all that stood between the declared
    /// composition and a node that boots.
    #[test]
    fn the_seal_answers_now_that_every_claim_names_a_registered_transport() {
        let sealed = seal(ClientSettings::default()).expect("every claim names a live transport");
        assert_eq!(sealed.claims.len(), 48);
        assert_eq!(sealed.precedence.len(), 48);
    }

    /// The operator's request-body cap reaches every mounted plane's transport.
    ///
    /// A deployment that writes `limits.request_body_max_bytes: 1024` is asking for a node that
    /// buffers a kilobyte, and it has to mean it on every plane at once — the door's inbound limit
    /// and the transport's accumulation ceiling are the same number, so a plane served over a
    /// transport built from a `Default` would take a body the door refused. The seal composes ONE
    /// http instance from the settings it is handed and every http-carrying transport is over that
    /// instance, so the cap is checked at the instance and the claim walk is what says no plane sits
    /// anywhere else.
    #[test]
    fn the_operators_body_cap_reaches_every_mounted_planes_transport() {
        const CAP: usize = 1024;
        let limits = busbar_substrate::config::limits::LimitsResolved {
            request_body_max_bytes: CAP,
            ..busbar_substrate::config::limits::LimitsResolved::default()
        };
        let sealed = crate::root::registry::seal(crate::root::policy::client_settings(&limits))
            .expect("every claim names a live transport");

        assert_eq!(
            sealed.transports.http.max_body_bytes(),
            CAP,
            "the http transport must carry the operator's cap, not the crate's default"
        );

        for claim in &sealed.claims {
            let key = claim.claim.transport;
            let row = sealed
                .registered
                .iter()
                .find(|r| r.key == key)
                .unwrap_or_else(|| {
                    panic!(
                        "claim of plane `{}` names unregistered `{key}`",
                        claim.plane
                    )
                });
            let over_the_capped_instance =
                key == HttpTransport::KEY || row.composed_over == Some(HttpTransport::KEY);
            assert!(
                over_the_capped_instance || key == StdioTransport::KEY,
                "plane `{}` claims bytes on transport `{key}`, which neither is the capped http \
                 instance nor is composed over it",
                claim.plane
            );
        }

        // The other direction: a deployment that set nothing is where it always was.
        let unset = crate::root::registry::seal(crate::root::policy::client_settings(
            &busbar_substrate::config::limits::LimitsResolved::default(),
        ))
        .expect("every claim names a live transport");
        assert_eq!(
            unset.transports.http.max_body_bytes(),
            ClientSettings::default().request_body_max_bytes
        );
    }

    /// The voice plane's realtime upstreams are `wss`, and this node must be able to dial one.
    ///
    /// The ws transport refuses a secure target over a cleartext lower layer rather than put a
    /// plain upgrade on a wire the caller was told was encrypted. That refusal is right, and with a
    /// single `ws` instance composed over `http` it also means every `wss://` upstream this
    /// deployment has — OpenAI Realtime, Gemini Live — is refused at the dial. So the root composes
    /// the key twice: the ingress instance over `http`, which is what an in-band upgrade arrives
    /// on, and a dial-side instance over `tls`, which is the only composition under which `wss` is
    /// honest. A `ws://` destination still resolves to the ingress instance, so nothing that worked
    /// over cleartext quietly moved onto a different stack.
    #[test]
    fn a_secure_realtime_upstream_resolves_to_the_tls_composed_instance() {
        let sealed = seal(ClientSettings::default()).expect("every claim names a live transport");
        let ws_key = <WsTransport as TransportMeta>::KEY;

        let secure = sealed
            .transports
            .dialer(
                ws_key,
                &UpstreamAddress::socket("wss://api.openai.com/v1/realtime"),
            )
            .expect("`ws` is a registered key");
        assert_eq!(
            secure.composed_over(),
            Some(TlsTransport::KEY),
            "a wss upstream must dial through the tls-composed instance, or the ws transport \
             refuses it as a downgrade and the voice plane cannot reach a realtime provider at all"
        );

        let cleartext = sealed
            .transports
            .dialer(
                ws_key,
                &UpstreamAddress::socket("ws://127.0.0.1:8080/duplex"),
            )
            .expect("`ws` is a registered key");
        assert_eq!(
            cleartext.composed_over(),
            Some(HttpTransport::KEY),
            "a cleartext ws destination stays on the instance the in-band upgrade arrives on"
        );

        // The two are different objects, not one instance answering two ways.
        assert!(!Arc::ptr_eq(&secure, &cleartext));

        // And every other key is unchanged: one composition, one instance, whatever the address.
        for (key, over) in [
            (TcpTransport::KEY, None),
            (HttpTransport::KEY, None),
            (SseTransport::KEY, Some(HttpTransport::KEY)),
            (GrpcTransport::KEY, Some(HttpTransport::KEY)),
            (StdioTransport::KEY, None),
        ] {
            let dialer = sealed
                .transports
                .dialer(key, &UpstreamAddress::socket("wss://api.openai.com"))
                .unwrap_or_else(|| panic!("`{key}` is a registered key"));
            assert_eq!(dialer.composed_over(), over, "`{key}` resolved elsewhere");
        }

        assert!(
            sealed
                .transports
                .dialer(
                    "twilio-media",
                    &UpstreamAddress::socket("wss://example.invalid")
                )
                .is_none(),
            "a key the root never registered resolves to no instance"
        );
    }

    /// And the same check over every declared claim, voice included now that its telephony row is
    /// gone: nothing anywhere names a transport the root did not register.
    #[test]
    fn every_planes_claims_name_a_registered_transport() {
        let registered = registered_rows();
        let transports = compose_transports(ClientSettings::default());
        let registry = register_all(&transports).expect("nothing collides on a key");
        for claim in plane_claims().iter() {
            assert!(
                registered.iter().any(|r| r.key == claim.claim.transport),
                "claim of plane `{}` names transport `{}`, which is not registered",
                claim.plane,
                claim.claim.transport
            );
            // And the same question of the registry itself, which is what a request is served out
            // of: the rows are the root's own statement about what it built, and a name that
            // resolves in the statement but not in the registry would be a claim on a transport
            // nothing can answer with.
            assert!(
                registry
                    .resolve(PluginKind::Transport, claim.claim.transport)
                    .is_some(),
                "claim of plane `{}` names transport `{}`, which the registry does not resolve",
                claim.plane,
                claim.claim.transport
            );
        }
    }
}
