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
//! **153 of the cross-plane pairs overlap** — 90 across selector families and 63 within the path
//! family. Both numbers follow from the overlap rule as the design writes it, and neither is a
//! rounding of the other.
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
//! planes at once — took it from 65 to 63. Of the 63, 23 involve a pattern ending in a tail (which
//! can supply whatever the fragment asks for), 24 are a fragment landing inside a pattern's
//! variable segment, and 16 are two fragment forms that can be satisfied at once by writing a path
//! with both. Every one of them is a real shape, not a gap in the reasoning.
//!
//! All 153 are settled by the sealed order, and none of them is a refusal. That is not the check
//! being softened: every one of the 153 is a pair whose two claims sit at different precedence, so
//! the order already says which plane takes bytes both describe, and the pair is recorded in
//! `resolved` with its winner named. The tests below pin the count at 153, the refusal count at
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

use super::dialects;
use busbar_contract::plane::PlaneMeta;
use busbar_contract::transport::TransportMeta;
use busbar_contract::{
    check_composition, CompositionError, Plugin, Registered, Transport, UpstreamAddress,
};
use busbar_kernel::registry::{seal_claims, ClaimConflict, PlaneClaim, Registry, ResolvedOverlap};
use busbar_plane_a2a::A2aPlane;
use busbar_plane_admin::AdminPlane;
use busbar_plane_llm::registry::DialectRegistry;
use busbar_plane_llm::LlmPlane;
use busbar_plane_mcp::McpPlane;
#[cfg(feature = "plane-voice")]
use busbar_plane_voice::VoicePlane;
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
    #[cfg(feature = "plane-voice")]
    pub ws: Arc<WsTransport>,
    /// WebSocket for a secure dial, built over TLS — the same key, composed a second way.
    ///
    /// Not registered: the registry seals by key and there is one `ws` entry. This instance is the
    /// root's own handle, reached through [`ComposedTransports::dialer`], because the composition a
    /// `wss://` destination needs is not the composition an upgrade arrives on and one instance
    /// cannot be both.
    #[cfg(feature = "plane-voice")]
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
        #[cfg(not(feature = "plane-voice"))]
        let _ = address;
        #[cfg(feature = "plane-voice")]
        let secure = address
            .authority()
            .is_some_and(|authority| authority.starts_with("wss://"));
        Some(match key {
            TcpTransport::KEY => Arc::clone(&self.tcp) as Arc<dyn Transport>,
            TlsTransport::KEY => Arc::clone(&self.tls) as Arc<dyn Transport>,
            HttpTransport::KEY => Arc::clone(&self.http) as Arc<dyn Transport>,
            SseTransport::KEY => Arc::clone(&self.sse) as Arc<dyn Transport>,
            #[cfg(feature = "plane-voice")]
            <WsTransport as TransportMeta>::KEY if secure => {
                Arc::clone(&self.ws_tls) as Arc<dyn Transport>
            }
            #[cfg(feature = "plane-voice")]
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

/// The `llm` plane, with every dialect this build registered sealed into it.
///
/// SEALING IS THE WHOLE OF REGISTRATION. The plane holds the table as data — a location row and a
/// ladder per dialect — and never a value of a dialect's type, because holding the value would be
/// the plane naming the dialect. The table is [`dialects::LLM`], and this function does not know
/// what is in it.
#[must_use]
fn llm_plane() -> LlmPlane {
    LlmPlane::EMPTY.with_dialects(DialectRegistry::sealed(dialects::LLM))
}

/// Every plane's claims, paired with the key that names the plane.
///
/// This is the pairing nothing else in the tree can do: `<LlmPlane as PlaneMeta>::CLAIMS` needs the
/// type and `"llm"` needs the string, and only a composition root holds both.
///
/// A PLANE'S SERVED SURFACE IS ITS OWN CLAIMS UNIONED WITH ITS REGISTERED DIALECTS'. The claims a
/// dialect declares are claims ON ITS PLANE — the rung numbers are the plane's scale and the
/// transport, scheme and alternative set are the plane's builder's — so they carry the plane's key
/// here exactly as the plane's own do. A boot that unioned only the plane's half would seal a
/// surface that answers on fewer paths than the binary can decode, and the request that arrived on
/// the difference would be refused as claimed by nothing while the dialect that speaks it sat
/// registered in the same process.
#[must_use]
pub fn plane_claims() -> Vec<PlaneClaim> {
    fn claims_of<P: PlaneMeta>() -> impl Iterator<Item = PlaneClaim> {
        P::CLAIMS.iter().map(|claim| PlaneClaim {
            plane: P::KEY,
            claim: *claim,
        })
    }

    /// The LLM plane's claims — its own and its registered dialects' — IN LADDER ORDER.
    ///
    /// Blind to the dialect: it asks the sealed plane for its merged walk, which interleaves every
    /// registered rung at the number it declared, and reads the plane's `KEY`. Adding the next
    /// dialect adds a row to [`dialects`] and changes nothing here.
    ///
    /// WHY THE WALK AND NOT "THE PLANE'S CLAIMS, THEN THE DIALECTS'". Declaration order is what
    /// breaks a precedence tie, and a plane's declaration order is its LADDER — the order its
    /// constant read before any rung was carved out. The first two dialects declared path suffixes
    /// of distinct lengths, so no tie could arise and appending them after the plane's own claims
    /// sealed the same order the constant had. The third declares HEADER rungs, and a header-present
    /// claim ties every other header-present claim on specificity: appended, a rung-2 header rung
    /// sealed BEHIND the plane's own rung-3 header rung, and a request carrying both headers would
    /// have gone to the wrong vendor. The merged walk is the one order the plane itself decides
    /// requests by, so it is the one order the seal may carry.
    fn llm_claims() -> Vec<PlaneClaim> {
        let mut out = Vec::new();
        llm_plane().walk_ladder(|rung| {
            out.push(PlaneClaim {
                plane: <LlmPlane as PlaneMeta>::KEY,
                claim: rung.claim,
            });
        });
        out
    }

    // Declaration order is what breaks precedence ties, so the planes are appended in the order the
    // table has always read: llm, mcp, a2a, voice, admin. Voice's row is present exactly when its
    // crate edge is — a claim from a plane this build does not register would name a plane, and a
    // transport, that no request could ever reach.
    let mut claims: Vec<PlaneClaim> = llm_claims()
        .into_iter()
        .chain(claims_of::<McpPlane>())
        .chain(claims_of::<A2aPlane>())
        .collect();
    #[cfg(feature = "plane-voice")]
    claims.extend(claims_of::<VoicePlane>());
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
    // The dial-side composition of the same key. `ws` adds no encryption of its own, so a `wss://`
    // target is only honest when the layer below is the one that encrypts — the transport refuses
    // the dial otherwise rather than put a cleartext upgrade on a wire the caller was told was
    // secure. Every realtime upstream this deployment reaches is `wss`, so without this instance
    // the refusal is the whole voice plane's answer.
    #[cfg(feature = "plane-voice")]
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
        #[cfg(feature = "plane-voice")]
        ws,
        #[cfg(feature = "plane-voice")]
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
        Arc::new(llm_plane()) as Arc<dyn Plugin>,
        Arc::new(McpPlane::EMPTY) as Arc<dyn Plugin>,
        Arc::new(A2aPlane::EMPTY) as Arc<dyn Plugin>,
    ];
    // The voice plane goes in with its own crate edge and leaves with it. It is the only plane that
    // claims bytes on `ws`, so registering it in a build with no WS transport would be the root
    // mounting a plane whose claims name a layer this binary does not carry.
    #[cfg(feature = "plane-voice")]
    planes.push(Arc::new(VoicePlane::EMPTY) as Arc<dyn Plugin>);
    planes.push(Arc::new(AdminPlane::new()) as Arc<dyn Plugin>);
    for plane in planes {
        registry.register(plane).map_err(BootRefusal::Registry)?;
    }

    Ok(registry)
}

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
