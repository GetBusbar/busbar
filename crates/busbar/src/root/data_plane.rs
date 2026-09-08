// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATA-PLANE CHAIN: the node's own parts, composed once, in front of ONE plane's leg.
//!
//! ## The finding this file is the answer to
//!
//! Every plane that reached the loop grew its own composition. The administrative mount built a
//! kernel, a gauge, a canary and a key counter of its own; the A2A mount, landed beside it, built a
//! second set of exactly the same four. Two of those is two nodes: the gauge that bounds concurrency
//! counts half the traffic, the canary balances half the books, and each of the two looks healthy
//! because neither can see the other. The third plane would have made three.
//!
//! So the parts a plane's leg is walked on are composed HERE, once, generically — and what makes it
//! generic is that nothing in this file is allowed to know which plane it is serving. There is no
//! protocol name, no path, no operation and no media type: what a plane declares, it declares in its
//! own [`WireSurface`], and this file reads that declaration rather than a copy of it.
//!
//! ## The three things a data plane needs from the node, and nothing else
//!
//! 1. **Its addresses**, so a mount can tell a request this protocol owns from one it does not. Read
//!    off the surface's own dispatch table through the contract's own resolvers — so a protocol that
//!    gains an address gains it here for free, and this file never grows a route list.
//! 2. **Its audience**, so a credential minted for another resource is refused at its door. Joined
//!    from the deployment's declared identity and the surface's own mount, which is the RFC 8707
//!    canonical URI and is ONE reading: the audience a caller is told to ask for and the audience
//!    this node demands cannot drift apart if neither is written down twice.
//! 3. **The node's counters**, so a unit is judged against the whole node rather than against its
//!    own plane's corner of it.
//!
//! ## And the deployment's own front door
//!
//! [`data_chain`] is the fourth thing, and it is here for the same reason: the administrative door
//! is composed in [`crate::root::auth_bindings`] out of the operator's own token, and every data
//! plane needs the same service performed over `auth.chain:`. One builder, so two planes cannot
//! resolve one configuration two ways.
//!
//! ## What this file does NOT do
//!
//! It decides nothing about a request. It reads no body, names no unit, holds no money and takes no
//! step. A function here that made a judgement about an arrival would be the composition root doing
//! a plane's job — and it could not, because it does not know which plane it is.

use std::sync::atomic::{AtomicU64, Ordering};

use busbar_contract::transport::surface::{binding_at, check_surface, resolve_target, WireSurface};
use busbar_kernel::teller::{Kernel, Run, UnitCtx};
use busbar_unit_auth::AuthChain;

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE BOOT REFUSAL
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// A declared surface this node will not serve.
///
/// The contract's own check, run at composition rather than at the first request. Each of the four
/// shapes it refuses is a declaration that was a comment until something ran it: an operation
/// nothing addresses, a template outside the grammar, a binding nothing declares, two operations at
/// one address. Every one of them boots clean and serves traffic, and the symptom is a verb the
/// release notes list answering 404.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceRefused {
    /// What the contract's own check said, in the contract's own words.
    pub because: busbar_contract::transport::SurfaceError,
}

impl std::fmt::Display for SurfaceRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the composition root did not seal: a plane's declared surface does not check — {:?}",
            self.because
        )
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE CHAIN
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// THE NODE'S OWN PARTS, in front of one plane's leg.
///
/// Built once, at boot, and shared by every request that plane answers. The counters are the whole
/// reason it is shared: a gauge is a statement about how much this NODE is doing, and one per mount
/// would be one per plane's opinion of the node.
///
/// The surface is `&'static` because a declaration is a constant of the protocol rather than a value
/// a deployment picks. That is not a convenience — a surface that could be rebuilt per request is a
/// surface a request could change.
pub struct PlaneChain {
    /// What the plane declared: its addresses, its mounts, its media types.
    surface: &'static WireSurface,
    /// The node's concurrency gauge. ONE per node, held here and lent to every walk.
    gauge: busbar_kernel::slice::ConcurrencyGauge,
    /// The node's canary. ONE per node, for the same reason.
    canary: busbar_caps::Canary,
    /// The next unit key. Monotonic across every walk on this chain, so two arrivals are two units.
    next_key: AtomicU64,
}

impl std::fmt::Debug for PlaneChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlaneChain")
    }
}

impl PlaneChain {
    /// Compose the node's parts over one declared surface, or REFUSE to.
    ///
    /// # Errors
    ///
    /// The surface does not pass the contract's own [`check_surface`]. See [`SurfaceRefused`].
    pub fn over(surface: &'static WireSurface) -> Result<Self, SurfaceRefused> {
        check_surface(surface).map_err(|because| SurfaceRefused { because })?;
        Ok(PlaneChain {
            surface,
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            canary: busbar_caps::Canary::new(),
            next_key: AtomicU64::new(1),
        })
    }

    /// The surface this chain serves, for a caller that has to ask it something else.
    #[must_use]
    pub fn surface(&self) -> &'static WireSurface {
        self.surface
    }

    /// **Whether one request target and method is an address THIS PLANE DECLARED.**
    ///
    /// The question a mount has to ask before it takes a request off the surface that already
    /// answers it, and it is asked of the declaration rather than of a list here. Two ways an
    /// address can be declared and both are asked:
    ///
    /// - a **target**, which is a template and a method, resolved in the declarer's own order;
    /// - a **mount**, which is the address a document binding is served on and which no template
    ///   names — a chain that read only templates would hand the protocol's own front door away.
    ///
    /// There is no prefix arm and its absence is the point: a sibling path is somebody else's, and a
    /// `starts_with` would take it.
    #[must_use]
    pub fn claims_the_target(&self, target: &str, method: &str) -> bool {
        resolve_target(self.surface, path_of(target), method).is_some()
            || binding_at(self.surface, target).is_some()
    }

    /// The address this plane's document binding is mounted on, where it declares one.
    ///
    /// The FIRST declared mount, in the declarer's own order, for the same reason a target list is
    /// read in order: which of a protocol's addresses is its canonical one is the protocol's to say.
    #[must_use]
    pub fn mount_path(&self) -> Option<&'static str> {
        self.surface
            .bindings
            .iter()
            .find_map(|binding| binding.mounts.first().copied())
    }

    /// **THE AUDIENCE A CREDENTIAL PRESENTED HERE MUST NAME**, from the node's declared identity.
    ///
    /// The RFC 8707 canonical URI: the deployment's own `public_url` with this plane's declared
    /// mount as its path, and nothing else on it. Neither half is written down here — the identity
    /// is the operator's and the mount is the protocol's — so the string this node demands and the
    /// string its protected-resource metadata advertises are one derivation rather than two.
    ///
    /// `None` for a deployment that declared no identity, and `None` for a surface that mounts
    /// nothing. Both are honest absences and neither is a default: an audience derived from an
    /// absent identity is a resource indicator no client could be told to ask for, and a composition
    /// that needs one refuses rather than opening a door nothing can be checked against.
    ///
    /// Every spelling of one identity resolves to ONE audience. A trailing slash, a path, a query
    /// and a fragment are all legitimate things an operator writes and all name the same node; four
    /// different strings would be four different audiences, and the only symptom is a caller who
    /// cannot get in.
    #[must_use]
    pub fn audience(&self, public_url: &str) -> Option<String> {
        let origin = declared_origin(public_url)?;
        let mount = self.mount_path()?;
        Some(format!("{origin}{mount}"))
    }

    /// **Compose the node's parts for ONE walk, and hand them to the caller.**
    ///
    /// The caller supplies the leg; this supplies everything a leg may not make for itself. The
    /// hold cell, the lease cell and the meter are per-unit and are made here; the gauge and the
    /// canary are the node's and are lent from here. A leg that made its own would be balancing its
    /// own books beside the node's.
    ///
    /// A closure rather than a returned value because [`Run`] BORROWS the four cells it names, and a
    /// function cannot hand back a value that borrows from the frame it returned from. That is the
    /// same reason the arrival is composed in a closure one axis away.
    pub fn run<T>(&self, kernel: &Kernel, f: impl FnOnce(&UnitCtx, Run<'_>) -> T) -> T {
        let key = busbar_caps::UnitKey::new(self.next_key.fetch_add(1, Ordering::Relaxed));
        let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
            &kernel.admit_token(),
            busbar_caps::PrincipalId::new(""),
            0,
        ));
        let leases = busbar_kernel::slice::LeaseCell::new();
        let meter = busbar_kernel::teller::AccrualMeter::new();
        let ctx = UnitCtx {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            // A DATA listener, and a unit of an ordinary plane. Both are answered with what is true
            // of this composition rather than derived: a node that answered otherwise would be
            // running ordinary traffic as kernel verbs, through the operator's own door, and
            // arriving there silently.
            admin_listener: false,
            kernel_verb_only: false,
        };
        f(
            &ctx,
            Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &self.gauge,
                canary: &self.canary,
                meter: &meter,
            },
        )
    }
}

/// One request target with its query and fragment cut off, which is the part that is a PATH.
///
/// Neither is part of the address, and a resolver that read them would answer 404 to a well-formed
/// request that carried a cache-buster. The contract's own `binding_at` cuts the same way and for
/// the same reason; this is that cut, applied on the template side as well, so the two halves of one
/// claim question cannot disagree about where the path ends.
fn path_of(target: &str) -> &str {
    target.split(['?', '#']).next().unwrap_or(target)
}

/// THE NODE'S DECLARED IDENTITY, reduced to the origin an audience is built on.
///
/// Scheme and authority, and deliberately nothing after them. An operator writes this deployment's
/// public address in whichever of several legitimate spellings comes to hand — with a trailing
/// slash, with a path, with a query — and every one of them names the SAME node. Keeping any of the
/// tail would make those spellings different audiences, and the symptom of two audiences for one
/// node is a caller holding a token this node refuses for a reason nothing reports.
///
/// `None` for anything that is not an absolute address. A relative identity has no origin to build
/// on, and inventing one would be this file deciding where a deployment lives.
fn declared_origin(public_url: &str) -> Option<&str> {
    let declared = path_of(public_url.trim());
    let (scheme, rest) = declared.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    Some(&declared[..scheme.len() + "://".len() + authority.len()])
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE DEPLOYMENT'S OWN FRONT DOOR
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// ONE POSITION of the configured `auth.chain:`, as the composition reads it.
///
/// The provider NAME and the MODULE it referenced, which is exactly the pair the resolved
/// configuration carries. The name is the identity that role bindings bind and that scope ceilings
/// key off, so two named providers sharing one module stay two positions here as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPosition<'c> {
    /// The `identity-providers:` key this chain position referenced.
    pub provider: &'c str,
    /// The module that key resolved to.
    pub module: &'c str,
}

/// A configured authentication position this composition has no module for.
///
/// A REFUSAL and never a silent drop. The alternative is the shape this type exists against: a node
/// whose operator wrote down an authentication requirement, serving a door with one fewer lock than
/// they wrote, where every request reads as ADMITTED rather than as unchecked — and nothing on any
/// surface says which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedProvider {
    /// The `identity-providers:` key that could not be resolved.
    pub provider: String,
    /// The module it named.
    pub module: String,
}

impl std::fmt::Display for UnresolvedProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the composition root did not seal: `auth.chain:` names the provider `{}`, whose \
             module `{}` this node's data-plane composition cannot resolve — it is loaded by the \
             engine's own plugin pipeline, which the composed leg does not reach",
            self.provider, self.module
        )
    }
}

/// **THE DATA PLANE'S FRONT DOOR, from the deployment's own `auth.chain:`.**
///
/// One builder, so no two planes resolve one configuration two ways — the reason the administrative
/// door is likewise built exactly once, in [`crate::root::auth_bindings::admin_chain`].
///
/// ## What resolves, and what refuses
///
/// The built-in signed-key arm resolves. It is not a boxed module and cannot be: the module contract
/// hands back a principal, and the arm resolves a whole enforced key — so it rides the chain as a
/// FLAG, and that flag is the only thing keeping the door shut for a `chain: [keys]` deployment.
/// Getting it wrong is silent in the worst direction, which is why it is asked of the configuration
/// by name rather than inferred from the module list being empty.
///
/// Every other position REFUSES, naming the provider and the module. A plugin-backed identity
/// provider is opened by the engine's own signed-plugin loader against its own registry, and the
/// composed leg reaches neither; a chain that dropped it would be worse than one that refused,
/// because the deployment would go on looking authenticated.
///
/// A configuration that names NO position resolves to the open front door. That is a posture an
/// operator wrote down, not a source this composition is missing.
///
/// # Errors
///
/// A configured position names a module this composition cannot resolve. See [`UnresolvedProvider`].
pub fn data_chain(positions: &[ChainPosition<'_>]) -> Result<AuthChain, UnresolvedProvider> {
    // The boxed positions, resolved one at a time. It is EMPTY on every configuration this
    // composition can serve today, and that is a statement about what is resolvable here rather
    // than a posture: the one arm a data plane's door can be built from at this seam is the
    // built-in signed-key verifier, which is a flag and not a module, and every other position
    // refuses on the line below rather than being quietly left out of this list.
    let modules: Vec<busbar_unit_auth::chain::ChainEntry> = Vec::new();
    let mut keys_in_chain = false;
    for position in positions {
        if position.module == busbar_unit_auth::chain::KEYS_MODULE {
            keys_in_chain = true;
            continue;
        }
        return Err(UnresolvedProvider {
            provider: position.provider.to_string(),
            module: position.module.to_string(),
        });
    }
    Ok(AuthChain::new(modules, keys_in_chain))
}

#[cfg(test)]
#[path = "tests/data_plane.rs"]
mod tests;
