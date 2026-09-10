// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A MOUNTED LEG IS HANDED AT MOUNT TIME so it can build the arrival its plane's walk needs.
//!
//! ## The hole this fills, and why it is not a global
//!
//! A plane whose walk is driven from the substrate's own ingress reads three things off a request
//! that the composition root resolved BEFORE the request reached any plane: the engine host, the
//! governance context the presented credential resolved to, and the caller's own bearer for
//! passthrough forwarding. On the driven path all three arrive boxed in the substrate's opaque
//! `busbar_substrate::ingress::arrival::ArrivalCtx`, put there by the catch-all that resolved them.
//!
//! **A MOUNT SITS IN FRONT OF THAT CATCH-ALL.** It wraps the router a deployment already composed
//! and answers the claimed addresses itself, so the context that would have carried those three
//! values is never built — the request never reaches the code that builds one. Something has to
//! supply them, and there were only three places it could come from:
//!
//! - **A global** — a static the boot writes and a leg reads. Refused: two deployments in one
//!   process (which is what every mount cell in this tree composes) would share one, and the second
//!   one composed would silently answer for the first. A process with two nodes in it is not an
//!   exotic shape; it is the shape that catches exactly this.
//! - **A per-request reach back into the mounted router**, asking the surface underneath what the
//!   request means. The surface underneath is the thing a mount exists to go in front of.
//! - **A VALUE THE LEG IS GIVEN WHEN IT IS BUILT.** Which is this. The composition root holds all
//!   three sources at the instant it composes a mount, so it seals one of these and hands it over,
//!   and the leg asks it per arrival.
//!
//! ## Why it names no plane
//!
//! Nothing here is about a protocol. The three values are the SUBSTRATE's ingress vocabulary — the
//! same three every driven arrival on this node carries, whichever dialect sent it — and the
//! credential a payload is resolved against is the mount's own reserved fact, published for every
//! plane alike. A plane that needs them names this seam; a plane that does not — the two mounted
//! before this one walk their own boot-resolved bindings and never touch the substrate's ingress —
//! never sees it, which is why neither of their legs changed to make room for it.

use std::sync::Arc;

use busbar_substrate::ingress::arrival::ArrivalPayload;

/// THE ONE QUESTION A MOUNTED LEG ASKS ITS BOOT, per arrival.
///
/// One method rather than three accessors, deliberately: the three values are one answer about one
/// caller. A leg that read a host from one place and a governance context from another could hold a
/// host minted over one deployment beside a key resolved on a second, and nothing about the two
/// reads would say so.
///
/// The argument is the credential AS PRESENTED — the whole header value, scheme word included,
/// exactly as the mount published it under the kernel's reserved key. Deciding what a scheme means
/// belongs to the side that resolves it, which is the same rule the mount's own fact publication
/// follows when it declines to split one.
pub trait ArrivalSource: Send + Sync + 'static {
    /// The engine host, governance context and caller token this credential arrives with.
    fn payload(&self, credential: Option<&str>) -> ArrivalPayload;
}

/// THE COMPOSITION ROOT'S ANSWER, sealed once and shared by every arrival on one mount.
///
/// The host is the DEPLOYMENT's and does not change for the life of the node; the governance context
/// is the CALLER's and cannot be known until one arrives. That split is the whole shape of this
/// type: one value baked in, one function supplied. A struct that baked both would answer every
/// request with the identity of whoever the boot happened to resolve first.
pub struct BootIngress {
    host: Arc<dyn busbar_substrate::plane_host::EngineHost>,
    /// How this deployment turns a presented credential into a governance context. Boxed rather than
    /// a generic parameter because a leg holds this as `dyn ArrivalSource`, and a parameter here
    /// would have to travel through every type between the two for no gain.
    resolve: Box<dyn Fn(Option<&str>) -> busbar_api::PlaneRequestCtx + Send + Sync>,
}

impl BootIngress {
    /// Seal one deployment's ingress source.
    pub fn new(
        host: Arc<dyn busbar_substrate::plane_host::EngineHost>,
        resolve: impl Fn(Option<&str>) -> busbar_api::PlaneRequestCtx + Send + Sync + 'static,
    ) -> Self {
        BootIngress {
            host,
            resolve: Box::new(resolve),
        }
    }
}

impl std::fmt::Debug for BootIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BootIngress")
    }
}

impl ArrivalSource for BootIngress {
    fn payload(&self, credential: Option<&str>) -> ArrivalPayload {
        ArrivalPayload {
            host: Arc::clone(&self.host),
            gov: (self.resolve)(credential),
            // FLATTENED TO THE SECRET, because that is what the driven path carries: the catch-all
            // boxes the resolved caller token, not the header value it came in on. A passthrough
            // that forwarded the scheme word as part of the token would send `Bearer Bearer sk-…`
            // upstream, which is a credential no destination has ever accepted.
            caller_token: credential.and_then(presented_secret).map(str::to_string),
        }
    }
}

/// The secret out of one credential as presented.
///
/// A credential is `<scheme> <secret>` or a bare secret, and both arrive on real deployments — the
/// second is what a caller sends to a surface whose vendor SDK writes the key into a header of its
/// own. Split on the first space and nowhere else: WHICH schemes a plane will accept is the
/// authentication chain's answer and is not re-decided here, so this drops whatever word came first
/// rather than matching a list of names it would then have to keep in step with that chain.
///
/// An empty secret is `None` rather than `Some("")`, for the reason the mount's own credential fact
/// is absent rather than blank: a caller that presented nothing and a caller that presented an empty
/// string are two different statements, and only one of them is a caller.
#[must_use]
pub fn presented_secret(credential: &str) -> Option<&str> {
    let presented = credential.trim_start();
    let secret = match presented.split_once(' ') {
        // A scheme word and a secret. What is left after the word is the secret, even where what is
        // left is nothing — a credential that named a scheme and carried no secret presented no
        // secret, and answering the scheme word itself would forward the string `Bearer` upstream as
        // if it were a key.
        Some((_, rest)) => rest.trim(),
        // No space at all: the whole value is the secret, which is the shape a vendor SDK writing
        // its key into a header of its own sends.
        None => presented.trim_end(),
    };
    (!secret.is_empty()).then_some(secret)
}

#[cfg(test)]
#[path = "tests/mount_ingress.rs"]
mod tests;
