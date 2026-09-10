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
//! ## Why it names no plane, and no host
//!
//! Nothing here is about a protocol. The three values are the SUBSTRATE's ingress vocabulary — the
//! same three every driven arrival on this node carries, whichever dialect sent it — and the
//! credential a payload is resolved against is the mount's own reserved fact, published for every
//! plane alike. A plane that needs them names this seam; a plane that does not — the two mounted
//! before this one walk their own boot-resolved bindings and never touch the substrate's ingress —
//! never sees it, which is why neither of their legs changed to make room for it.
//!
//! The context is handed over SEALED, in the same opaque box the driven path carries, and the
//! deployment's half of it is MINTED BY THE BOOT rather than held here. The engine host is the one
//! value the root reaches the retiring engine through, and this file naming its type would be one
//! more spelling of that engine's surface in the root: the ratchet that measures how much of the
//! retiring crates the root still names counts distinct symbols, and the boot already spells the
//! one it needs where it mints the host. So the boot hands this seam a MINT — given the caller's
//! resolved governance context and token, box the deployment's own arrival — and this file holds
//! the mint, the resolution, and no type of the engine's at all. A leg reads the sealed context the
//! way the driven path's own readers do: by downcasting to the payload the substrate declares.

use std::sync::Arc;

use busbar_api::PlaneRequestCtx;
use busbar_substrate::ingress::arrival::ArrivalCtx;
use busbar_substrate::plane_host::EngineHost;

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
///
/// The answer is the substrate's SEALED arrival context — the same opaque box the catch-all would
/// have built for this request had the mount not answered first — carrying the engine host, the
/// governance context and the caller token. A leg reads it by downcasting to the payload the
/// substrate declares, which is exactly how the driven path's own readers read theirs.
#[async_trait::async_trait]
pub trait ArrivalSource: Send + Sync + 'static {
    /// The engine host, governance context and caller token this credential arrives with, sealed —
    /// or the deployment's own REFUSAL to admit this caller at all.
    ///
    /// ASYNC because the resolution is: this node's configured auth chain may dial an operator's own
    /// identity provider, and the driven path's middleware awaits it for exactly the same reason. A
    /// synchronous answer here could only be a SECOND, weaker resolution — which is what this seam
    /// used to hold, and what [`Admitted::Refused`] exists to retire.
    async fn arrival(&self, credential: Option<&str>) -> Admitted;
}

/// **WHAT THE DEPLOYMENT'S OWN IDENTITY DOOR SAID ABOUT ONE CALLER.**
///
/// Two arms, because the door has two answers and a seam that carried only the first is a door that
/// cannot refuse. That was this seam's shape until now: every credential — absent, malformed,
/// expired, revoked, or signed for a key this node never minted — resolved to a context with NO key
/// in it, and `key: None` is not "this caller was refused". It is the UNGOVERNED POSTURE, the open
/// front door a node with no governance configured serves on purpose, and every step downstream
/// reads it that way: the authenticate step attributes the anonymous actor, the verify step's scope
/// guard is `if let Some(key)` and so passes, and the door has no key to meter or bill against.
///
/// So a mounted deployment answered `200` to a caller the driven path answers `401` to, served it
/// out of scope, and recorded no usage for it. One absent arm, three holes.
pub enum Admitted {
    /// The chain ADMITTED this caller: the sealed arrival the plane's walk takes, carrying the
    /// resolved governance context — which is `key: None` only where the chain itself said `Open`.
    Arrival(ArrivalCtx),
    /// The chain REFUSED this caller. Carries nothing: which of `Denied` and `NoGrant` it was is the
    /// operator's diagnostic and never the client's, because a wire that told them apart would let a
    /// caller enumerate which credentials exist. The leg answers the vendor-native refusal for the
    /// dialect it named, from the same declaration the driven path's own 401 is shaped from.
    Refused,
}

/// How the boot boxes the deployment's own arrival around one caller's resolved half.
///
/// The governance context and the caller token are the CALLER's; everything else in the sealed
/// context — the engine host — is the DEPLOYMENT's and was minted by the boot. The boot writes this
/// closure at the one site it holds that host, so the host's type is spelled where the host is
/// made and nowhere else.
type Mint = dyn Fn(PlaneRequestCtx, Option<String>) -> ArrivalCtx + Send + Sync;

/// THE COMPOSITION ROOT'S ANSWER, sealed once and shared by every arrival on one mount.
///
/// The host is the DEPLOYMENT's and does not change for the life of the node; the governance context
/// is the CALLER's and cannot be known until one arrives. That split is the whole shape of this
/// type: one value baked in (inside the mint), one function supplied. A struct that baked both would
/// answer every request with the identity of whoever the boot happened to resolve first.
pub struct BootIngress {
    /// This deployment's [`Mint`]: the boot's own host, closed over where the boot minted it.
    mint: Box<Mint>,
    /// **THE DEPLOYMENT'S OWN IDENTITY DOOR**, asked per arrival.
    ///
    /// The host the boot minted for this generation, held for the ONE question only it can answer:
    /// who is this caller, by this node's configured chain. It is the same handle the [`Mint`]
    /// closes over — one host, asked two things — rather than a second binding that could be minted
    /// over a different generation than the arrivals it then seals.
    identity: Arc<dyn EngineHost>,
}

impl BootIngress {
    /// Seal one deployment's ingress source over its mint and its identity door.
    pub fn new(
        mint: impl Fn(PlaneRequestCtx, Option<String>) -> ArrivalCtx + Send + Sync + 'static,
        identity: Arc<dyn EngineHost>,
    ) -> Self {
        BootIngress {
            mint: Box::new(mint),
            identity,
        }
    }
}

impl std::fmt::Debug for BootIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BootIngress")
    }
}

#[async_trait::async_trait]
impl ArrivalSource for BootIngress {
    async fn arrival(&self, credential: Option<&str>) -> Admitted {
        // FLATTENED TO THE SECRET, because that is what the driven path carries: the catch-all
        // boxes the resolved caller token, not the header value it came in on. A passthrough that
        // forwarded the scheme word as part of the token would send `Bearer Bearer sk-…` upstream,
        // which is a credential no destination has ever accepted. The SAME flattening feeds the
        // chain below, because the chain is handed a candidate credential and not a header either.
        let presented = credential.and_then(presented_secret).map(str::to_string);
        // **THE DATA PLANE'S OWN RESOLUTION, NOT A SECOND ONE.** `identity_admit` is this node's
        // configured auth chain followed by the ONE verdict resolution the HTTP middleware runs —
        // the same two steps, over the same live governance state, reached through the plane ABI so
        // this file names no auth vocabulary and holds no credential rule of its own.
        //
        // NO EXPECTED AUDIENCE, spelled as the empty string the seam reads as absent. That is the
        // DATA-plane boundary: RFC 8707 audience binding is what an admission-bearing plane asks
        // for, and a dialect surface has no resource canonical URI to bind against. The driven
        // path's own middleware passes `expected_aud: None` here for the same reason.
        match self
            .identity
            .identity_admit(presented.clone(), String::new(), String::new())
            .await
        {
            // The chain admitted. The context is the chain's — `key: Some` for an identified
            // caller, `key: None` only where the chain itself answered `Open`, which is the
            // ungoverned posture and not a refusal quietly renamed.
            Ok((_principal, gov)) => Admitted::Arrival((self.mint)(gov, presented)),
            // Denied, or a role principal that earned no grant. Both are refusals on the driven
            // path and both are refusals here; the distinction stays off the wire.
            Err(_refusal) => Admitted::Refused,
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

/// **THE DEPLOYMENT'S OWN INGRESS SOURCE, sealed from what the boot holds.**
///
/// The composition step calls this and nothing else: the resolution below is the DATA PLANE'S own,
/// and writing it out at the call site would put this node's credential rule in the file that
/// composes routers rather than in the file that owns what a mounted arrival is made of.
///
/// **THE RESOLUTION IS THE DATA PLANE'S, AND IT IS NOW LITERALLY THE SAME ONE.** This used to be a
/// credential rule written HERE — `presented_secret` into `GovState::verify_token`, at the data
/// plane's audience boundary — described as "the same verification the driven path's chain reaches
/// for the same credential". It was not, and the gap was not academic:
///
/// - It had **no refusal**. Every credential it could not resolve — absent, malformed, expired,
///   revoked, minted by another node — came back `key: None`, which every step downstream reads as
///   the ungoverned open posture rather than as a denial. A mounted node answered `200` where the
///   driven path answers a vendor-native `401`.
/// - It had **no SigV4 arm**, so an inbound `AWS4-HMAC-SHA256` credential — the Bedrock SDK's own
///   model, and the only way that dialect authenticates — flattened to the leftovers after the
///   first space and resolved to nothing. Every mounted Bedrock-ingress request was therefore
///   anonymous: unbilled, unscoped and unbudgeted.
/// - It ran **only the keys arm**, so an operator's configured chain — their own identity provider,
///   their role bindings — decided nothing on a mounted surface.
///
/// All three were one defect: a second answer to who a caller is. So there is no resolution in this
/// file any more. The seam holds the deployment's own [`EngineHost`] and asks it, and the host's
/// `identity_admit` is the configured chain plus the ONE verdict resolution the HTTP middleware
/// itself runs. One answer, two paths to it.
///
/// The `mint` is the boot's: it closes over the engine host the boot minted for this generation and
/// boxes the deployment's arrival around the caller's resolved half. See [`Mint`]. The `identity`
/// is THAT SAME HOST, handed in rather than re-minted, so the generation that seals an arrival is
/// the generation that admitted it.
#[must_use]
pub fn boot_ingress(
    mint: impl Fn(PlaneRequestCtx, Option<String>) -> ArrivalCtx + Send + Sync + 'static,
    identity: Arc<dyn EngineHost>,
) -> BootIngress {
    BootIngress::new(mint, identity)
}

#[cfg(test)]
#[path = "tests/mount_ingress.rs"]
pub(crate) mod tests;
