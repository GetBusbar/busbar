// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The A2A card fetch's redirect rule (IF §12.14 "the A2A card fetch and its redirects", round 21). In a
//! TGT_SIGHT session, and only there, a GET answered 301, 302, 303, 307 or 308 with a `Location` is followed when
//! the target has the upstream URL's origin and fewer than [`MAX_REDIRECTS`] were followed in that exchange. A
//! followed hop is a fresh GET the connector judges like a first dial (W1-C1A). A cross-origin target, or a
//! fourth redirect, is not followed: no byte goes to it, the 3xx reaches the plane unchanged, and core audits
//! [`AUDIT_ACTION`] with its own text.

/// Redirects followed per exchange (today's card_trust MAX_REDIRECTS).
pub const MAX_REDIRECTS: u32 = 3;

/// The audit action of a redirect core did not follow.
pub const AUDIT_ACTION: &str = "upstream_redirect_not_followed";

/// Why a redirect was not followed (the audit row's `reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotFollowedReason {
    CrossOrigin,
    TooMany,
}

impl NotFollowedReason {
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::CrossOrigin => "cross_origin",
            Self::TooMany => "too_many",
        }
    }
}

/// A redirect core did not follow: the audit row's fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotFollowed {
    pub upstream: Box<str>,
    /// The origin of the hop that sent the redirect.
    pub from: Box<str>,
    /// The origin of its target.
    pub to: Box<str>,
    pub reason: NotFollowedReason,
}

impl NotFollowed {
    /// Core's text, byte for byte (§12.14).
    #[must_use]
    pub fn text(&self) -> String {
        crate::cold::auth::sight::not_followed_text(&self.from, &self.to, &self.upstream)
    }
}

/// What core does with one answered hop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hop {
    /// Hand the answer to the plane unchanged (not a followable redirect, or not a TGT_SIGHT session).
    Deliver,
    /// Follow: GET this URL as a fresh hop.
    Follow(url::Url),
    /// Hand the 3xx to the plane unchanged and audit [`AUDIT_ACTION`].
    NotFollowed(NotFollowed),
}

/// One answered hop of an exchange (§12.14).
#[derive(Clone, Copy, Debug)]
pub struct Answered<'a> {
    /// The exchange runs in a TGT_SIGHT session.
    pub sight: bool,
    pub method: &'a str,
    pub status: u16,
    /// The answer's `Location`, if any.
    pub location: Option<&'a str>,
    /// The URL of the hop that answered.
    pub hop: &'a url::Url,
    /// Redirects already followed in this exchange.
    pub followed: u32,
}

/// Decides one hop for upstream `name` whose configured URL is `upstream_url`. The target is `Location` joined
/// against the hop's URL (RFC 3986 §5.2); a `Location` that does not join is delivered unfollowed.
#[must_use]
pub fn next_hop(answered: Answered<'_>, name: &str, upstream_url: &url::Url) -> Hop {
    let redirect = matches!(answered.status, 301 | 302 | 303 | 307 | 308);
    if !answered.sight || !redirect || !answered.method.eq_ignore_ascii_case("GET") {
        return Hop::Deliver;
    }
    let Some(target) = answered.location.and_then(|l| answered.hop.join(l).ok()) else {
        return Hop::Deliver;
    };
    let reason = if target.origin() != upstream_url.origin() {
        NotFollowedReason::CrossOrigin
    } else if answered.followed >= MAX_REDIRECTS {
        NotFollowedReason::TooMany
    } else {
        return Hop::Follow(target);
    };
    Hop::NotFollowed(NotFollowed {
        upstream: name.into(),
        from: answered.hop.origin().ascii_serialization().into(),
        to: target.origin().ascii_serialization().into(),
        reason,
    })
}
