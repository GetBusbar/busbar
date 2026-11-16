// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The outbound side of a `Target.upstream` exchange (IF §8.6 UpCarrier.outbound, §12.18 "upstream bindings",
//! §13 "the upstream head order"): which binding OUTBOUND_DEFAULT presents, which of the plane's facts reach that
//! binding (O_SCOPE only for a STYLE_SCOPE binding, O_CALLER_GRANT only for a STYLE_CALLER one), and the head the
//! binding's `outbound` sees: the plane's lines, then the transport's `defaults` the head lacks, never one of the
//! four handshake names the framer owns.

use busbar_plugin_abi::plane::OUTBOUND_DEFAULT;
use busbar_plugin_abi::types::Pair;

use crate::upstreams::{UpstreamAuth, UpstreamDef};

/// The protocol handshake lines a framer adds itself after `outbound` (§8.7 `emit`, a closed list). Core drops
/// them, ASCII case-insensitively, from the plane's head and from `defaults` before `outbound`, so no auth style
/// sees or signs them and the wire never carries two of one.
pub const FRAMER_OWNED: [&str; 4] = [
    "upgrade",
    "connection",
    "sec-websocket-key",
    "sec-websocket-version",
];

/// Whether `name` is one of [`FRAMER_OWNED`].
#[must_use]
pub fn framer_owned(name: &str) -> bool {
    FRAMER_OWNED.iter().any(|n| n.eq_ignore_ascii_case(name))
}

/// The binding OUTBOUND_DEFAULT presents for an exchange to `upstream`: its configured `upstreams.<name>.auth`
/// (resolved by K6 into an auth instance), or none. OUTBOUND_NONE presents none. Values above OUTBOUND_NONE are
/// refused by the plane adapter before this is asked (FAULT BadRecords); here they present none.
#[must_use]
pub fn outbound_binding(outbound: u32, upstream: Option<&UpstreamDef>) -> Option<&UpstreamAuth> {
    if outbound != OUTBOUND_DEFAULT {
        return None;
    }
    upstream.and_then(|u| u.auth.as_ref())
}

/// Whether an upstream is caller-mode (listed in a plane's `caller_upstreams`): only a binding whose style
/// declared STYLE_CALLER. An upstream with no `auth` is never caller-mode.
#[must_use]
pub fn caller_mode(upstream: &UpstreamDef) -> bool {
    upstream.auth.as_ref().is_some_and(|a| a.caller)
}

/// The plane's UP_SCOPE as O_SCOPE: sent only to a STYLE_SCOPE binding; otherwise dropped (CredKey.scope zero).
#[must_use]
pub fn scope_for<'a>(binding: &UpstreamAuth, up_scope: Option<&'a str>) -> Option<&'a str> {
    up_scope.filter(|_| binding.scoped)
}

/// The verified caller's grant as O_CALLER_GRANT: sent only to a STYLE_CALLER binding, and only when core holds
/// one.
#[must_use]
pub fn caller_grant_for<'a>(binding: &UpstreamAuth, grant: Option<&'a [u8]>) -> Option<&'a [u8]> {
    grant.filter(|_| binding.caller)
}

/// The head a binding's `outbound` sees (§13 round 22, round 23): the plane's PAIR* lines in order, then each
/// line of the carrying transport's `defaults(ROLE_CLIENT)` whose name the plane's head lacks (ASCII
/// case-insensitive), with every [`FRAMER_OWNED`] name dropped from both. A plane line that states its own value
/// keeps it (the default is not added).
#[must_use]
pub fn upstream_head<'a>(plane: &[Pair<'a>], defaults: &[Pair<'a>]) -> Vec<Pair<'a>> {
    let mut head: Vec<Pair<'a>> = plane
        .iter()
        .filter(|p| !framer_owned(p.name.get()))
        .copied()
        .collect();
    let stated = head.len();
    for line in defaults {
        let name = line.name.get();
        if framer_owned(name)
            || head[..stated]
                .iter()
                .any(|p| p.name.get().eq_ignore_ascii_case(name))
        {
            continue;
        }
        head.push(*line);
    }
    head
}

/// The authority core adds to the upstream head: host, then `:port` only when the URL states a port other than
/// its scheme's default.
#[must_use]
pub fn authority(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}
