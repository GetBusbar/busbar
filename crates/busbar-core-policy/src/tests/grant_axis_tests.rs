// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GRANT AXIS — the `no ⊂ ro ⊂ rw` ladder is written over the hook subject's ARGUMENT payload
//! and the caller's IDENTITY, in the engine's own words. What one plane projects as its
//! conversation and another as its call arguments is one axis here; the operator's config key and
//! the manifest's `needs:` key are each a spelling of it that the seat adapter and the config leaf
//! own, never the engine.

/// The nouns a plane owns. A kind-neutral crate's TYPE and FIELD names may not carry one: the
/// operator's config key and the wire's member names keep theirs (they are deployed bytes), but the
/// engine's vocabulary for the axis they spell is the axis, not one plane's word for it.
const PLANE_NOUNS: [&str; 4] = ["prompt", "tool", "message", "model"];

/// The seat's public shape — every `pub` type, field and method in `src/seat.rs` — names no plane.
/// Red the day a plane's noun sits on the grant ladder's own struct; green once the ladder is
/// written over the subject's argument axis.
#[test]
fn seat_port_names_no_plane_noun() {
    let src = include_str!("../seat.rs");
    let offenders: Vec<String> = src
        .lines()
        .filter_map(|line| {
            let t = line.trim_start();
            // A `pub` item or field: `pub struct X`, `pub enum X`, `pub fn x(`, `pub x: T`,
            // `pub type X`. Doc comments and prose are the config/wire keys' business, not this.
            let rest = t.strip_prefix("pub ")?;
            let rest = rest.strip_prefix("(crate) ").unwrap_or(rest);
            let ident = rest
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .find(|w| {
                    !matches!(*w, "struct" | "enum" | "fn" | "type" | "trait" | "use" | "")
                })?;
            let lower = ident.to_ascii_lowercase();
            PLANE_NOUNS
                .iter()
                .any(|n| lower.contains(n))
                .then(|| format!("{ident}: {}", t.trim_end()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "seat.rs carries a plane's noun on a public name — the grant ladder is written over the \
         subject's argument axis, not one plane's projection of it:\n  {}",
        offenders.join("\n  ")
    );
}
