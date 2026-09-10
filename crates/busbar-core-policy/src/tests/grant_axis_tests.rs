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

use crate::{Access, HookEnv, HookSeat, Need, Projectors, RoutingPolicy};
use std::sync::Arc;

/// A seat that answers one fixed declaration for every reference and can open nothing — the
/// manifest half of the meet, with no plugin tooling behind it.
struct Declares(Access);

impl HookSeat for Declares {
    fn declared_needs(&self, _plugin_ref: &str) -> Option<Access> {
        Some(self.0)
    }
    fn open(
        &self,
        _plugin_ref: &str,
        _settings_json: &str,
        _name: &str,
        _projectors: &Arc<Projectors>,
    ) -> Result<Arc<dyn RoutingPolicy>, String> {
        Err("a declaration-only seat opens nothing".into())
    }
}

fn env_declaring(needs: Access) -> HookEnv {
    HookEnv::new(
        Arc::new(Declares(needs)),
        Arc::new(|_| None),
        Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    )
}

/// The operator's hook, written under the config leaf's OWN keys — the deployed spelling, parsed
/// by the leaf, so the cell proves the key an operator writes lands on the axis the engine meets.
fn hook_granting(content: &str, caller: &str) -> crate::config::HookCfg {
    serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "module": "p",
        "prompt": content,
        "user": caller,
    }))
    .expect("a hook leaf under its own keys")
}

const LADDER: [(&str, Need); 3] = [("no", Need::No), ("ro", Need::Ro), ("rw", Need::Rw)];

/// The effective access is the MEET of grant and declaration on EACH axis, and the read and
/// rewrite admissions both derive from it: the full 3×3 over the argument axis and 2×2 over the
/// identity axis, with the config key and the declaration crossing at every rung.
#[test]
fn effective_access_is_the_meet_per_axis() {
    for (grant_word, grant) in LADDER {
        for (_, declared) in LADDER {
            let env = env_declaring(Access {
                argument: declared,
                identity: Need::No,
            });
            let hook = hook_granting(grant_word, "no");
            let access = crate::effective_access("h", &hook, &env);
            let expected = grant.min(declared);
            assert_eq!(
                access,
                Access {
                    argument: expected,
                    identity: Need::No
                },
                "argument axis: grant {grant:?} meet declared {declared:?}"
            );
            assert_eq!(
                crate::projection_grants("h", &hook, &env),
                (expected.wants_read(), false),
                "the read pair is the meet's read halves"
            );
            assert_eq!(
                crate::admits_rewrite("h", &hook, &env),
                grant == Need::Rw && declared == Need::Rw,
                "a rewrite chain admits only the top rung on BOTH sides"
            );
        }
    }
    for (grant_word, grant) in LADDER[..2].iter().copied() {
        for (_, declared) in LADDER[..2].iter().copied() {
            let env = env_declaring(Access {
                argument: Need::No,
                identity: declared,
            });
            let hook = hook_granting("no", grant_word);
            let access = crate::effective_access("h", &hook, &env);
            assert_eq!(
                access.identity,
                grant.min(declared),
                "identity axis: grant {grant:?} meet declared {declared:?}"
            );
            assert_eq!(
                crate::projection_grants("h", &hook, &env).1,
                access.identity.wants_read()
            );
        }
    }
}

/// A reference the seat cannot resolve falls back to the operator's grant alone — the pre-flight
/// safety net — on both axes.
#[test]
fn an_unresolvable_declaration_leaves_the_grant_as_written() {
    struct Nobody;
    impl HookSeat for Nobody {
        fn declared_needs(&self, _plugin_ref: &str) -> Option<Access> {
            None
        }
        fn open(
            &self,
            _plugin_ref: &str,
            _settings_json: &str,
            _name: &str,
            _projectors: &Arc<Projectors>,
        ) -> Result<Arc<dyn RoutingPolicy>, String> {
            Err("nobody".into())
        }
    }
    let env = HookEnv::new(
        Arc::new(Nobody),
        Arc::new(|_| None),
        Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    );
    assert_eq!(
        crate::effective_access("h", &hook_granting("rw", "ro"), &env),
        Access {
            argument: Need::Rw,
            identity: Need::Ro
        }
    );
}
