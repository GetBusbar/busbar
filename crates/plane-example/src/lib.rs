// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REFERENCE PLANE PLUGIN — a plane that depends on `busbar-api` alone.
//!
//! This crate exists to answer one question with a build rather than an argument: *could this crate
//! be downloaded and dropped in?* Its `Cargo.toml` names `busbar-api` and nothing else. It cannot
//! reach a `busbar-core` internal, so it cannot require a widening, so there is nothing in it that a
//! third-party author could not have written against the published contract.
//!
//! What it demonstrates, one property per feature:
//!
//! - **A typed config section without core naming the type.** [`ExampleCfg`] is this crate's own
//!   struct. Core reads the `example:` section as opaque text and hands it over in
//!   [`PlaneCtx::config`]; the parse happens here. Core never names `ExampleCfg` and never could.
//! - **Routes core mounts but does not know.** [`ROUTES`] declares two paths. Core mounts exactly
//!   these — a plane serving a path it did not declare is not a state the seam can produce.
//! - **The admission bar declared, not implemented.** `/example/echo` declares
//!   [`PlaneAuth::Key`]; the auth chain that enforces it stays core's. That is what keeps "a
//!   protocol doesn't change breakers or failover or auditing" true by construction.
//! - **Capabilities granted, not imported.** The handler reads the clock through
//!   [`PlaneCtx::clock`] rather than importing a core module path.

use busbar_api::plane::{
    PlaneAuth, PlaneCtx, PlaneDecl, PlaneError, PlaneHandler, PlaneMethod, PlaneRequest,
    PlaneResponse, PlaneRoute,
};

/// THIS PLANE'S OWN CONFIG TYPE — the point being that it is *this crate's*, not core's.
///
/// Deliberately hand-parsed from the JSON text rather than serde-derived, to make the seam's
/// property unmissable: what crosses is TEXT, so a plane may parse it into any shape it likes, with
/// any validation it likes, and core is not a party to the decision. A real plane would derive
/// `Deserialize` and add `serde` to its own manifest — which it may, because its dependency list is
/// its own business.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExampleCfg {
    /// The greeting this plane answers `<base>/hello` with.
    pub greeting: String,
    /// The path prefix this plane mounts under — the stand-in for MCP's operator-set
    /// `canonical_uri`, and the reason `routes` is a function of the config text.
    pub base: String,
}

/// Pull `"key": "value"` out of the section text. Dependency-free on purpose — see `parse`.
fn extract(text: &str, key: &str) -> Option<String> {
    let start = text.find(key)?;
    let rest = &text[start + key.len()..];
    let after = &rest[rest.find(':')? + 1..];
    let tail = &after[after.find('"')? + 1..];
    Some(tail[..tail.find('"')?].to_string())
}

impl ExampleCfg {
    /// Parse the section text. Fail-closed: an unparseable section is a refusal, never a default,
    /// because a plane silently serving defaults over a config the operator got wrong is exactly
    /// the failure mode a typed section exists to prevent.
    pub fn parse(text: &str) -> Result<Self, PlaneError> {
        // Minimal, dependency-free extraction of `"greeting": "..."`.
        let key = "\"greeting\"";
        let start = text
            .find(key)
            .ok_or_else(|| PlaneError::new("invalid", "example: section has no `greeting`"))?;
        let rest = &text[start + key.len()..];
        let colon = rest
            .find(':')
            .ok_or_else(|| PlaneError::new("invalid", "example: `greeting` is not a mapping"))?;
        let after = &rest[colon + 1..];
        let open = after
            .find('"')
            .ok_or_else(|| PlaneError::new("invalid", "example: `greeting` is not a string"))?;
        let tail = &after[open + 1..];
        let close = tail
            .find('"')
            .ok_or_else(|| PlaneError::new("invalid", "example: `greeting` is unterminated"))?;
        // `base` is optional and defaults, because a plane may reasonably have both required and
        // defaulted keys; `greeting` above is the required one and its absence is a refusal.
        let base = extract(text, "\"base\"").unwrap_or_else(|| "/example".to_string());
        Ok(Self {
            greeting: tail[..close].to_string(),
            base,
        })
    }
}

/// The routes this plane serves. Both are unary (`streaming: false`), so this plane is loadable as
/// well as linkable — [`PlaneDecl::requires_linking`] is `false` for it, and that fact is derived
/// from this table rather than claimed beside it.
/// THE ROUTES, DERIVED FROM THE OPERATOR'S CONFIG. A function rather than a constant because a real
/// plane's paths may depend on the config (MCP's metadata document sits under the operator's
/// `canonical_uri`); this example exercises the same seam with a `base` key so the derivation is
/// covered by a test rather than only by MCP's eventual migration.
fn routes(config: &str) -> Vec<PlaneRoute> {
    let base = ExampleCfg::parse(config)
        .map(|c| c.base)
        .unwrap_or_else(|_| "/example".to_string());
    vec![
        // Unauthenticated on purpose, and this table is where that decision is reviewable. The
        // real instance of this shape is MCP's RFC 9728 metadata document, which a client must read
        // BEFORE it holds a credential. Core RAISES this to `Key` unless it has ratified it — see
        // the mount's ratchet.
        PlaneRoute {
            path: format!("{base}/hello"),
            method: PlaneMethod::Get,
            auth: PlaneAuth::None,
            streaming: false,
        },
        // The data-plane bar. Core runs the auth chain; this plane never sees a request that
        // failed it.
        PlaneRoute {
            path: format!("{base}/echo"),
            method: PlaneMethod::Post,
            auth: PlaneAuth::Key,
            streaming: false,
        },
    ]
}

/// The serving half.
struct ExamplePlane;

#[async_trait::async_trait]
impl PlaneHandler for ExamplePlane {
    async fn serve(&self, ctx: &PlaneCtx, req: &PlaneRequest) -> Result<PlaneResponse, PlaneError> {
        // The typed section, parsed HERE from the text core handed over.
        let cfg = ExampleCfg::parse(&ctx.config)?;
        match req.path.strip_prefix(&cfg.base) {
            Some("/hello") => {
                // The clock as a granted capability, not a module import.
                let at = ctx.clock.now_secs();
                Ok(PlaneResponse::json(
                    200,
                    format!("{{\"greeting\":\"{}\",\"at\":{at}}}", cfg.greeting),
                ))
            }
            Some("/echo") => Ok(PlaneResponse::json(200, req.body.clone())),
            // Core only dispatches paths this plane declared, so this arm is unreachable through
            // the seam. It is a refusal rather than a panic because "unreachable" is a claim about
            // core's behaviour, and a plugin should not stake its process on another crate's
            // invariant.
            _ => Err(PlaneError::new(
                "invalid",
                format!("example: no such route {}", req.path),
            )),
        }
    }
}

static HANDLER: ExamplePlane = ExamplePlane;

/// THE DECLARATION — what a plane crate exports and the composition root installs. The direct
/// analogue of `busbar_proto_anthropic::DECL` on the plane axis, and of the `&DECL` row that
/// `install_protocols` folds.
pub static DECL: PlaneDecl = PlaneDecl {
    key: "example",
    config_section: "example",
    scope_kinds: &["example"],
    subject_noun: "example endpoint",
    audit_kind: "example",
    wire_format_names: || &["example/json"],
    routes,
    verified_headers: &[],
    handler: Some(&HANDLER),
};

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
