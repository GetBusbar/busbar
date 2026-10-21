// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ERROR-SHAPING BOUNDARY: one resolved ingress, one native envelope.
//!
//! Everything that must answer a request from its PATH ALONE — the oversized-body `413` reshape,
//! the `404` fallback, the `405` wrong-method reply, the auth-time `401` — comes through here, so
//! there is exactly one place that turns [`crate::plane::PlaneDispatch::ingress_of`]'s answer into
//! bytes. The alternative is what shipped: several sites each deciding for themselves, from a
//! classifier that could not see the mount table, and quietly disagreeing about what a given mounted
//! plane's path is.
//!
//! It is the SHAPE that is decided here, never the outcome. Status and message arrive from the
//! caller, because the caller is the only one that knows why it is refusing.

use axum::http::StatusCode;
use axum::response::Response;

use crate::plane::Ingress;

/// THE DIALECTS A PATH NAMES BY ITS SHAPE ALONE, as the linked declarations state them: the label
/// an authentication refusal's `response` tap is told (`ingress_protocol`). v1.5.5 labelled that
/// tap off the path alone (`crates/busbar/src/auth/mod.rs:1167` at v1.5.5, `proto_for_path(path)`),
/// whatever the verb. The table is not the kernel's: each dialect states its own path claim
/// (`busbar_contract::protocol::ProtocolDecl::residual_claims`) and which dialect answers a path no
/// claim takes (`ProtocolDecl::residual_default`), and the composition root folds the linked
/// declarations into this value and installs it ([`install_path_dialects`]). The kernel names none.
#[derive(Clone)]
pub struct PathDialects {
    /// The dialect the declarations claim `path` for by its shape alone, the tightest claim kept
    /// and a tie broken by the linked order; `None` when no declaration claims it.
    pub claimed: std::sync::Arc<dyn Fn(&str) -> Option<&'static str> + Send + Sync>,
    /// The dialect a path no declaration claims is labelled in, when one declares itself the
    /// residual default.
    pub residual: Option<&'static str>,
}

/// The installed path dialects ([`install_path_dialects`]).
static PATH_DIALECTS: std::sync::OnceLock<PathDialects> = std::sync::OnceLock::new();

/// Install the linked declarations' path dialects, once, from the composition root. A second
/// install is ignored: there is one composition root.
pub fn install_path_dialects(dialects: PathDialects) {
    let _ = PATH_DIALECTS.set(dialects);
}

/// The installed path dialects, or `None` in a build whose root installed none.
pub fn path_dialects() -> Option<&'static PathDialects> {
    PATH_DIALECTS.get()
}

/// THE DIALECT A REFUSAL AT `path` IS LABELLED IN, read off the path alone and never off the verb or
/// a door route: a path mounted by a plane is that plane's first wire format; any other path is
/// the dialect the declarations claim it for; failing either, the residual default. `None` when
/// none of them names one.
pub fn labelled_dialect(
    ingress: Ingress,
    path: &str,
    by_path: Option<&PathDialects>,
) -> Option<&'static str> {
    let _ = (ingress, path, by_path);
    None
}

/// THE KERNEL'S OWN REFUSAL: the answer when no plane renders one (no plane's line and no fallback
/// plane takes the path, or the plane's render failed). The kernel speaks no dialect (spec §1, "It
/// is a byte pump"), so it is the neutral envelope, `application/json`, at the kernel's status: the
/// bytes a build that links no dialect has always answered.
pub(crate) fn kernel_refusal(status: StatusCode, kind: &str, message: &str) -> Response {
    crate::proxy::ingress_error(status, kind, message)
}

/// Render `status`/`kind`/`message` for the resolved `ingress`: a mounted plane's JSON-RPC answer, or
/// the kernel's own envelope.
///
/// The `kind` is the protocol-agnostic error category of the kernel's envelope; a JSON-RPC plane has
/// no such vocabulary — its category IS its numeric code — so the mounted arm does not consult it.
pub(crate) fn native_error(
    ingress: Ingress,
    status: StatusCode,
    kind: &str,
    message: &str,
) -> Response {
    match ingress {
        // EVERY MOUNTED PLANE SPEAKS JSON-RPC 2.0. That is not an assumption made here — it is what
        // `Plane::wire_format_names` states and what `every_mounted_planes_dialect_is_jsonrpc`
        // pins, so the day a mounted plane speaks something else the build says so rather than this
        // arm quietly mis-shaping it. Answering a JSON-RPC client in a vendor envelope is not a
        // cosmetic mismatch: the client's decoder fails, and the failure is attributed to the wrong
        // layer.
        Ingress::Mounted(_) => crate::ingress::jsonrpc::transport_refusal(status, message),
        // THE RESIDUAL: a path no plane is mounted on. The kernel identifies no dialect from a path
        // (a plane matches its own claimed routes and renders its own refusals through its door),
        // so it answers its own envelope.
        Ingress::Fallback => kernel_refusal(status, kind, message),
    }
}
