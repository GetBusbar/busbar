//! The `jev` dialect: plain HTTP+JSON, byte-identity passthrough.
//!
//! There is no envelope to read the way MCP/A2A read a JSON-RPC envelope — jev's two operations are
//! named by the HTTP verb and path (`ops.rs`), and a request or response body is a bare JSON
//! document forwarded UNCHANGED. This module's whole job is: name the small, closed set of pointers
//! this plane ever resolves (never `state`, never `answers` — see `facts.rs`'s module note), and
//! read them through the contract's own span grammar rather than a second parser.
//!
//! ## Byte-identity passthrough, precisely
//!
//! "Byte-identity" means the body bytes that arrive are the body bytes that leave, on both legs:
//! `encode_egress` forwards the caller's request body to the provider unchanged, and
//! `encode_response` forwards the provider's response body to the caller unchanged. The pointer
//! list below is read ALONGSIDE that forwarding, never in place of it — `Ir::body()` always carries
//! the whole document; `Ir::pointer()` is a read into a handful of declared members of it, and
//! nothing this plane does discards or rewrites the rest.

use busbar_contract::bounded::{Ir, PlaneAlloc};
use busbar_contract::unit::Ctx;
use busbar_contract::wire::Decode;

/// The pointer a response carries its top-level error object at, where it errored.
///
/// Presence alone is what this plane reads — never the error's own fields, which could echo
/// caller-supplied content back (jev's error bodies are not exempted from the PII rule by being
/// "just an error").
pub const PTR_ERROR: &str = "/error";

/// The pointer a response carries its provider-assigned request identifier at, where it names one.
/// Plain metadata: a correlation handle, never decision content.
pub const PTR_REQUEST_ID: &str = "/request_id";

/// The pointer a `systemone` request or response body echoes a bare `id` at, where jev uses that
/// spelling instead of `request_id`. Read as a fallback, same as `PTR_REQUEST_ID`.
pub const PTR_ID: &str = "/id";

/// The pointer a SUCCESSFUL `systemone` response reports its billable usage count at.
///
/// This is the one number `plane.rs::meter` reads. Nested under `usage` rather than top-level so a
/// provider that reports several billing dimensions in the future has somewhere to add a sibling
/// without this plane growing a second top-level member to ignore.
pub const PTR_USAGE_UNITS: &str = "/usage/units";

/// Every pointer this plane resolves in a RESPONSE body (`systemone` or `models`). Declared here
/// once, so the "never resolves `/state` or `/answers`" claim is checkable by reading one list
/// rather than auditing every call site.
pub const RESPONSE_PTRS: &[&str] = &[PTR_ERROR, PTR_REQUEST_ID, PTR_ID, PTR_USAGE_UNITS];

/// Every pointer this plane resolves in a REQUEST body.
///
/// Empty. A `systemone` request carries the caller's `state` and nothing else this plane has a use
/// for — there is no safe member to declare a pointer at, so none is declared. This is not an
/// oversight the way an empty ingress pointer list would be for MCP/A2A (which read a method name
/// and an id out of every request): jev names its operation in the path, not the body, so the
/// REQUEST body genuinely carries nothing this plane reads.
pub const REQUEST_PTRS: &[&str] = &[];

/// The span view of a body, built from one of the two declared pointer lists above.
///
/// One scan of one closed grammar, into the unit's own arena — the same seam `busbar-plane-a2a`
/// reads through, named here rather than re-derived, so a declared-pointer list is the only way
/// this plane's view of a body can ever widen.
pub fn view<'u>(body: &'u [u8], pointers: &[&'u str], ctx: &Ctx<'u>) -> Result<Ir<'u>, Decode> {
    let spans = busbar_contract::spans::resolve(body, pointers, ctx.arena())
        .map_err(|_| Decode::Oversize)?;
    Ok(Ir::new(body, spans))
}

/// The span view of a body against an arbitrary arena, for callers (tests, `encode_egress`'s own
/// rebuild) that hold an arena without a full `Ctx`.
pub fn view_with_arena<'u>(
    body: &'u [u8],
    pointers: &[&'u str],
    arena: &'u dyn PlaneAlloc,
) -> Result<Ir<'u>, Decode> {
    let spans =
        busbar_contract::spans::resolve(body, pointers, arena).map_err(|_| Decode::Oversize)?;
    Ok(Ir::new(body, spans))
}

/// Whether a body has a member at one declared pointer at all.
#[must_use]
pub fn has(body: &[u8], pointer: &str) -> bool {
    read_raw(body, pointer).is_some()
}

/// The raw bytes at one declared pointer of a body.
#[must_use]
pub fn read_raw<'u>(body: &'u [u8], pointer: &str) -> Option<&'u [u8]> {
    match busbar_contract::spans::resolve_pointer(body, pointer) {
        busbar_contract::spans::Resolved::Found(span) => body.get(span.start..span.end),
        _ => None,
    }
}

/// The string value at one declared pointer, with its quotes stripped.
#[must_use]
pub fn read_str<'u>(body: &'u [u8], pointer: &str) -> Option<&'u str> {
    let raw = read_raw(body, pointer)?;
    let inner = raw.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    core::str::from_utf8(inner).ok()
}

/// The integer value at one declared pointer, where it parses as a bare JSON number.
#[must_use]
pub fn read_u64(body: &[u8], pointer: &str) -> Option<u64> {
    let raw = read_raw(body, pointer)?;
    core::str::from_utf8(raw).ok()?.parse().ok()
}

#[cfg(test)]
#[path = "../tests/codec.rs"]
mod tests;
