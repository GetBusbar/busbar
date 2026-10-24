//! THE CONNECTOR'S CARRIER NAMES ARE THE CONNECTOR'S OWN VOCABULARY, IN THE CONNECTOR AND IN THE
//! LOADER'S NEED SERVICES (architect ruling 2026-10-23 (R-3), L0-3, applying the amended 2026-10-21
//! ruling, docs/design/BUSBAR-1.6.0.md l.4323-4332: exempt positionally, everything else counts).
//!
//! THE WORDS ([`CARRIER_WORDS`]) are the two carriers THE DESIGN §5 names (l.581-586: "carriers
//! (`tcp`, `stdio`) dial, accept, read and write", and "the connector builds every connection as
//! carrier → [TLS] → framer"; the third, `unix`, was dropped by OWNER Q127, l.5074). They are the
//! words the connector composes connections out of and the words a plugin's declared need names its
//! carrier by, so they are not renamed.
//!
//! WHERE THEY ARE EXEMPT, and nowhere else:
//! - in the connector ([`CONNECTOR_PACKAGE`]), every file: the crate that owns every dialled and
//!   accepted socket;
//! - in the loader ([`LOADER_PACKAGE`]), its need-service files ([`NEED_SERVICE_FILES`]: the table
//!   that serves a declared need its carrier, and the connection services a plugin's needs are
//!   opened through), every line;
//! - in the rest of the loader, two positions ([`mask_loader`]): the need service's own name (the
//!   carrier joined to `conns`: `tcp_conns`, `TcpConns`) and a need's carrier as a whole string
//!   literal (`"tcp"`, `"stdio"`, as `need(abi_str("tcp"))` or a facts document declares it).
//!
//! ONLY THE BARE CARRIER ID IS EXEMPT. A transport plugin's package name or kind-qualified id
//! (`busbar-transport-tcp`, `transport-stdio`) names an instance, not the carrier, and counts in
//! these crates as anywhere; so does every framer's id (`http`, `ws`, `grpc`, …), and so does a
//! carrier word anywhere else in the loader (an identifier, a comment) and in every other crate.

/// The carriers THE DESIGN §5 names.
pub(super) const CARRIER_WORDS: &[&str] = &["tcp", "stdio"];

/// The connector: every file of it.
pub(super) const CONNECTOR_PACKAGE: &str = "busbar-core-connector";

/// The loader: its need-service files, and two positions elsewhere.
pub(super) const LOADER_PACKAGE: &str = "busbar-plugin-loader";

/// The loader's need-service files, relative to its crate directory.
pub(super) const NEED_SERVICE_FILES: &[&str] =
    &["src/tcp_conns.rs", "src/dispatch/conn_services.rs"];

/// The axis the carrier words are needles of.
const AXIS: &str = "transport";

/// Whether a hit of needle `word` on axis `kind`, in file `rel` of crate `krate` (directory `dir`),
/// is a carrier name where the ruling places it: the bare carrier id, in the connector or in one
/// of the loader's need-service files.
pub(super) fn exempt_hit(krate: &str, dir: &str, rel: &str, kind: &str, word: &str) -> bool {
    kind == AXIS
        && CARRIER_WORDS.contains(&word)
        && (krate == CONNECTOR_PACKAGE || (krate == LOADER_PACKAGE && is_need_service(dir, rel)))
}

/// Whether `rel` is one of the loader's [`NEED_SERVICE_FILES`] under its directory `dir`.
pub(super) fn is_need_service(dir: &str, rel: &str) -> bool {
    rel.strip_prefix(dir)
        .and_then(|r| r.strip_prefix('/'))
        .is_some_and(|r| NEED_SERVICE_FILES.contains(&r))
}

/// A loader file's `text` with the carrier masked in its two loader-wide positions (same-length
/// filler, so lines and columns hold), or `None` when it holds neither.
pub(super) fn mask_loader(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    if !CARRIER_WORDS.iter().any(|w| lower.contains(w)) {
        return None;
    }
    let b = text.as_bytes();
    let lb = lower.as_bytes();
    let mut out = b.to_vec();
    let mut changed = false;
    for w in CARRIER_WORDS {
        let mut from = 0;
        while let Some(off) = lower[from..].find(w) {
            let i = from + off;
            let j = i + w.len();
            from = j;
            if carrier_literal(b, i, j) || need_service_name(b, lb, i, j) {
                out[i..j].fill(b'x');
                changed = true;
            }
        }
    }
    changed.then(|| String::from_utf8(out).expect("ascii-for-ascii"))
}

/// `"tcp"`: the carrier is the whole string literal.
fn carrier_literal(b: &[u8], i: usize, j: usize) -> bool {
    i > 0 && b[i - 1] == b'"' && b.get(j) == Some(&b'"') && (i < 2 || b[i - 2] != b'\\')
}

/// `tcp_conns` / `TcpConns` / `TCP_CONNS`: the carrier as the first word of the need service's
/// name, not joined to a name before it, and the name ending at `conns`.
fn need_service_name(b: &[u8], lb: &[u8], i: usize, j: usize) -> bool {
    let joined_before = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
    if joined_before {
        return false;
    }
    let rest = if lb.get(j) == Some(&b'_') { j + 1 } else { j };
    // Camel case joins without a separator only at a case transition (`TcpConns`, not `tcpconns`).
    if rest == j && !b.get(j).is_some_and(u8::is_ascii_uppercase) {
        return false;
    }
    let end = rest + "conns".len();
    lb.get(rest..end) == Some(b"conns".as_slice())
        && !b
            .get(end)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

#[cfg(test)]
#[path = "carriers_tests.rs"]
mod tests;
