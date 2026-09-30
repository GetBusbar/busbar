//! `unix` AS THE OPERATING SYSTEM, NOT THE CARRIER.
//!
//! `BUSBAR-1.6.0.md` THE DESIGN, §5 names the connector's carriers `tcp, stdio, unix`. The day
//! `busbar-transport-unix` exists, `unix` is a transport needle in every crate. A scanner that reads
//! bytes would then score every `#[cfg(unix)]`, every `std::os::unix::fs::PermissionsExt` and every
//! `now_unix_ns()` in the kernel, the connector and the loader as those crates naming a transport.
//! None of them does. They name the target family the compiler builds for, the standard
//! library's OS module, or the clock.
//!
//! Masked (same-length `x` filler, so lines and columns hold):
//!
//! * a `cfg` predicate: `#[cfg(unix)]`, `cfg!(not(unix))`, `cfg(all(unix, …))`,
//!   `target_family = "unix"`;
//! * a path rooted at the standard library or an OS crate ([`OS_PATH_HEADS`]), or any crate's
//!   `os::unix` module: `std::os::unix::fs::PermissionsExt`, `tokio::net::unix::…`,
//!   `libloading::os::unix::Library`;
//! * a standard-library socket type named whole ([`OS_SOCKET_TYPES`]): `UnixStream`,
//!   `UnixListener`, `UnixDatagram`, `UnixSocket`;
//! * `unix` as a MIDDLE segment of an identifier (`*_unix_*`: `set_unix_mode`,
//!   `start_time_unix_nano`), and as any segment whose neighbour is the clock ([`TIME_WORDS`]:
//!   `now_unix`, `UNIX_EPOCH`, `expires_at_unix`);
//! * `unix` written as a WORD ("SIGTERM on unix", "non-unix builds", "Unix/Windows"), in a
//!   comment or a message, unless the next word makes it the socket ([`CARRIER_WORDS`]: "a unix
//!   socket", "the unix-domain carrier", "the unix wire");
//! * `unix://` inside a transport's own `claims.rs`, where a sibling carrier's claim table spells
//!   the scheme it refuses.
//!
//! Everything else still counts: the crate's own name (`busbar_transport_unix::`,
//! `transport-unix`), a claim literal (`"unix"`), a scheme target (`unix:///run/busbar.sock`), prose
//! that names the socket ("dial the unix socket", "claim `unix`"), a manifest key,
//! `mod unix`, a crate-rooted path
//! (`crate::carrier::unix::open`), and an identifier whose `unix` is its first or last segment
//! with no clock beside it (`connect_unix`, `UnixCarrier`).

use std::borrow::Cow;

/// The words this module reads contexts for.
const OS_WORDS: &[&str] = &["unix"];

/// Path heads whose `…::unix…` is the operating system's module, not the carrier.
const OS_PATH_HEADS: &[&str] = &[
    "std", "core", "libc", "nix", "rustix", "tokio", "mio", "socket2",
];

/// Standard-library, tokio and mio socket types that carry the OS word, matched WHOLE.
const OS_SOCKET_TYPES: &[&str] = &["UnixStream", "UnixListener", "UnixDatagram", "UnixSocket"];

/// A neighbour that makes `unix` the clock.
const TIME_WORDS: &[&str] = &[
    "epoch",
    "time",
    "timestamp",
    "timestamps",
    "second",
    "seconds",
    "secs",
    "sec",
    "ms",
    "us",
    "ns",
    "nano",
    "nanos",
    "nanosecond",
    "nanoseconds",
    "milli",
    "millis",
    "millisecond",
    "milliseconds",
    "micro",
    "micros",
    "microsecond",
    "microseconds",
    "now",
    "at",
    "expires",
    "date",
];

/// A following word that makes `unix` the platform.
const PLATFORM_WORDS: &[&str] = &[
    "only",
    "specific",
    "like",
    "build",
    "builds",
    "platform",
    "platforms",
    "family",
    "os",
    "systems",
    "system",
];

fn is_id(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The whole identifier (`[A-Za-z0-9_]+`) around `b[i..j]`.
fn ident_around(b: &[u8], i: usize, j: usize) -> (usize, usize) {
    let mut s = i;
    while s > 0 && is_id(b[s - 1]) {
        s -= 1;
    }
    let mut e = j;
    while e < b.len() && is_id(b[e]) {
        e += 1;
    }
    (s, e)
}

/// `b[s..e]` split into lowercase segments at `_` and at camel-case joints, each with its range.
fn segments(b: &[u8], s: usize, e: usize) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for k in s..=e {
        let c = if k < e { Some(b[k]) } else { None };
        let boundary = match c {
            None | Some(b'_') => true,
            Some(c) => {
                let prev = k.checked_sub(1).filter(|p| *p >= s).map(|p| b[p]);
                let next = if k + 1 < e { Some(b[k + 1]) } else { None };
                c.is_ascii_uppercase()
                    && (prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
                        || (prev.is_some_and(|p| p.is_ascii_uppercase())
                            && next.is_some_and(|n| n.is_ascii_lowercase())))
            }
        };
        if boundary {
            if let Some(st) = start.take() {
                out.push((
                    st,
                    k,
                    String::from_utf8_lossy(&b[st..k]).to_ascii_lowercase(),
                ));
            }
            if c.is_some_and(|c| c != b'_') {
                start = Some(k);
            }
        } else if start.is_none() {
            start = Some(k);
        }
    }
    out
}

/// The word before and after `b[i..j]` across one run of spaces or `-`, lowercased.
fn prose_neighbours(b: &[u8], i: usize, j: usize) -> (String, String) {
    let word = |from: usize, to: usize| String::from_utf8_lossy(&b[from..to]).to_ascii_lowercase();
    let mut k = i;
    while k > 0 && matches!(b[k - 1], b' ' | b'-') {
        k -= 1;
    }
    let before = if k < i {
        let mut s = k;
        while s > 0 && b[s - 1].is_ascii_alphabetic() {
            s -= 1;
        }
        word(s, k)
    } else {
        String::new()
    };
    let mut k = j;
    while k < b.len() && matches!(b[k], b' ' | b'-') {
        k += 1;
    }
    let after = if k > j {
        let mut e = k;
        while e < b.len() && b[e].is_ascii_alphabetic() {
            e += 1;
        }
        word(k, e)
    } else {
        String::new()
    };
    (before, after)
}

/// Whether `b[i..j]` is an argument of a `cfg(`, `cfg!(` or `cfg_attr(` predicate on this line.
fn in_cfg(b: &[u8], i: usize, j: usize) -> bool {
    let line = String::from_utf8_lossy(b);
    if !(line.contains("cfg(") || line.contains("cfg!(") || line.contains("cfg_attr(")) {
        return false;
    }
    let mut k = i;
    while k > 0 && b[k - 1] == b' ' {
        k -= 1;
    }
    let mut e = j;
    while e < b.len() && b[e] == b' ' {
        e += 1;
    }
    k > 0 && matches!(b[k - 1], b'(' | b',') && matches!(b.get(e), Some(b')' | b','))
}

/// `target_family = "unix"`.
fn is_target_family(b: &[u8], i: usize, j: usize) -> bool {
    if !(i > 0 && b[i - 1] == b'"' && b.get(j) == Some(&b'"')) {
        return false;
    }
    let before = String::from_utf8_lossy(&b[..i - 1]);
    before
        .trim_end()
        .trim_end_matches('=')
        .trim_end()
        .ends_with("target_family")
}

/// The head of the `a::b::…` path whose segment is `b[i..j]`, when `b[i..j]` is one. On a `use`
/// line the head is the first segment after `use`, so a grouped import is rooted where it starts.
fn os_path_head(b: &[u8], i: usize, j: usize) -> Option<String> {
    let path_before = i >= 2 && &b[i - 2..i] == b"::";
    let path_after = b[j..].starts_with(b"::");
    let line = String::from_utf8_lossy(b);
    let t = line.trim_start();
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    if let Some(rest) = t.strip_prefix("use ") {
        if path_before || path_after || matches!(b.get(i.wrapping_sub(1)), Some(b'{' | b' ' | b','))
        {
            return rest
                .trim_start_matches("::")
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
                .map(str::to_string);
        }
    }
    if !path_before && !path_after {
        return None;
    }
    let mut s = i;
    while s >= 2 && &b[s - 2..s] == b"::" {
        let mut k = s - 2;
        while k > 0 && is_id(b[k - 1]) {
            k -= 1;
        }
        if k == s - 2 {
            break;
        }
        s = k;
    }
    let mut e = s;
    while e < b.len() && is_id(b[e]) {
        e += 1;
    }
    Some(String::from_utf8_lossy(&b[s..e]).into_owned())
}

/// Whether the OS word at `b[i..j]` is one of the operating-system contexts in a file at `rel`.
fn is_os_context(rel: &str, b: &[u8], i: usize, j: usize) -> bool {
    // The crate's own name (`busbar-transport-unix`, `transport_unix`, `TransportUnix`).
    if super::joined_to_marker(b, i) {
        return false;
    }
    if b[j..].starts_with(b"://") {
        // A scheme target is the carrier, except in a transport's own claim table.
        return rel.ends_with("/claims.rs");
    }
    if in_cfg(b, i, j) || is_target_family(b, i, j) {
        return true;
    }
    // `…::os::unix::…` is the operating-system module of whatever crate holds it
    // (`std::os::unix`, `libloading::os::unix`).
    if i >= 4 && b[..i].ends_with(b"os::") {
        return true;
    }
    if os_path_head(b, i, j).is_some_and(|h| OS_PATH_HEADS.contains(&h.as_str())) {
        return true;
    }
    let (s, e) = ident_around(b, i, j);
    let ident = String::from_utf8_lossy(&b[s..e]);
    if OS_SOCKET_TYPES.contains(&ident.as_ref()) {
        return true;
    }
    // Inside a longer identifier: its position and its neighbouring segments decide.
    let segs = segments(b, s, e);
    if let Some(at) = segs.iter().position(|(a, z, _)| *a <= i && j <= *z) {
        let prev = at.checked_sub(1).map(|p| segs[p].2.as_str());
        let next = segs.get(at + 1).map(|n| n.2.as_str());
        if prev == Some("transport") {
            return false;
        }
        if prev.is_some_and(|p| TIME_WORDS.contains(&p))
            || next.is_some_and(|n| TIME_WORDS.contains(&n))
        {
            return true;
        }
        if segs.len() > 1 {
            // `*_unix_*`: a middle segment names a property, never the carrier.
            return prev.is_some() && next.is_some();
        }
    }
    // A WHOLE WORD. Written as a name it is the carrier: quoted as code (`` `unix` ``), the exact
    // literal `"unix"`, `mod unix`, a crate-rooted path segment, a manifest key.
    let quoted_as = |open: u8, close: u8| i > 0 && b[i - 1] == open && b.get(j) == Some(&close);
    if quoted_as(b'"', b'"') {
        return false;
    }
    // Quoted as code in prose, it is still read by its neighbours: "claim `unix`" is the carrier,
    // "`unix` in the gate" is the cfg predicate.
    if quoted_as(b'`', b'`') {
        let (before, after) = prose_neighbours(b, i - 1, j + 1);
        return !(CARRIER_WORDS.contains(&after.as_str())
            || CARRIER_WORDS.contains(&before.as_str()));
    }
    let before_text = String::from_utf8_lossy(&b[..i]);
    if before_text.trim_end().ends_with("mod") || os_path_head(b, i, j).is_some() {
        return false;
    }
    if rel.ends_with(".toml") && before_text.trim().is_empty() {
        return false;
    }
    // Written as a word, it is the operating system, unless the next word makes it the socket
    // ("a unix socket", "the unix-domain carrier", "the unix wire"). A clock or platform word on
    // either side ("Unix seconds", "Unix-only") is the operating system as well.
    let (before, after) = prose_neighbours(b, i, j);
    if before == "non" {
        return true;
    }
    if TIME_WORDS.contains(&after.as_str())
        || PLATFORM_WORDS.contains(&after.as_str())
        || (TIME_WORDS.contains(&before.as_str()) && before != "at")
    {
        return true;
    }
    !CARRIER_WORDS.contains(&after.as_str())
}

/// A following word that makes a whole-word `unix` the carrier rather than the operating system.
const CARRIER_WORDS: &[&str] = &[
    "socket",
    "sockets",
    "domain",
    "carrier",
    "carriers",
    "transport",
    "transports",
    "wire",
    "wires",
    "claim",
    "claims",
    "target",
    "targets",
    "listener",
    "stream",
    "streams",
    "door",
    "plugin",
    "connector",
];

/// `text` (a file at `rel`) with every operating-system occurrence of an [`OS_WORDS`] word masked.
#[cfg(test)]
pub(super) fn mask_os_words<'a>(rel: &str, text: &'a str) -> Cow<'a, str> {
    mask_os_words_in(rel, text, text)
}

/// [`mask_os_words`] over `masked`, an earlier mask's same-length rewrite of `original`: every
/// context is read off `original`, and the filler goes into `masked` at the same bytes.
pub(super) fn mask_os_words_in<'a>(rel: &str, original: &str, masked: &'a str) -> Cow<'a, str> {
    let lower = masked.to_ascii_lowercase();
    if !OS_WORDS.iter().any(|w| lower.contains(w)) || original.len() != masked.len() {
        return Cow::Borrowed(masked);
    }
    let mut out = String::with_capacity(masked.len());
    for (line, orig) in masked
        .split_inclusive('\n')
        .zip(original.split_inclusive('\n'))
    {
        if orig.len() != line.len() {
            out.push_str(line);
            continue;
        }
        let b = orig.as_bytes();
        let low = line.to_ascii_lowercase();
        let mut buf = line.as_bytes().to_vec();
        let mut touched = false;
        for word in OS_WORDS {
            let mut from = 0;
            while let Some(off) = low[from..].find(word) {
                let i = from + off;
                let j = i + word.len();
                from = j;
                if is_os_context(rel, b, i, j) {
                    buf[i..j].fill(b'x');
                    touched = true;
                }
            }
        }
        match (touched, String::from_utf8(buf)) {
            (true, Ok(s)) => out.push_str(&s),
            _ => out.push_str(line),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(rel: &str, s: &str) -> bool {
        !mask_os_words(rel, s).to_ascii_lowercase().contains("unix")
    }

    #[test]
    fn the_operating_system_is_masked() {
        for s in [
            "#[cfg(unix)]",
            "#[cfg(not(unix))]",
            "#[cfg(all(unix, not(target_os = \"macos\")))]",
            "if cfg!(unix) {",
            "#[cfg(target_family = \"unix\")]",
            "use std::os::unix::fs::PermissionsExt;",
            "use std::os::{unix, fd};",
            "std::os::unix::fs::symlink(a, b)",
            "let s = tokio::net::UnixStream::connect(p);",
            "let l: UnixListener = bind();",
            "let t = now_unix_ns();",
            "SystemTime::UNIX_EPOCH",
            "use std::time::{SystemTime, UNIX_EPOCH};",
            "let d = now.duration_since(UNIX_EPOCH)?;",
            "expires_at_unix: u64,",
            "let unix_ms = 1;",
            "start_time_unix_nano",
            "fn set_unix_mode_bits() {}",
            "/// Unix seconds since the epoch.",
            "// a unix time, not a wall clock",
            "// Unix-only: the mode bits.",
            "// UNIX ONLY",
            "// unix builds skip this",
            "// Non-unix has no SO_REUSEPORT, so those builds",
            "// Non-unix targets see it as unused.",
            "libloading::os::unix::Library::this()",
            "/// `unix` in the gate, not just `test`: its one caller",
            "summary: \"SIGTERM on unix, or ctrl_c\"",
            "/// Portable across Unix/Windows via getrandom",
            "// On unix each of the N data-plane workers runs its own accept loop",
            "/// Unix file mode for the temp file.",
            "# THE THREAD-PER-CORE BOOT SEAM, the one unix data-plane topology",
        ] {
            assert!(masked("crates/busbar-kernel/src/a.rs", s), "{s}");
        }
        assert!(masked(
            "crates/busbar-transport-tcp/src/claims.rs",
            "// refuses unix://, which is not a tcp target"
        ));
    }

    #[test]
    fn the_carrier_still_counts() {
        for s in [
            "use busbar_transport_unix::Carrier;",
            "fn busbar_transport_unix_carrier() {}",
            "pub const TRANSPORT: &str = \"unix\";",
            "let target = \"unix:///run/busbar.sock\";",
            "// dial the unix socket",
            "fn connect_unix(p: &Path) {}",
            "struct UnixCarrier;",
            "match scheme { \"unix\" => dial() }",
            "mod unix;",
            "crate::carrier::unix::open()",
            "// a unix-domain stream carrier, claim `unix`",
            "// the `unix` carrier opens a path",
            "# THE UNIX WIRE'S LINKED ROW",
            "busbar-transport-unix = { path = \"../busbar-transport-unix\" }",
        ] {
            assert!(!masked("crates/busbar-kernel/src/a.rs", s), "{s}");
        }
    }

    /// An earlier mask's filler (`socket` masked as a contract identifier) must not turn "the unix
    /// socket" into "the unix xxxxxx" and so into the operating system.
    #[test]
    fn context_is_read_off_the_original_text() {
        let original = "// dial the unix socket first.\n";
        let masked = "// dial the unix xxxxxx xxxxx.\n";
        assert_eq!(mask_os_words_in("a.rs", original, masked), masked);
        let os = "// SIGTERM on unix, or ctrl_c.\n";
        assert!(!mask_os_words_in("a.rs", os, os).contains("unix"));
    }

    #[test]
    fn untouched_text_is_borrowed() {
        assert!(matches!(
            mask_os_words("a.rs", "no os word here"),
            Cow::Borrowed(_)
        ));
    }
}
