//! FROZEN 1.5.5 BYTES ARE DATA, NOT INSTANCE LOGIC (ARCHITECT rulings Q3 and Q2(i), 2026-10-20,
//! Law 0 burndown §3(d)).
//!
//! Four 1.5.5 surfaces are customer-visible bytes that DoD forbids changing: the admin API's
//! OpenAPI document, the config schema snapshot, the `--migrate-config` translation (which must read
//! 1.5.x module names) and the `{ env: VAR }` / `{ file: path }` secret shorthand. A plugin's name
//! written there is 1.5.5's wire, frozen, and counting it charged core with an instance reference it
//! cannot drain without breaking DoD item 6. The ruling: exclude ONLY those named artifacts, each
//! entry citing its 1.5.5 surface, and nothing else.
//!
//! THE EXCLUSION IS NARROWER THAN THE FILE. Each artifact has grown in 1.6.0 (the OpenAPI document
//! from 8 736 lines at `v1.5.5` to 14 055), and a line 1.6.0 added is not a 1.5.5 byte. So a hit in
//! a listed artifact is excluded only when its line, trimmed, is a line of the SAME artifact at the
//! `v1.5.5` tag, read from git ([`RELEASE`], [`Artifact::released`]). A line 1.6.0 wrote there counts
//! as it does anywhere. If the tag cannot be read the artifact excludes nothing: when an instrument
//! must choose, it false-fails.
//!
//! [`WIRE_SPELLINGS`] is the Q2(i) half: a 1.5.5 wire spelling in a crate that owns sockets, named
//! one line at a time, each with its citation. Every other protocol word in those crates still
//! counts (Q2: not excluded wholesale).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::ctx::Ctx;

/// The released tag whose bytes are frozen.
pub(super) const RELEASE: &str = "v1.5.5";

/// One frozen artifact: where it lives now, where it lived at [`RELEASE`], and the surface it is.
pub(super) struct Artifact {
    /// The path in this tree.
    pub(super) path: &'static str,
    /// The git object name of the same artifact at the release (`<tag>:<path>`).
    pub(super) released: &'static str,
    /// The 1.5.5 surface, cited.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) surface: &'static str,
}

/// THE NAMED ARTIFACTS (Q3). Nothing else is excluded.
pub(super) const ARTIFACTS: &[Artifact] = &[
    Artifact {
        path: "crates/busbar-core-admin/src/v1/json/openapi.json",
        released: "v1.5.5:crates/busbar/src/admin/v1/json/openapi.json",
        surface: "the admin API's OpenAPI document, served at GET /v1/openapi.json (v1.5.5 \
                  crates/busbar/src/admin/v1/json/openapi.json)",
    },
    Artifact {
        path: "crates/busbar-kernel/src/config/config-schema.snapshot.json",
        released: "v1.5.5:crates/busbar/src/config/config-schema.snapshot.json",
        surface:
            "the operator config schema snapshot the config-schema gate holds additive (v1.5.5 \
                  crates/busbar/src/config/config-schema.snapshot.json)",
    },
    Artifact {
        path: "crates/busbar-kernel/src/config/migrate.rs",
        released: "v1.5.5:crates/busbar/src/config/migrate.rs",
        surface: "the --migrate-config translation, which reads 1.5.x module names (v1.5.5 \
                  crates/busbar/src/config/migrate.rs)",
    },
    Artifact {
        path: "crates/busbar-kernel/src/config/migrate_export.rs",
        released: "v1.5.5:crates/busbar/src/config/migrate_export.rs",
        surface: "the --migrate-config export translation: 1.5.x export modules and their streams \
                  (v1.5.5 crates/busbar/src/config/migrate_export.rs)",
    },
    Artifact {
        path: "crates/busbar-kernel/src/config/tests/migrate_tests.rs",
        released: "v1.5.5:crates/busbar/src/config/tests/migrate_tests.rs",
        surface: "the --migrate-config translation's 1.5.x input configs (v1.5.5 \
                  crates/busbar/src/config/tests/migrate_tests.rs)",
    },
    Artifact {
        path: "crates/busbar-contract/src/secret_ref.rs",
        released: "v1.5.5:crates/secret-ref/src/lib.rs",
        surface:
            "the { env: VAR } / { file: path } secret shorthand and its built-in module names \
                  (v1.5.5 crates/secret-ref/src/lib.rs)",
    },
];

/// One 1.5.5 wire spelling in a socket-owning crate (Q2(i)): the file, the line (trimmed, whole),
/// and the citation.
pub(super) struct WireSpelling {
    pub(super) path: &'static str,
    pub(super) line: &'static str,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) cite: &'static str,
}

/// THE NAMED WIRE SPELLINGS (Q2(i)). Every other `tcp`, `http` and `sse` in the connector, the
/// kernel's egress and the loader still counts; the ones core hard-codes as a transport's behaviour
/// are real and are drained in code.
pub(super) const WIRE_SPELLINGS: &[WireSpelling] = &[WireSpelling {
    path: "crates/busbar-kernel-egress/src/trust/net.rs",
    line: "scheme: \"http\".to_string(),",
    cite: "the URL scheme of an operator's upstream `base_url` named in the plaintext refusal: \
           1.5.5's rule that `http` is admitted only for a local or private host (v1.5.5 \
           crates/busbar/src/config_validate/mod.rs:343-345, `scheme_is(base_url, \"http\")`)",
}];

/// Per path, the trimmed lines that are frozen bytes.
pub(super) type Frozen = BTreeMap<&'static str, Arc<BTreeSet<String>>>;

type ReleasedMemo = std::sync::Mutex<BTreeMap<&'static str, Option<Arc<BTreeSet<String>>>>>;
static RELEASED_MEMO: std::sync::OnceLock<ReleasedMemo> = std::sync::OnceLock::new();

fn lines_of(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// The trimmed lines of `released` (`<tag>:<path>`), read with `git show` once per process; a
/// self-test's planted `git-show:<tag>:<path>` answers first and is never memoised.
fn released_lines(cx: &Ctx, released: &'static str) -> Option<Arc<BTreeSet<String>>> {
    let (tag, path) = released.split_once(':')?;
    // Only the release's own bytes are frozen: an entry naming any other ref freezes nothing.
    if tag != RELEASE {
        return None;
    }
    if let Some(planted) = cx.overlay_command(&format!("git-show:{released}")) {
        return Some(Arc::new(lines_of(&planted)));
    }
    let memo = RELEASED_MEMO.get_or_init(Default::default);
    if let Some(held) = memo
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(released)
    {
        return held.clone();
    }
    let read = cx.git_show(tag, path).ok().map(|t| Arc::new(lines_of(&t)));
    memo.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(released, read.clone());
    read
}

/// The frozen lines of every artifact and wire spelling, for this tree.
pub(super) fn load(cx: &Ctx) -> Frozen {
    let mut out: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for a in ARTIFACTS {
        if let Some(lines) = released_lines(cx, a.released) {
            out.entry(a.path).or_default().extend(lines.iter().cloned());
        }
    }
    for w in WIRE_SPELLINGS {
        out.entry(w.path).or_default().insert(w.line.to_string());
    }
    out.into_iter().map(|(k, v)| (k, Arc::new(v))).collect()
}

/// Whether line `line` (1-based; 0 is the path, never frozen) of `text`, the file at `rel`, is a
/// frozen byte.
pub(super) fn is_frozen(frozen: &Frozen, rel: &str, lines: &[&str], line: usize) -> bool {
    let Some(set) = frozen.get(rel) else {
        return false;
    };
    line.checked_sub(1)
        .and_then(|i| lines.get(i))
        .map(|l| l.trim())
        .is_some_and(|l| !l.is_empty() && set.contains(l))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_cites_its_surface_and_names_a_file_of_this_tree() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits in the repository root");
        for a in ARTIFACTS {
            assert!(
                a.surface.contains("v1.5.5"),
                "{} cites no 1.5.5 surface",
                a.path
            );
            assert!(a.released.starts_with("v1.5.5:"), "{}", a.released);
            assert!(root.join(a.path).is_file(), "{} is not in the tree", a.path);
        }
        for w in WIRE_SPELLINGS {
            assert!(
                w.cite.contains("v1.5.5"),
                "{} cites no 1.5.5 surface",
                w.path
            );
            let text = std::fs::read_to_string(root.join(w.path)).expect("the file is in the tree");
            assert!(
                text.lines().any(|l| l.trim() == w.line),
                "the wire spelling `{}` is not in {}: a reservation over nothing is a dead allowance",
                w.line,
                w.path
            );
        }
    }

    #[test]
    fn only_a_frozen_line_of_a_listed_file_is_frozen() {
        let mut frozen = Frozen::new();
        frozen.insert(
            "a/openapi.json",
            Arc::new(["\"x\": \"llm\",".to_string()].into_iter().collect()),
        );
        let lines = ["{", "  \"x\": \"llm\",", "  \"y\": \"llm\",", ""];
        assert!(is_frozen(&frozen, "a/openapi.json", &lines, 2));
        assert!(!is_frozen(&frozen, "a/openapi.json", &lines, 3));
        assert!(!is_frozen(&frozen, "a/openapi.json", &lines, 0));
        assert!(!is_frozen(&frozen, "a/openapi.json", &lines, 4));
        assert!(!is_frozen(&frozen, "b/openapi.json", &lines, 2));
    }
}
