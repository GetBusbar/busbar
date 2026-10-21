//! FROZEN 1.5.5 BYTES ARE EXEMPT FROM LAW 0 ONLY IN PLACE (ARCHITECT ruling 2026-10-21,
//! BUSBAR-1.6.0.md; it corrects Q3 of 2026-10-20 and withdraws Q1, Q2 and Q4).
//!
//! Four 1.5.5 surfaces are customer-visible bytes that #9 and DoD item 6 forbid changing: the admin
//! API's OpenAPI document, the config schema snapshot, the `--migrate-config` translation (which
//! must read 1.5.x module names) and the `{ env: VAR }` / `{ file: path }` secret shorthand. A
//! plugin's name the release wrote there is that release's wire, and counting it charges core with
//! a reference it cannot drain without changing those bytes. Only the named [`ARTIFACTS`] are read;
//! nothing else is exempt.
//!
//! THE EXEMPTION IS POSITIONAL: A LINE, NOT A STRING. A hit is exempt only when its line is THE SAME
//! LINE the artifact carried at [`RELEASE`], unchanged: the line is matched (byte-equal, whole) in a
//! minimal line diff of the artifact against its own bytes at the tag ([`mask`], Myers' O(ND)
//! alignment). An equal string written anywhere else in the file is an insertion of that diff and
//! counts; so does an edited line, a moved line and a new one. The 1.6.0 `"streams"` key of the
//! schema snapshot, whose text matched another 1.5.5 line, is the case this rules out.
//!
//! WHY A DIFF AGAINST THE TAG AND NOT `git blame`. Blame's attribution IS diff alignment, applied
//! commit by commit; this is the same alignment taken once, from the tag to the bytes under
//! judgement. It reads the one input the gate already trusts (`git show v1.5.5:<path>`), so it needs
//! no history between the two (a shallow clone answers the same), no rename heuristics (every
//! artifact moved crates since 1.5.5, which blame follows only with `-C` guessing), and it judges
//! the tree the gate is handed, overlays included, so a self-test plants both sides and a working
//! tree is judged as written rather than as committed. If the tag cannot be read the artifact
//! exempts nothing: when an instrument must choose, it false-fails.

use std::collections::BTreeMap;
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

/// THE NAMED ARTIFACTS. Nothing else is exempt.
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

/// The artifact at `path`, if it is one.
pub(super) fn artifact(path: &str) -> Option<&'static Artifact> {
    ARTIFACTS.iter().find(|a| a.path == path)
}

/// Per artifact path, its text at the release.
pub(super) type Frozen = BTreeMap<&'static str, Arc<String>>;

type ReleasedMemo = std::sync::Mutex<BTreeMap<&'static str, Option<Arc<String>>>>;
static RELEASED_MEMO: std::sync::OnceLock<ReleasedMemo> = std::sync::OnceLock::new();

/// The text of `released` (`<tag>:<path>`), read with `git show` once per process; a self-test's
/// planted `git-show:<tag>:<path>` answers first and is never memoised.
fn released_text(cx: &Ctx, released: &'static str) -> Option<Arc<String>> {
    let (tag, path) = released.split_once(':')?;
    // Only the release's own bytes are frozen: an entry naming any other ref freezes nothing.
    if tag != RELEASE {
        return None;
    }
    if let Some(planted) = cx.overlay_command(&format!("git-show:{released}")) {
        return Some(Arc::new(planted));
    }
    let memo = RELEASED_MEMO.get_or_init(Default::default);
    if let Some(held) = memo
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(released)
    {
        return held.clone();
    }
    let read = cx.git_show(tag, path).ok().map(Arc::new);
    memo.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(released, read.clone());
    read
}

/// The released text of every artifact, for this tree.
pub(super) fn load(cx: &Ctx) -> Frozen {
    ARTIFACTS
        .iter()
        .filter_map(|a| released_text(cx, a.released).map(|t| (a.path, t)))
        .collect()
}

/// Per line of a file (index `i` is line `i + 1`), whether it is a frozen 1.5.5 line in place.
pub(super) type Mask = Arc<Vec<bool>>;

type MaskMemo = std::sync::Mutex<BTreeMap<(String, u64, u64), Mask>>;
static MASK_MEMO: std::sync::OnceLock<MaskMemo> = std::sync::OnceLock::new();

fn digest(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

/// The frozen-line mask of `text`, the file at `rel`: `None` when `rel` is no artifact or its
/// release could not be read (nothing is exempt). Computed once per (path, bytes, released bytes).
pub(super) fn mask(frozen: &Frozen, rel: &str, text: &str) -> Option<Mask> {
    let released = frozen.get(rel)?;
    let key = (rel.to_string(), digest(text), digest(released));
    let memo = MASK_MEMO.get_or_init(Default::default);
    if let Some(held) = memo
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
    {
        return Some(held.clone());
    }
    let m = Arc::new(aligned(released, text));
    memo.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, m.clone());
    Some(m)
}

/// Whether line `line` (1-based; 0 is the path, never frozen) is frozen under `mask`.
pub(super) fn at(mask: &[bool], line: usize) -> bool {
    line.checked_sub(1)
        .and_then(|i| mask.get(i))
        .copied()
        .unwrap_or(false)
}

/// Per line of `now`, whether a minimal line diff from `then` to `now` keeps it (matched, not
/// inserted). Lines compare whole and byte-equal: an edit of any byte, indentation included, is
/// an edit.
fn aligned(then: &str, now: &str) -> Vec<bool> {
    let mut ids: BTreeMap<&str, u32> = BTreeMap::new();
    let mut id = |l| {
        let next = u32::try_from(ids.len()).unwrap_or(u32::MAX);
        *ids.entry(l).or_insert(next)
    };
    let a: Vec<u32> = then.lines().map(&mut id).collect();
    let b: Vec<u32> = now.lines().map(&mut id).collect();
    let mut out = vec![false; b.len()];
    align(&a, &b, 0, &mut out);
    out
}

/// Marks in `out` (indexed from `b_at`) every line of `b` a minimal edit script from `a` keeps:
/// the common prefix and suffix, then the halves either side of Myers' middle split.
fn align(a: &[u32], b: &[u32], b_at: usize, out: &mut [bool]) {
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    for o in &mut out[b_at..b_at + pre] {
        *o = true;
    }
    let (a, b, b_at) = (&a[pre..], &b[pre..], b_at + pre);
    let suf = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    for o in &mut out[b_at + b.len() - suf..b_at + b.len()] {
        *o = true;
    }
    let (a, b) = (&a[..a.len() - suf], &b[..b.len() - suf]);
    if a.is_empty() || b.is_empty() {
        return;
    }
    if let Some((x, y)) = split(a, b) {
        align(&a[..x], &b[..y], b_at, out);
        align(&a[x..], &b[y..], b_at + y, out);
    }
}

/// Myers' middle split of a minimal edit script from `a` to `b` (both non-empty, sharing no prefix
/// or suffix): a point `(x, y)` such that a minimal script passes through it, or `None` when the
/// two share no line at all.
fn split(a: &[u32], b: &[u32]) -> Option<(usize, usize)> {
    let n = isize::try_from(a.len()).ok()?;
    let m = isize::try_from(b.len()).ok()?;
    let max_d = (n + m + 1) / 2;
    let off = max_d + 1;
    let len = usize::try_from(2 * max_d + 3).ok()?;
    let mut v1 = vec![-1isize; len];
    let mut v2 = vec![-1isize; len];
    let ix = |k: isize| usize::try_from(off + k).ok();
    v1[ix(1)?] = 0;
    v2[ix(1)?] = 0;
    let delta = n - m;
    // With an odd delta the forward path meets the reverse one; with an even, the reverse meets.
    let front = delta % 2 != 0;
    let (mut k1start, mut k1end, mut k2start, mut k2end) = (0isize, 0isize, 0isize, 0isize);
    let at = |s: &[u32], i: isize| s[usize::try_from(i).unwrap_or(0)];
    for d in 0..max_d {
        let mut k1 = -d + k1start;
        while k1 <= d - k1end {
            let k = ix(k1)?;
            let mut x1 = if k1 == -d || (k1 != d && v1[k - 1] < v1[k + 1]) {
                v1[k + 1]
            } else {
                v1[k - 1] + 1
            };
            let mut y1 = x1 - k1;
            while x1 < n && (0..m).contains(&y1) && at(a, x1) == at(b, y1) {
                x1 += 1;
                y1 += 1;
            }
            v1[k] = x1;
            if x1 > n {
                k1end += 2;
            } else if y1 > m {
                k1start += 2;
            } else if front {
                if let Some(k2) = ix(delta - k1).filter(|k2| *k2 < len) {
                    if v2[k2] != -1 && x1 >= n - v2[k2] {
                        return Some((usize::try_from(x1).ok()?, usize::try_from(y1).ok()?));
                    }
                }
            }
            k1 += 2;
        }
        let mut k2 = -d + k2start;
        while k2 <= d - k2end {
            let k = ix(k2)?;
            let mut x2 = if k2 == -d || (k2 != d && v2[k - 1] < v2[k + 1]) {
                v2[k + 1]
            } else {
                v2[k - 1] + 1
            };
            let mut y2 = x2 - k2;
            while x2 < n && (0..m).contains(&y2) && at(a, n - x2 - 1) == at(b, m - y2 - 1) {
                x2 += 1;
                y2 += 1;
            }
            v2[k] = x2;
            if x2 > n {
                k2end += 2;
            } else if y2 > m {
                k2start += 2;
            } else if !front {
                if let Some(k1) = ix(delta - k2).filter(|k1| *k1 < len) {
                    let x1 = v1[k1];
                    if x1 != -1 {
                        let y1 = x1 - (delta - k2);
                        if x1 >= n - x2 {
                            return Some((usize::try_from(x1).ok()?, usize::try_from(y1).ok()?));
                        }
                    }
                }
            }
            k2 += 2;
        }
    }
    None
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
    }

    fn kept(then: &[&str], now: &[&str]) -> Vec<bool> {
        aligned(&then.join("\n"), &now.join("\n"))
    }

    #[test]
    fn an_unchanged_line_is_frozen_in_place_and_an_equal_string_elsewhere_is_not() {
        let then = ["{", "  \"x\": \"llm\",", "  \"z\": 1", "}"];
        // Unchanged, with a line inserted before it: still the same line.
        let now = ["{", "  \"w\": 0,", "  \"x\": \"llm\",", "  \"z\": 1", "}"];
        assert_eq!(kept(&then, &now), [true, false, true, true, true]);
        // COPIED: the 1.5.5 string written again at a new position counts there.
        let now = [
            "{",
            "  \"x\": \"llm\",",
            "  \"z\": 1",
            "  \"x\": \"llm\",",
            "}",
        ];
        let m = kept(&then, &now);
        assert!(m[1], "the original stays in place");
        assert!(!m[3], "the copy is new: {m:?}");
        // EDITED: one byte, indentation included.
        let now = ["{", "   \"x\": \"llm\",", "  \"z\": 1", "}"];
        assert_eq!(kept(&then, &now), [true, false, true, true]);
    }

    #[test]
    fn a_moved_line_is_not_frozen() {
        let then = ["a", "llm", "b", "c", "d", "e"];
        let now = ["a", "b", "c", "d", "e", "llm"];
        assert_eq!(kept(&then, &now), [true, true, true, true, true, false]);
        let then = ["a", "b", "c", "d", "llm", "e"];
        let now = ["llm", "a", "b", "c", "d", "e"];
        assert_eq!(kept(&then, &now), [false, true, true, true, true, true]);
    }

    #[test]
    fn the_alignment_is_minimal_on_interleaved_edits() {
        // A longest common subsequence of these is 5 lines (a b d f g).
        let then = ["a", "b", "c", "d", "e", "f", "g"];
        let now = ["x", "a", "b", "d", "y", "f", "z", "g"];
        let m = kept(&then, &now);
        assert_eq!(m.iter().filter(|k| **k).count(), 5, "{m:?}");
        assert_eq!(m, [false, true, true, true, false, true, false, true]);
        // Nothing shared, and an empty side.
        assert_eq!(kept(&["a"], &["b", "c"]), [false, false]);
        assert_eq!(kept(&[], &["a"]), [false]);
        assert!(kept(&["a"], &[]).is_empty());
    }

    #[test]
    fn only_a_listed_artifact_has_a_mask_and_line_zero_is_never_frozen() {
        let mut frozen = Frozen::new();
        frozen.insert(ARTIFACTS[0].path, Arc::new("a\nllm\nb\n".to_string()));
        let m = mask(&frozen, ARTIFACTS[0].path, "a\nllm\nb\nllm\n").expect("listed");
        assert!(at(&m, 2));
        assert!(!at(&m, 4));
        assert!(!at(&m, 0));
        assert!(!at(&m, 9));
        assert!(mask(&frozen, "crates/busbar-kernel/src/lib.rs", "llm\n").is_none());
    }
}
