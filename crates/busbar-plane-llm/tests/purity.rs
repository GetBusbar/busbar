//! The plane is a value, and its source holds nothing it could remember between calls.
//!
//! A plane that remembers something between calls is a plane whose answer depends on what happened
//! earlier, and the loop has no way to see that. So two properties are asserted here rather than
//! promised: the declaration type can be shared across threads and holds nothing, and the source
//! holds nothing that can be mutated through a shared reference beyond the door's named,
//! ABI-mandated state. That the door answers the same bytes for the same inputs is its both-ways
//! witness's (`tests/conformance.rs`: the linked and the dropped-in door, two instances, one script,
//! one answer).

use busbar_plane_llm::LlmPlane;
use std::path::{Path, PathBuf};

/// The plane can be registered once and called from every worker.
#[test]
fn the_plane_is_shareable() {
    fn require<T: Send + Sync + 'static>() {}
    require::<LlmPlane>();
}

/// The plane can be copied, which a type holding a cell or a lock cannot be.
///
/// This is the compile-time half of the interior-mutability check: every one of the standard
/// shared-mutation containers is either not `Copy` or not `Sync`, so a plane that grew one would
/// stop satisfying this bound and the build would fail here rather than in production.
#[test]
fn the_plane_is_a_plain_value() {
    fn require<T: Copy + Sync + Send + Eq>() {}
    require::<LlmPlane>();
}

/// The source holds no shared-mutation container and no mutable static.
///
/// The compile-time check above catches a field; this catches one hidden inside a static or behind
/// a type alias, which is the way the property is usually lost.
///
/// EXCEPT `src/codec/`: the dialect codecs.
/// `codec::synth_rng` keeps a `thread_local!` `RefCell<EntropyPool>` for the writers' synthesized
/// wire ids — a per-thread scratch pool, not plane session state, and it predates this test (the
/// codec crate it moved from carried no purity test of this shape). The property this test asserts
/// is about the PLANE — [`LlmPlane`] and its door — never remembering anything BETWEEN calls;
/// the codec is read-only from the plane's own methods and this scan is unchanged for every other
/// file in `src/`.
#[test]
fn the_source_holds_nothing_mutable() {
    let banned = [
        "Cell<",
        "RefCell<",
        "Mutex<",
        "RwLock<",
        "AtomicUsize",
        "AtomicU64",
        "AtomicU32",
        "AtomicBool",
        "OnceLock",
        "OnceCell",
        "LazyLock",
        "static mut",
        "UnsafeCell",
        "thread_local",
    ];
    // THE DOOR'S ABI-MANDATED STATE (ARCHITECT 2026-10-02): the memory-ABI door keeps, per
    // instance, the shaping of its current refresh generation and the table of units in flight
    // across their Ready|Pending calls (the design's plugin ABI: plugin-owned memory, valid to its
    // next refresh generation). These lines are that state, named exactly; anything else in the
    // door, and anything in the plane ([`LlmPlane`]), is still refused.
    const DOOR_STATE: &[(&str, &str)] = &[
        ("plane_door.rs", "shapings: Mutex<"),
        ("plane_door.rs", "units: Mutex<"),
        ("plane_door.rs", "tickets: Mutex<"),
        ("plane_door.rs", "fn guard<T>(m: &Mutex<T>)"),
    ];
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        if path.components().any(|c| c.as_os_str() == "codec") {
            return;
        }
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if DOOR_STATE
                .iter()
                .any(|(file, held)| path.ends_with(file) && trimmed.starts_with(held))
            {
                continue;
            }
            for name in banned {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane's own source can mutate state through a shared reference: {offenders:?}"
    );
}

/// The crate's own source directory.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Walk every source file under a directory.
fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    let entries = std::fs::read_dir(dir).expect("the source directory is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
            f(&path, &text);
        }
    }
}
