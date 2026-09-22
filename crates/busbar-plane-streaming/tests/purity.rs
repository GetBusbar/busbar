//! Purity gates: the properties every plane in the design is held to — pure over its inputs, no input
//! or output of its own, no interior-mutable state across calls — checked here rather than asserted in
//! prose. The streaming plane inherits its behaviour from the voice adapter, so it must inherit the
//! purity too: a wrapper that added a cell, a lock or an atomic would be a plane that kept state of its
//! own across calls, and the whole point of the reframe is that it does not.

use busbar_contract::ids::LaneId;
use busbar_plane_streaming::{Dialect, StreamingPlane, Upstream};

/// `StreamingPlane` derives `Copy`. Every interior-mutable cell (`Cell`, `RefCell`, `Mutex`,
/// `OnceLock`, ...) is `!Copy`, so a type that IS `Copy` structurally cannot hold one: a compile-time
/// proof, not a convention, that the plane keeps no mutable state of its own across calls. Everything
/// that varies across a session lives in the kernel-held `PlaneSessionState` the adapter opens.
const fn assert_copy<T: Copy>() {}
const _: () = assert_copy::<StreamingPlane>();

/// A plane is shared across every concurrent connection the kernel drives, so it must be `Send + Sync`;
/// it is held for the life of the program, so it must be `'static`. Asserted structurally.
const fn assert_shareable<T: Send + Sync + 'static>() {}
const _: () = assert_shareable::<StreamingPlane>();

/// Two planes built from the same upstream list compare equal, and looking up the same dialect twice
/// gives the same answer — a pure function of `self.upstreams()` and the argument.
#[test]
fn same_configuration_answers_the_same_way_every_time() {
    static UPSTREAMS: &[Upstream] = &[Upstream {
        lane: LaneId::new("realtime"),
        host: "api.openai.example",
        dialect: Dialect::OpenaiRealtime,
    }];
    let a = StreamingPlane::new(UPSTREAMS);
    let b = StreamingPlane::new(UPSTREAMS);
    assert_eq!(a, b);
    assert_eq!(
        a.upstream_for_dialect(Dialect::OpenaiRealtime),
        b.upstream_for_dialect(Dialect::OpenaiRealtime)
    );
    assert_eq!(a.upstream_for_dialect(Dialect::GeminiLive), None);
}

/// A plane with nothing configured answers every dialect lookup with `None` rather than panicking or
/// fabricating a host — the honest answer for a plane with no upstream.
#[test]
fn empty_plane_names_no_upstream() {
    assert!(StreamingPlane::EMPTY
        .upstream_for_dialect(Dialect::OpenaiRealtime)
        .is_none());
    assert_eq!(StreamingPlane::EMPTY, StreamingPlane::default());
}

/// The plane is registered under its own KEY, and never under "voice": the plane is streaming and the
/// realtime voice dialect is one dialect under it.
#[test]
fn the_plane_key_is_streaming_never_voice() {
    use busbar_contract::plane::PlaneMeta;
    use busbar_contract::plugin::Plugin;
    assert_eq!(<StreamingPlane as PlaneMeta>::KEY, "streaming");
    assert_eq!(StreamingPlane::EMPTY.key(), "streaming");
    assert_ne!(<StreamingPlane as PlaneMeta>::KEY, "voice");
}

// ── THE KERNEL-SIDE FORBID LIST ───────────────────────────────────────────────────────────────
//
// Its four sibling planes (`busbar-plane-a2a`, `-mcp`, `-llm`, `-decision`) each carry this test.
// THIS CRATE DID NOT, and the asymmetry was invisible because the rule it asserts was green
// anyway — so nothing pointed at the gap, and a reach landing here would have been the first
// thing to notice it. The manifest allow-list is the real control; this is the same rule asserted
// from the INSIDE, so a reach for the kernel is a red here rather than a discovery at packaging.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Walk every source file, handing each to a reader.
fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    for entry in std::fs::read_dir(dir)
        .expect("the source directory is readable")
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
            f(&path, &text);
        }
    }
}

/// A line that is only a comment says nothing about what the code does.
///
/// LOAD-BEARING HERE, not decoration: this crate's headers legitimately DISCUSS the kernel and its
/// sibling planes — `lib.rs:35` names the older `busbar_kernel::plane::registry::PlaneDecl`
/// architecture it is not built on, `claims.rs:117` cites `busbar_plane_llm`'s ladder, and
/// `governed.rs:10/18` explain the dependency inversion by naming `busbar_voice::runtime`. Every
/// one is prose about what this plane does NOT do. A gate its own explanation fails is a gate
/// somebody deletes.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*') || t.starts_with("/*")
}

/// The plane names no kernel-side crate, and no sibling plane.
///
/// `busbar_voice::` carries its `::` on purpose. The bare stem would match `busbar_voice_codec`,
/// which is this crate's own WIRE DIALECT and a declared dependency (`Cargo.toml`) — banning it
/// would ban the thing the plane is built out of. The path separator is what distinguishes
/// reaching into the legacy voice ENGINE from using the codec.
#[test]
fn the_plane_names_no_kernel_side_crate() {
    let forbidden = [
        "busbar_contract::caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_substrate",
        "busbar_voice::",
        "busbar_plane_llm",
        "busbar_plane_mcp",
        "busbar_plane_a2a",
        "busbar_plane_decision",
    ];
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the streaming plane reaches a kernel-side crate or a sibling plane: {offenders:#?}"
    );
}
