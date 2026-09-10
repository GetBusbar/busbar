// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PREMISE UNDER TWO MOVED MONEY CELLS, PINNED INSTEAD OF ASSERTED.**
//!
//! The landing that made the kernel's contradiction arm reachable moved two counts. `units_a2a`
//! and `units_voice` each pinned a relayed answer with an error finish at ZERO — the plane's finish
//! deciding alone, because the leg had told the kernel there was no status leg to reconcile it
//! against — and both now read ONE and disputed, which is the ruled policy applied to a
//! contradiction those legs can produce.
//!
//! That move was defended by one sentence: *neither leg serves a byte today*. It is true. It is
//! also, as written, a sentence — and a sentence is not a gate. The day a line switches either leg
//! onto the wire, two counts that today describe an unreachable code path become live billed
//! amounts, and nothing in the tree would say so. `root-a2a` is DEFAULT ON, which makes this closer
//! than it reads: what keeps that leg off the wire is not a feature flag, it is the internal fact
//! that the serving path is still the one the plugin mounts.
//!
//! So the sentence becomes assertions, and they are made against the tree's own source rather than
//! against a comment about it.
//!
//! # WHAT REDS, AND WHAT THE PERSON WHO REDDENS IT OWES
//!
//! Whoever switches either leg to serve will trip this cell. What is owed then is not a nudge to
//! this file's allow-lists: it is the money question these assertions are standing in front of —
//! **what does a contradicted fee cost on a plane that is now billing real callers?** — answered
//! deliberately, under the tariff, with the two moved cells re-decided rather than quietly going
//! live. Editing the lists below and moving on is the one response that defeats the purpose of
//! having written them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The workspace root, from this crate's manifest directory.
fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> sits two levels under the workspace root")
        .to_path_buf()
}

/// Every `.rs` file under a directory, in a stable order.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("a directory this repo has") {
            let path = entry.expect("a readable entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The path as the repository spells it, so a failure names a file somebody can open.
fn repo_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Which files under the composition root's `src/` name a given symbol.
///
/// The legs' own proofs live under `src/root/tests/` and `src/root/units_admin/tests/`, which are
/// test-classified paths: a cell that drives a leg's decider is exactly what this landing added,
/// and counting it here would make the guard fight the proofs.
fn root_files_naming(symbol: &str) -> BTreeSet<String> {
    let root = workspace();
    let src = root.join("crates/busbar/src");
    rust_files(&src)
        .into_iter()
        .filter(|p| {
            let s = repo_path(&root, p);
            !s.contains("/tests/")
        })
        .filter(|p| {
            std::fs::read_to_string(p)
                .expect("a readable source file")
                .contains(symbol)
        })
        .map(|p| repo_path(&root, &p))
        .collect()
}

/// **THE TWO LEGS ARE NAMED BY NOBODY WHO COULD SERVE THROUGH THEM.**
///
/// A leg reaches a client's bytes only if something constructs its `Units` implementor. Both
/// implementors are named in exactly one production file each — their own — so there is no site at
/// which a request could enter either leg's step loop, and therefore no site at which either leg's
/// `fee_evidence` is built for a real caller.
///
/// This is the assertion `main.rs` would break first: switching a leg on means naming its unit type
/// where the listeners are assembled, and that is a file this set does not contain.
#[test]
fn the_a2a_and_voice_legs_are_constructed_by_no_production_file_but_their_own() {
    for (symbol, own_file) in [
        ("A2aUnits", "crates/busbar/src/root/units_a2a.rs"),
        ("VoiceUnit", "crates/busbar/src/root/units_voice.rs"),
    ] {
        let naming = root_files_naming(symbol);
        let expected: BTreeSet<String> = [own_file.to_string()].into_iter().collect();
        assert_eq!(
            naming, expected,
            "`{symbol}` is named outside its own leg, which is how a leg starts serving. Two \
             counts in that leg's cells were moved on the premise that it serves nothing — read \
             this file's header before touching this line"
        );
    }
}

/// **THE KERNEL'S LOOP IS ENTERED FROM THREE PLACES ON A DEFAULT BUILD, AND NEITHER LEG IS ONE.**
///
/// The second, independent reading of the same fact, taken from the other end: rather than asking
/// who names the legs, ask who enters the loop at all. `harness.rs` is in the list and is not a
/// fourth answer — it is `#[cfg(any(test, feature = "test-harness"))]`, so it is in no shipped
/// binary; it is listed rather than filtered out because a guard that hid a file would be a guard
/// somebody could hide a leg behind.
#[test]
fn the_kernels_loop_is_entered_from_three_production_files_and_one_test_harness() {
    let entering = root_files_naming("teller::run_unit");
    let expected: BTreeSet<String> = [
        // The transport ingress driver, over `ProductionUnits` — which refuses every non-admin step.
        "crates/busbar/src/root/transports.rs",
        // The llm plane: the one leg that serves through the loop today.
        "crates/busbar/src/root/units_llm.rs",
        // The admin surface's mount.
        "crates/busbar/src/root/units_admin/admin_mount.rs",
        // Not shipped: `#[cfg(any(test, feature = "test-harness"))]` at root/mod.rs.
        "crates/busbar/src/root/harness.rs",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(
        entering, expected,
        "somebody entered the kernel's step loop from a file that did not before. If it is a leg \
         whose fee cells were moved on the premise that it serves nothing, the money question \
         those cells are standing in front of has to be answered before this line lands"
    );
}

/// **THE STREAMS PLANE HAS A SECOND DOOR, AND IT IS SHUT BY DEFAULT.**
///
/// Independent of anything the composition root does, the voice plane mounts no dispatch slot
/// without a deployment `public_url` — and with no slot, every `WsArrivalSpec` the root installed
/// is dropped where the router looks the slot up. Recorded rather than argued: a boot of this
/// tree's own binary with a `streams:` section and no `public_url` answers 401 to an anonymous
/// caller and 404 to an admitted one on all seven of the plane's declared paths, and the 404 is
/// born at router build rather than on the request path.
///
/// Both halves of that are pinned here as the SHAPE of the two lines that produce it. A shape
/// rather than a behaviour because the behaviour needs a booted node and this is the guard that
/// runs on every build; if either line changes, the recorded boot above stops describing the tree
/// and the premise wants re-measuring, which is exactly the signal worth having.
#[test]
fn the_streams_planes_dispatch_slot_still_requires_a_public_url() {
    let root = workspace();

    let mount = std::fs::read_to_string(root.join("crates/busbar-voice/src/mount.rs"))
        .expect("the streams plane's mount");
    assert!(
        mount
            .contains("pub fn voice_build(ctx: &BuildCtx) -> Option<Arc<dyn Any + Send + Sync>> {")
            && mount.contains("let public = ctx.public_url?;"),
        "the streams plane's dispatch slot no longer opens on the deployment's receiving origin; \
         the boot that recorded this plane answering nothing no longer describes this tree"
    );

    let router = std::fs::read_to_string(root.join("crates/busbar-core/src/router.rs"))
        .expect("the legacy router");
    assert!(
        router.contains("let Some(slot) = plane_slots.get(slot_key) else {"),
        "the arrival specs the root installs are no longer dropped on a missing slot; a spec that \
         now reaches a slot is a plane that now answers, and the two moved fee cells in \
         units_voice describe a leg that does not"
    );
}
