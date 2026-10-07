//! The plane is pure, and this is what says so.
//!
//! A plane is pure over its inputs and performs no input or output of its own. Those are two
//! separate claims and they are checked two separate ways: the source is walked for the shapes that
//! would make either false, and the door's arrival is driven repeatedly over the same inputs and its
//! answers compared. A comment claiming purity is worth nothing; a scan and a repeat are worth something.

use busbar_contract::plane::PlaneMeta;
use busbar_plane_a2a::A2aPlane;
use std::path::{Path, PathBuf};

/// The crate's own source directory.
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

/// THE GENERATED MESSAGES (`build.rs`, the gRPC line's `lf.a2a.v1` package): the plane's source
/// includes them from the build's output directory, so the scans read them as the plane's own
/// source and read the include line itself as what it is, a compile-time inclusion.
const GENERATED: &[&str] = &["lf.a2a.v1.rs", "lf.a2a.v1.serde.rs"];

/// Every source file of the plane: its own, then the generated messages it includes.
fn each_source(f: &mut impl FnMut(&Path, &str)) {
    walk(&src_dir(), f);
    for name in GENERATED {
        let path = Path::new(env!("OUT_DIR")).join(name);
        let text = std::fs::read_to_string(&path).expect("the generated source is readable");
        f(&path, &text);
    }
}

/// The plane's inclusion of one [`GENERATED`] file, whose text [`each_source`] scans in its place.
fn is_generated_include(line: &str) -> bool {
    // The macro's name is spliced in so this file holds no include of its own for a scan of the
    // crate's build inputs to read.
    let t = line.trim();
    GENERATED
        .iter()
        .any(|name| t == format!("{}!(concat!(env!(\"OUT_DIR\"), \"/{name}\"));", "include"))
}

/// A line that is only a comment says nothing about what the code does.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("*") || t.starts_with("/*")
}

/// The plane keeps no state of its own between calls.
///
/// The only place cross-frame codec state may live is the kernel-held per-connection state, which
/// the kernel hands in and takes back. A plane holding a cell, a lock, an atomic or a global is a
/// plane that could answer differently the second time for a reason no caller can see.
#[test]
fn the_plane_holds_no_interior_state() {
    let forbidden = [
        "Cell<",
        "RefCell",
        "UnsafeCell",
        "Mutex<",
        "RwLock",
        "AtomicUsize",
        "AtomicU64",
        "AtomicU32",
        "AtomicBool",
        "OnceLock",
        "OnceCell",
        "LazyLock",
        "lazy_static",
        "thread_local",
        "static mut",
    ];
    let mut offenders = Vec::new();
    each_source(&mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) || is_generated_include(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane holds interior state: {offenders:?}"
    );
}

/// The plane performs no input and no output.
///
/// Not a socket, not a file, not a process, not a thread, not a system clock. The one clock a plane
/// may read is the one the context hands it, which is why the system clock is on this list.
#[test]
fn the_plane_performs_no_input_or_output() {
    let forbidden = [
        "std::fs",
        "std::net",
        "std::process",
        "std::thread",
        "std::io",
        "SystemTime",
        "Instant::now",
        "tokio",
        "reqwest",
        "async fn",
        "await",
        "env!",
        "std::env",
        "println!",
        "eprintln!",
    ];
    let mut offenders = Vec::new();
    each_source(&mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) || is_generated_include(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane reaches outside itself: {offenders:?}"
    );
}

/// The plane names no kernel-side crate.
///
/// The manifest allow-list is the real control; this is the same rule asserted from the inside, so a
/// reach for the kernel is a red here rather than a discovery at packaging time.
#[test]
fn the_plane_names_no_kernel_side_crate() {
    let forbidden = [
        "busbar_contract::caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_substrate",
    ];
    let mut offenders = Vec::new();
    each_source(&mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) || is_generated_include(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
            // No plane names a sibling plane crate — same broker law (DECISION #8) as the
            // manifest-level check in `tests/invariance.rs`, asserted here from the source side.
            // A prefix over the whole `busbar_plane_` family covers every sibling plane, present
            // or future, rather than naming siblings one at a time.
            if line.contains("busbar_plane_") {
                offenders.push(format!("{}:{}: busbar_plane_", path.display(), n + 1));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane names kernel-side crates: {offenders:?}"
    );
}

/// The door's arrival gives the same answer every time it is asked the same question.
#[test]
fn the_arrival_is_deterministic() {
    let bodies: Vec<Vec<u8>> = A2aPlane::OP_CLASSES
        .iter()
        .filter_map(|op| busbar_plane_a2a::ops::METHODS.iter().find(|r| r.op == *op))
        .map(|row| {
            format!(
                r#"{{"jsonrpc":"2.0","id":5,"method":"{}","params":{{"id":"t1"}}}}"#,
                row.method
            )
            .into_bytes()
        })
        .collect();
    // The bodies are DERIVED — a filter over one declared table looked up in another — so an
    // op class dropped from the first, or a method row dropped from the second, empties this
    // vector and the loop below runs zero times. A determinism test that examined nothing would
    // report `ok`, which is the shape this assertion exists to make impossible.
    assert!(
        !bodies.is_empty(),
        "no request body was derived from the declared op classes, so nothing was driven twice"
    );
    for body in &bodies {
        let answers: Vec<String> = (0..8)
            .map(|_| format!("{:?}", busbar_plane_a2a::arrival::decide(body, |_| None)))
            .collect();
        assert!(
            answers.windows(2).all(|w| w[0] == w[1]),
            "the arrival varied over one body: {answers:?}"
        );
    }
}

/// The plane never hands back a decision, an amount or a credential.
///
/// This is a source scan for the words a plane must not be able to say. It is coarse on purpose: a
/// plane that has started reasoning about money will name money.
#[test]
fn the_plane_names_no_money_and_no_decision() {
    let forbidden = [
        "nano_units",
        "nanounits",
        "unit_price",
        "price_micros",
        "charge(",
        "admit_decision",
        "allow(",
        "deny(",
        "credential_bytes",
        "secret_value",
        "auth_token_raw",
    ];
    let mut offenders = Vec::new();
    each_source(&mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) || is_generated_include(line) {
                continue;
            }
            // A lint attribute is an instruction to the compiler, not a decision about a
            // request. It is the one shape here whose words overlap with the forbidden ones.
            let t = line.trim_start();
            if t.starts_with("#[") || t.starts_with("#![") {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane names money or decisions: {offenders:?}"
    );
}

/// THE PUSH TOKEN IS NEVER LOGGED (`BUSBAR-1.6.0.md` l.4882: the plane checks its own callback
/// correlation token, "never logged/audited"; the push route is audited nowhere, the door's own
/// cell): no diagnostic line the plane writes, in any of its sources, names the token, the field
/// it rides in, or a value read from either.
#[test]
fn no_diagnostic_line_of_the_plane_carries_the_push_token() {
    let mut lines = 0;
    each_source(&mut |path, text| {
        for (start, _) in text.match_indices("diag_") {
            let rest = &text[start..];
            let Some(open) = rest.find("!(").filter(|o| {
                rest[..*o]
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
            }) else {
                continue;
            };
            // The call's arguments, to the parenthesis that closes them.
            let mut depth = 0usize;
            let close = rest[open + 1..]
                .char_indices()
                .find(|(_, c)| {
                    match c {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    depth == 0
                })
                .map_or(rest.len(), |(i, _)| open + 1 + i);
            let call = rest[open..close].to_ascii_lowercase();
            lines += 1;
            for word in ["token", "authorization", "presented", "claim"] {
                assert!(
                    !call.contains(word),
                    "{}: a diagnostic line names `{word}`: {call}",
                    path.display()
                );
            }
        }
    });
    assert!(lines > 0, "the scan read the plane's diagnostic lines");
}

/// THE PLANE DECLARES NO TRUST STATE OF ITS OWN.
///
/// Ported from the deleted engine crate's `reuse_tests::the_a2a_plane_declares_no_trust_state_of_its_own`.
/// The trust lifecycle (the states, the drift, the approval, the pinned artifact and the verbs that
/// move a registration through them) is the kernel's, written once and plane-neutral. The plane
/// contributes its report types (`Sighting`, `Observation`: what a look saw) and parameterises the
/// machine over them; a second declaration of the machine here is a fork, and two machines disagree
/// the first time one of them is fixed. The sources are enumerated off disk (a hand-kept file list
/// silently stops covering the newest code), and a scan that finds nothing is a failure, not a pass.
#[test]
fn the_a2a_plane_declares_no_trust_state_of_its_own() {
    const BANNED: &[&str] = &[
        "enum TrustState",
        "enum Drift",
        "struct Approval",
        "trait PinnedArtifact",
        "fn serves",
        "fn suspend",
        "fn resume",
        "fn unpin",
    ];
    let mut scanned = 0usize;
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        scanned += 1;
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for needle in BANNED {
                if line.contains(needle) {
                    offenders.push(format!("{}:{}: `{needle}`", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        scanned >= 4,
        "the scan found {scanned} source file(s), which cannot be right: a scan that discovers \
         nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "the plane forks the trust machine, which is the kernel's and plane-neutral: {offenders:?}"
    );
}
