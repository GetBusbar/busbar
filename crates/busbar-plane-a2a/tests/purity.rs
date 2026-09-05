//! The plane is pure, and this is what says so.
//!
//! A plane is pure over its inputs and performs no input or output of its own. Those are two
//! separate claims and they are checked two separate ways: the source is walked for the shapes that
//! would make either false, and the methods are driven twice over the same inputs and their answers
//! compared. A comment claiming purity is worth nothing; a scan and a repeat are worth something.

use busbar_contract::plane::{Ingress, Plane, PlaneMeta};
use busbar_contract::wire::FrameCursor;
use busbar_plane_a2a::A2aPlane;
use std::path::{Path, PathBuf};

mod common;
use common::{frame, Scaffold};

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
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
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
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
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
        "busbar_caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_substrate",
        "busbar_core",
        "busbar_plane_llm",
        "busbar_plane_mcp",
    ];
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
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
        "the plane names kernel-side crates: {offenders:?}"
    );
}

/// The decode step gives the same answer every time it is asked the same question.
#[test]
fn the_decode_step_is_deterministic() {
    let plane = A2aPlane::EMPTY;
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
    for body in &bodies {
        let mut answers = Vec::new();
        for _ in 0..8 {
            let scaffold = Scaffold::new("http");
            let ctx = scaffold.ctx();
            let frames = vec![frame(body)];
            let mut cursor = FrameCursor::new(&frames);
            let ingress = plane
                .decode_ingress(&mut cursor, None, &ctx)
                .expect("a known method decodes");
            let summary = match ingress {
                Ingress::Open(d) | Ingress::OneShot(d) => {
                    format!("{:?}/{:?}/{}", d.op, d.correlation_out, d.facts.len())
                }
                other => format!("{other:?}"),
            };
            answers.push(summary);
        }
        assert!(
            answers.windows(2).all(|w| w[0] == w[1]),
            "the decode step varied over one body: {answers:?}"
        );
    }
}

/// The encode step writes the same bytes every time it is asked the same question.
#[test]
fn the_encode_step_is_deterministic() {
    let plane = A2aPlane::EMPTY;
    let answer = br#"{"id":1,"jsonrpc":"2.0","result":{"a":1,"b":2}}"#;
    let mut written = Vec::new();
    for _ in 0..8 {
        let scaffold = Scaffold::new("http");
        let ctx = scaffold.ctx();
        let r = busbar_contract::plane::Response {
            ir: busbar_contract::bounded::Ir::new(answer, &[]),
            finish: busbar_contract::unit::FinishClass::Complete,
            facts: busbar_contract::bounded::Facts::new(),
        };
        let out = plane
            .encode_response(&r, None, &ctx)
            .expect("it re-encodes");
        written.push(out.as_slice().to_vec());
    }
    assert!(
        written.windows(2).all(|w| w[0] == w[1]),
        "the encode step varied over one answer"
    );
}

/// The plane does not read the clock, so a call at a different time gives the same answer.
#[test]
fn the_answer_does_not_move_with_the_clock() {
    let plane = A2aPlane::EMPTY;
    let body = br#"{"jsonrpc":"2.0","id":9,"method":"tasks/get","params":{"id":"t1"}}"#;
    let mut answers = Vec::new();
    for _ in 0..2 {
        let scaffold = Scaffold::new("http");
        let ctx = scaffold.ctx();
        let frames = vec![frame(body)];
        let mut cursor = FrameCursor::new(&frames);
        let Ok(Ingress::OneShot(draft)) = plane.decode_ingress(&mut cursor, None, &ctx) else {
            panic!("a single-answer method decodes as one shot");
        };
        answers.push(format!("{:?}{:?}", draft.op, draft.correlation_out));
    }
    assert_eq!(answers[0], answers[1]);
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
        "bearer_token",
    ];
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
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
