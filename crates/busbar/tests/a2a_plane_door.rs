// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S DOOR, BOTH WAYS, at the composition root, which links the plane. `busbar_plane_a2a::plane_door::door` is loaded LINKED
//! (through [`load_linked`]) and DROPPED (the `a2a_plane_door_cdylib` example, through
//! [`load_dropped`]), and ONE script drives the door's lifecycle through the loader's plane kind:
//! `validate` refuses a bad registration in the grammar's own sentence and accepts a good one,
//! `open` publishes the first generation's snapshot over the public base URL, `refresh` the next,
//! `retire` drops the first, `tick`/`drive`/`cancel` answer their dispositions, and every
//! request-path op answers REFUSED (TRANSITIONAL: filled when the kernel's plane driver serves the request path). The two transcripts must be
//! identical, and the validate refusal must be the exact sentence.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut, PlaneSnapshot,
};

use busbar_plugin_loader::dispatch as loader;
use loader::kinds::plane::Plane;
use loader::{
    in_head, load_dropped, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame,
    ManifestFacts, NoSink, Plugin,
};

/// The settings the script opens with: one fronted agent.
const GOOD: &[u8] =
    br#"{"vendor": {"url": "https://vendor.example/a2a", "pin": {"mechanism": "unpinned"}}}"#;
/// A registration the grammar refuses.
const BAD: &[u8] =
    br#"{"vendor": {"url": "ftp://vendor.example", "pin": {"mechanism": "unpinned"}}}"#;
/// The grammar's own sentence for [`BAD`] (the predev refusal bytes).
const BAD_SENTENCE: &str =
    "`agents.vendor`: `url:` must be an http:// or https:// endpoint, got `ftp://vendor.example`";
/// The deployment's public base URL.
const PUBLIC: &[u8] = b"https://gw.example";

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

/// The one dispatcher both doors bind to, held for the test binary's life.
fn dispatcher() -> &'static Dispatcher {
    static ONE: std::sync::OnceLock<Dispatcher> = std::sync::OnceLock::new();
    ONE.get_or_init(|| Dispatcher::new(DispatchConfig::default()))
}

fn bind() -> Bind {
    Bind {
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher().adopter(),
    }
}

fn json(b: &'static [u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn text(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

/// A string the plugin published, read while its generation is live.
fn read(s: AbiStr) -> String {
    if s.ptr.is_null() {
        return "-".to_string();
    }
    // SAFETY: generation data, valid until `retire` of its generation.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

/// A published snapshot, read in full while its generation is live.
fn snapshot(p: *const PlaneSnapshot) -> String {
    assert!(!p.is_null(), "a READY open/refresh publishes a snapshot");
    // SAFETY: the plugin's generation data, valid until `retire` of its generation.
    let s = unsafe { &*p };
    // SAFETY: the snapshot names `claims_len` claims and `admin_routes_len` admin routes.
    let claims = unsafe { std::slice::from_raw_parts(s.claims, s.claims_len) };
    let routes = unsafe { std::slice::from_raw_parts(s.admin_routes, s.admin_routes_len) };
    let mut out = format!(
        "gen={} audience={} metadata={} openapi_bytes={}",
        s.generation,
        read(s.audience),
        read(s.resource_metadata),
        s.openapi.len
    );
    for c in claims {
        out.push_str(&format!(
            " | {} {} {} flags={}",
            read(c.verb),
            read(c.target),
            read(c.carrier),
            c.flags
        ));
    }
    for r in routes {
        out.push_str(&format!(
            " | admin {} {} flags={}",
            read(r.verb),
            read(r.target),
            r.flags
        ));
    }
    out
}

fn linked() -> Plugin<Plane> {
    load_linked::<Plane>(busbar_plane_a2a::plane_door::door, bind())
        .expect("the linked a2a door loads")
}

/// The example `cdylib` in this target dir (`cargo test` builds examples). Under CI a missing
/// artifact is a failure, never a skip.
fn dropped() -> Option<Plugin<Plane>> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("examples").join(format!(
        "{}a2a_plane_door_cdylib{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    assert!(
        path.exists() || std::env::var_os("CI").is_none(),
        "the a2a_plane_door_cdylib example is not built under CI; a both-ways proof must not skip"
    );
    let facts = ManifestFacts {
        mechanism_version: MECHANISM_VERSION,
        kind: KindCode::Plane,
        kind_abi: KindCode::Plane.abi_version(),
    };
    path.exists()
        .then(|| load_dropped::<Plane>(&path, &facts, bind()).expect("the dropped a2a door loads"))
}

/// THE SCRIPT: the lifecycle end to end, then every request-path op once.
fn script(p: &Plugin<Plane>) -> Vec<String> {
    let mut t = Vec::new();

    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(BAD),
        },
        out_head(),
    );
    let c = p.call(life::VALIDATE, &mut v);
    t.push(format!(
        "validate bad {:?} {}",
        c.outcome,
        String::from_utf8_lossy(&c.error.unwrap_or_default())
    ));
    v.input.settings = json(GOOD);
    t.push(format!(
        "validate {:?}",
        p.call(life::VALIDATE, &mut v).outcome
    ));

    let mut o: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(z(), z());
    (o.input.open.head, o.out.open.head) = (in_head(), out_head());
    o.input.open.generation = 1;
    o.input.open.settings = json(GOOD);
    o.input.public_url = text(PUBLIC);
    let c = p.call(life::OPEN, &mut o);
    t.push(format!("open {:?} {}", c.outcome, snapshot(o.out.snapshot)));

    let mut r: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
    (r.input.head, r.out.head) = (in_head(), out_head());
    r.input.generation = 2;
    r.input.settings = json(GOOD);
    let c = p.call(life::REFRESH, &mut r);
    t.push(format!(
        "refresh {:?} {}",
        c.outcome,
        snapshot(r.out.snapshot)
    ));

    let mut g = Frame::new(
        GenIn {
            head: in_head(),
            generation: 1,
        },
        out_head(),
    );
    t.push(format!(
        "retire 1 {:?}",
        p.call(life::RETIRE, &mut g).outcome
    ));

    let mut k: Frame<TickIn, TickOut> = Frame::new(z(), z());
    (k.input.head, k.out.head) = (in_head(), out_head());
    k.input.now_ns = 5;
    let c = p.call(life::TICK, &mut k);
    t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

    let mut d: Frame<PlaneDriveIn, PlaneDriveOut> = Frame::new(z(), z());
    (d.input.drive.head, d.out.head) = (in_head(), out_head());
    let c = p.call(life::DRIVE, &mut d);
    t.push(format!(
        "drive {:?} sessions={}",
        c.outcome, d.out.sessions_written
    ));

    let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
    (x.input.head, x.out.head) = (in_head(), out_head());
    let c = p.call(life::CANCEL, &mut x);
    t.push(format!(
        "cancel {:?} disposition={}",
        c.outcome, x.out.disposition
    ));

    // The request path, TRANSITIONAL until the kernel's plane driver serves it: every op answers
    // REFUSED.
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    (a.input.head, a.out.head) = (in_head(), out_head());
    t.push(format!("arrive {:?}", p.call(slot::ARRIVE, &mut a).outcome));
    for s in [slot::HYDRATE, slot::START] {
        let mut g = Frame::new(
            GenIn {
                head: in_head(),
                generation: 2,
            },
            out_head(),
        );
        t.push(format!("{s} {:?}", p.call(s, &mut g).outcome));
    }
    t
}

#[test]
fn the_a2a_door_answers_identically_linked_and_dropped_in() {
    let linked = script(&linked());
    assert_eq!(
        linked[0],
        format!("validate bad {:?} {BAD_SENTENCE}", Outcome::Refused),
        "the door refuses in the grammar's own sentence"
    );
    assert!(
        linked[2].starts_with(&format!(
            "open {:?} gen=1 audience=https://gw.example/a2a",
            Outcome::Ready
        )),
        "{}",
        linked[2]
    );
    assert!(
        linked[3].starts_with(&format!("refresh {:?} gen=2", Outcome::Ready)),
        "{}",
        linked[3]
    );
    if let Some(dropped) = dropped() {
        assert_eq!(
            script(&dropped),
            linked,
            "linked and dropped-in answer alike"
        );
    }
}
