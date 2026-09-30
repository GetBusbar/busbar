// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S DOOR, BOTH WAYS, at the composition root, which links the plane.
//! `busbar_plane_a2a::plane_door::door` is loaded LINKED (through `load_linked`) and DROPPED (the
//! `a2a_plane_door_cdylib` example, through `load_dropped`), and ONE script drives the door's
//! lifecycle through the loader's plane kind:
//!
//! * `validate` refuses a bad registration in the grammar's own sentence and accepts a good one;
//! * `open` publishes the first generation's snapshot over the public base URL, `refresh` the next,
//!   each read through the loader's own copy (`Plugin<Plane>::open`/`refresh`), so the test reads
//!   no plugin memory;
//! * `retire` drops the first; `tick`, `drive` and `cancel` answer their dispositions;
//! * every request-path op answers REFUSED (TRANSITIONAL: filled when the kernel's plane driver
//!   serves the request path).
//!
//! The two transcripts must be identical, and the validate refusal must be the exact sentence.

use std::ptr::{null, null_mut};
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut,
};

use crate::root::loader::dispatch::kinds::plane::{OwnedSnapshot, Plane};
use crate::root::loader::dispatch::{
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

/// The host's copy of a snapshot, as one line.
fn snapshot(s: Option<OwnedSnapshot>) -> String {
    let Some(s) = s else {
        return "no snapshot".to_string();
    };
    let mut out = format!(
        "gen={} audience={} metadata={} openapi_bytes={}",
        s.generation,
        s.audience.as_deref().unwrap_or("-"),
        s.resource_metadata.as_deref().unwrap_or("-"),
        s.openapi.as_ref().map_or(0, Vec::len)
    );
    for c in &s.claims {
        out.push_str(&format!(
            " | {} {} {} flags={}",
            c.verb, c.target, c.carrier, c.flags
        ));
    }
    for r in &s.admin_routes {
        out.push_str(&format!(
            " | admin {} {} flags={}",
            r.verb, r.target, r.flags
        ));
    }
    out
}

fn linked() -> Plugin<Plane> {
    load_linked::<Plane>(busbar_plane_a2a::plane_door::door, bind())
        .expect("the linked a2a door loads")
}

/// The example `cdylib` in this target dir. Under CI a missing artifact is a failure, never a skip.
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

fn gen_frame(generation: u64) -> Frame<GenIn, busbar_contract::abi::mechanism::call::OutHead> {
    Frame::new(
        GenIn {
            head: in_head(),
            generation,
        },
        out_head(),
    )
}

/// THE SCRIPT: the lifecycle end to end, then the request path.
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

    let mut o = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                head: in_head(),
                host: null(),
                settings: json(GOOD),
                secrets: null(),
                secrets_len: 0,
                generation: 1,
            },
            public_url: text(PUBLIC),
        },
        PlaneOpenOut {
            open: OpenOut {
                head: out_head(),
                instance: null_mut(),
            },
            snapshot: null(),
        },
    );
    let (c, s) = p.open(&mut o);
    t.push(format!("open {:?} {}", c.outcome, snapshot(s)));

    let mut r = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: json(GOOD),
            secrets: null(),
            secrets_len: 0,
        },
        PlaneRefreshOut {
            head: out_head(),
            snapshot: null(),
        },
    );
    let (c, s) = p.refresh(&mut r);
    t.push(format!("refresh {:?} {}", c.outcome, snapshot(s)));

    t.push(format!(
        "retire 1 {:?}",
        p.call(life::RETIRE, &mut gen_frame(1)).outcome
    ));

    let mut k = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 5,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    );
    let c = p.call(life::TICK, &mut k);
    t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

    let mut d = Frame::new(
        PlaneDriveIn {
            drive: DriveIn {
                head: in_head(),
                driver: Ticket::NONE,
            },
            sessions_buf: null_mut(),
            sessions_cap: 0,
        },
        PlaneDriveOut {
            head: out_head(),
            sessions_written: 0,
            sessions_needed: 0,
        },
    );
    let c = p.call(life::DRIVE, &mut d);
    t.push(format!(
        "drive {:?} sessions={}",
        c.outcome, d.out.sessions_written
    ));

    let mut x = Frame::new(
        CancelIn {
            head: in_head(),
            ticket: Ticket::NONE,
        },
        CancelOut {
            head: out_head(),
            disposition: 0,
            _reserved: 0,
        },
    );
    let c = p.call(life::CANCEL, &mut x);
    t.push(format!(
        "cancel {:?} disposition={}",
        c.outcome, x.out.disposition
    ));

    // The request path, TRANSITIONAL until the kernel's plane driver serves it: every op answers
    // REFUSED.
    let mut a = Frame::new(
        ArriveIn {
            head: in_head(),
            claim: 0,
            _reserved: 0,
            target: text(b"/a2a"),
            fields: null(),
            fields_len: 0,
            body: json(b"{}"),
            units_buf: null_mut(),
            units_cap: 0,
        },
        ArriveOut {
            head: out_head(),
            op_class: 0,
            principal_need: 0,
            dialect: 0,
            units_written: 0,
            units_needed: 0,
            _reserved: 0,
        },
    );
    t.push(format!("arrive {:?}", p.call(slot::ARRIVE, &mut a).outcome));
    for s in [slot::HYDRATE, slot::START] {
        t.push(format!("{s} {:?}", p.call(s, &mut gen_frame(2)).outcome));
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
