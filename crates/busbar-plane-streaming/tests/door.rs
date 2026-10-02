// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAMING PLANE'S DOOR, BOTH WAYS: the same door compiled in (`door::door`, through the
//! loader's `load_linked`) and dropped in (the `streaming_door` example `cdylib` `cargo test` builds,
//! through `load_dropped`), driven by ONE script over the loader's plane kind. Every answer is judged
//! by the kind's own checks on the way; the two transcripts must be identical, and each is pinned.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot,
    CANCEL_FAILED, CLAIM_EXACT, CLAIM_OPEN,
};
use busbar_plane_streaming::door;
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame,
    ManifestFacts, NoSink, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
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

fn text(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn read(s: AbiStr) -> String {
    if s.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the plugin's text, valid while its generation is live.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

/// A published snapshot, read while its generation is live: its generation, its claims
/// (`verb target carrier exact?`) and the audience and metadata it binds.
fn snapshot(p: *const PlaneSnapshot) -> String {
    assert!(!p.is_null(), "a READY open/refresh publishes a snapshot");
    // SAFETY: the plugin's generation data, valid until `retire` of its generation.
    let s = unsafe { &*p };
    let claims: Vec<String> = (0..s.claims_len)
        .map(|i| {
            // SAFETY: the snapshot names `claims_len` claims.
            let c = unsafe { &*s.claims.add(i) };
            format!(
                "{} {} {}{}{}",
                read(c.verb),
                read(c.target),
                read(c.carrier),
                if c.flags & CLAIM_EXACT != 0 { " exact" } else { "" },
                if c.flags & CLAIM_OPEN != 0 { " open" } else { "" }
            )
        })
        .collect();
    format!(
        "gen={} claims=[{}] audience={} metadata={} routes={}",
        s.generation,
        claims.join(", "),
        read(s.audience),
        read(s.resource_metadata),
        s.admin_routes_len
    )
}

fn linked(d: &Dispatcher) -> Plugin<Plane> {
    load_linked::<Plane>(door::door, bind(d)).expect("the linked streaming door loads")
}

/// The example `cdylib` in this target dir (`cargo test` builds examples). Under CI a missing
/// artifact is a failure, never a skip.
fn dropped(d: &Dispatcher) -> Option<Plugin<Plane>> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("examples").join(format!(
        "{}streaming_door{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    assert!(
        path.exists() || std::env::var_os("CI").is_none(),
        "the streaming_door example cdylib is not built under CI; a both-ways proof must not skip"
    );
    let facts = ManifestFacts {
        mechanism_version: MECHANISM_VERSION,
        kind: KindCode::Plane,
        kind_abi: KindCode::Plane.abi_version(),
    };
    path.exists().then(|| {
        load_dropped::<Plane>(&path, &facts, bind(d)).expect("the dropped streaming door loads")
    })
}

fn validate(p: &Plugin<Plane>, settings: &'static [u8]) -> Outcome {
    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(settings),
        },
        out_head(),
    );
    p.call(life::VALIDATE, &mut v).outcome
}

fn open(
    p: &Plugin<Plane>,
    generation: u64,
    settings: &'static [u8],
    public_url: Option<&'static str>,
) -> (Outcome, String) {
    let mut i: PlaneOpenIn = z();
    i.open.head = in_head();
    i.open.generation = generation;
    i.open.settings = json(settings);
    if let Some(u) = public_url {
        i.public_url = text(u);
    }
    let mut o: PlaneOpenOut = z();
    o.open.head = out_head();
    let mut f = Frame::new(i, o);
    let c = p.call(life::OPEN, &mut f);
    let snap = if c.outcome == Outcome::Ready {
        snapshot(f.out.snapshot)
    } else {
        String::new()
    };
    (c.outcome, snap)
}

/// THE SCRIPT: the lifecycle over two generations, then one unit offered to the door.
fn script(p: &Plugin<Plane>, public_url: Option<&'static str>) -> Vec<String> {
    let mut t = Vec::new();
    t.push(format!(
        "validate unknown key {:?}",
        validate(p, br#"{"nonsense_key":1}"#)
    ));
    t.push(format!(
        "validate zero ceiling {:?}",
        validate(p, br#"{"session_max_secs":0}"#)
    ));
    t.push(format!("validate empty {:?}", validate(p, b"")));
    t.push(format!(
        "validate ceiling {:?}",
        validate(p, br#"{"session_max_secs":1800}"#)
    ));

    let (outcome, snap) = open(p, 1, br#"{"session_max_secs":1800}"#, public_url);
    t.push(format!("open {outcome:?} {snap}"));

    let mut r = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: json(b"{}"),
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        PlaneRefreshOut {
            head: out_head(),
            snapshot: std::ptr::null(),
        },
    );
    let c = p.call(life::REFRESH, &mut r);
    t.push(format!("refresh {:?} {}", c.outcome, snapshot(r.out.snapshot)));

    let mut g = Frame::new(
        GenIn {
            head: in_head(),
            generation: 1,
        },
        out_head(),
    );
    t.push(format!("retire 1 {:?}", p.call(life::RETIRE, &mut g).outcome));

    for claim in [3, 5, 9] {
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        a.input.head = in_head();
        a.input.claim = claim;
        a.out.head = out_head();
        let c = p.call(slot::ARRIVE, &mut a);
        t.push(format!(
            "arrive {claim} {:?} dialect={} op={} principal={}",
            c.outcome, a.out.dialect, a.out.op_class, a.out.principal_need
        ));
    }

    let mut k: Frame<TickIn, TickOut> = Frame::new(z(), z());
    k.input.head = in_head();
    k.input.now_ns = 5;
    k.out.head = out_head();
    let c = p.call(life::TICK, &mut k);
    t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

    let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
    x.input.head = in_head();
    x.out.head = out_head();
    let c = p.call(life::CANCEL, &mut x);
    t.push(format!(
        "cancel {:?} failed={}",
        c.outcome,
        x.out.disposition == CANCEL_FAILED
    ));
    t
}

const PUBLIC: &str = "https://gw.example.com/ignored?q=1#f";

fn expected(public: bool) -> Vec<String> {
    let doors = "POST /v1/realtime/client_secrets http exact, POST /v1/realtime/calls http exact, \
                 GET /v1/realtime/sideband/{call_id} ws, GET /v1/realtime/gemini/{call_id} ws, \
                 GET /twilio/{call_id} ws, \
                 GET /.well-known/oauth-protected-resource/v1/realtime http exact open";
    let (claims, audience, metadata) = if public {
        (
            doors,
            "https://gw.example.com/v1/realtime",
            "https://gw.example.com/.well-known/oauth-protected-resource/v1/realtime",
        )
    } else {
        ("", "", "")
    };
    let snap = |g: u64| {
        format!("gen={g} claims=[{claims}] audience={audience} metadata={metadata} routes=0")
    };
    vec![
        "validate unknown key Refused".into(),
        "validate zero ceiling Refused".into(),
        "validate empty Ready".into(),
        "validate ceiling Ready".into(),
        format!("open Ready {}", snap(1)),
        format!("refresh Ready {}", snap(2)),
        "retire 1 Ready".into(),
        "arrive 3 Ready dialect=1 op=0 principal=1".into(),
        "arrive 5 Ready dialect=0 op=0 principal=0".into(),
        "arrive 9 Refused dialect=0 op=0 principal=0".into(),
        "tick Ready next=0".into(),
        "cancel Ready failed=true".into(),
    ]
}

#[test]
fn the_linked_door_states_the_planes_doors_under_its_public_url() {
    let d = Dispatcher::new(DispatchConfig::default());
    assert_eq!(script(&linked(&d), Some(PUBLIC)), expected(true));
}

#[test]
fn a_deployment_with_no_public_url_is_claimed_by_no_door() {
    let d = Dispatcher::new(DispatchConfig::default());
    assert_eq!(script(&linked(&d), None), expected(false));
}

#[test]
fn the_dropped_door_answers_as_the_linked_door_does() {
    let d = Dispatcher::new(DispatchConfig::default());
    let Some(dropped) = dropped(&d) else {
        eprintln!("skip: the streaming_door example cdylib is not built");
        return;
    };
    for url in [Some(PUBLIC), None] {
        assert_eq!(
            script(&dropped, url),
            script(&linked(&d), url),
            "the two doors must answer identically"
        );
    }
}

#[test]
fn the_tail_states_what_the_served_plane_declares() {
    // The billable classes a session counts in, the per-session fee and the `session` grant kind:
    // the served plane's own declaration, read off the tail the door states.
    let t = door::TAIL;
    assert_eq!(read(t.scope), "session");
    assert_eq!(read(t.audit_kind), "streaming_session");
    // SAFETY: the tail's `'static` lists.
    let classes: Vec<String> = unsafe { std::slice::from_raw_parts(t.billable_classes, t.billable_classes_len) }
        .iter()
        .map(|c| format!("{}/{}", read(c.class), read(c.family)))
        .collect();
    assert_eq!(
        classes,
        [
            "audio_tokens_in/token",
            "audio_tokens_out/token",
            "text_tokens_in/token",
            "text_tokens_out/token",
            "audio_seconds_in/duration",
            "tool_calls/count",
        ]
    );
    // SAFETY: as above.
    let fees: Vec<String> = unsafe { std::slice::from_raw_parts(t.fee_units, t.fee_units_len) }
        .iter()
        .map(|f| read(*f))
        .collect();
    assert_eq!(fees, ["per_session"]);
    busbar_contract::abi::plane::check::check_tail(t).expect("the kind's own check admits the tail");
}
