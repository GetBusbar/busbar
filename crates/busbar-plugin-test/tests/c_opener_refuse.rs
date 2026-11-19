// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OPENER-REFUSE (ABI-MIN3-INTERFACE §14): Plane `request`/`probe` and transport `begin` refusing: `(None,
//! answer)`, no cancel, no session counted.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! W1-H1: the openers are the typed session proxies of IF §10.4 (`plane::Proxy::request`/`probe`,
//! `transport::Proxy::begin`, over busbar-ffi's `Instance`/`Session`), bound to a `plugin!` fixture of the real
//! plane and transport kinds. The host-side instance is built from its public parts exactly as the registry builds
//! it after INSTANCE (`driver::Instance::new`), so the arm drives the proxies themselves, not a port over them.
//! "No session counted" is read from the session table the shim keeps: a refused opener inserts nothing, so the
//! next session it mints carries the very token a fresh instance mints first. "No cancel" is read from the
//! fixture's session drop counter, which a cancel moves (the accepted session's handle drop is the control).
//! [`fixture`] is shared with C-TOKEN-PAD's opener arm.

use busbar_plugin_abi::fail::{failed, refused};
use busbar_plugin_abi::host_side::pool::Pool;
use busbar_plugin_abi::records::{tag, Records, TokenRec};
use busbar_plugin_abi::types::Status;
use busbar_plugin_abi::{plane, transport};
use fixture::{
    conn, counts, hosted, plane_req, target, ACCEPT, FAIL, FAILED_TEXT, MAX_OUT, REFUSE,
};

/// The record tags of an answer, as the host's buffer holds them (the TOKEN included).
fn tags(bytes: &[u8]) -> Vec<u16> {
    Records::new(bytes)
        .map(|rec| match rec {
            Ok(rec) => rec.tag,
            Err(e) => panic!("the answer is not framed: {e:?}"),
        })
        .collect()
}

/// The session token an accepted opener's answer leads with.
fn leading_token(bytes: &[u8]) -> u64 {
    match Records::new(bytes).next() {
        Some(Ok(rec)) if rec.tag == tag::TOKEN => match rec.pod::<TokenRec>() {
            Ok(tok) => tok.token,
            Err(e) => panic!("a TOKEN body is one TokenRec: {e:?}"),
        },
        _ => panic!("an accepted opener's answer leads with its TOKEN"),
    }
}

/// Each refusing variant, with the status and code its answer must carry.
const REFUSALS: [(u32, Status, u32); 2] = [
    (REFUSE, Status::REFUSED, refused::R_DENIED),
    (FAIL, Status::FAILED, failed::F_UNAVAILABLE),
];

#[test]
fn refusing_openers_return_no_session_and_no_cancel() {
    // Plane: the token a fresh instance mints first (the control instance), then request and probe refusing.
    let control = plane::Proxy::bind(hosted::<plane::Marker>(
        &fixture::plane_fx::PLUGIN,
        plane::ALL,
    ))
    .expect("a plane instance");
    let mut buf = Pool::global().acquire(MAX_OUT);
    let (session, answer) = control
        .request(&mut buf, &plane_req(ACCEPT), b"")
        .expect("an accepted request");
    assert!(answer.is_ok());
    let fresh = leading_token(buf.bytes());
    drop(session);
    drop(buf);
    let _ = counts();

    let inst = hosted::<plane::Marker>(&fixture::plane_fx::PLUGIN, plane::ALL);
    let proxy = plane::Proxy::bind(std::sync::Arc::clone(&inst)).expect("a plane instance");
    for (variant, status, code) in REFUSALS {
        let mut buf = Pool::global().acquire(MAX_OUT);
        let (session, answer) = proxy
            .request(&mut buf, &plane_req(variant), b"a body")
            .expect("a refusal is an answer, not a call error");
        assert!(session.is_none(), "a refused request has no session");
        assert_eq!(answer.status, status);
        assert_eq!(answer.fail().map(|(code, _)| code), Some(code));
        assert_eq!(answer.records().count(), 0, "a refusal is exactly one FAIL");
        assert_eq!(
            tags(buf.bytes()),
            [tag::FAIL],
            "no TOKEN, and the record written before the refusal is gone"
        );

        let mut buf = Pool::global().acquire(MAX_OUT);
        let (session, answer) = proxy
            .probe(&mut buf, &target(variant))
            .expect("a refusal is an answer, not a call error");
        assert!(session.is_none(), "a refused probe has no session");
        assert_eq!(answer.status, status);
        assert_eq!(answer.fail().map(|(code, _)| code), Some(code));
        if status == Status::FAILED {
            assert_eq!(answer.fail().map(|(_, text)| text), Some(FAILED_TEXT));
        }
        assert_eq!(answer.records().count(), 0, "a refusal is exactly one FAIL");
        assert_eq!(tags(buf.bytes()), [tag::FAIL], "no TOKEN");
    }
    assert_eq!(counts(), (0, 0), "no session was made and none cancelled");
    assert!(inst.is_live(), "a refusal is not a fault");

    // The next session is the first one this instance's table holds: no refusal was counted in it.
    let mut buf = Pool::global().acquire(MAX_OUT);
    let (session, answer) = proxy
        .request(&mut buf, &plane_req(ACCEPT), b"")
        .expect("an accepted request");
    assert!(answer.is_ok());
    assert_eq!(
        leading_token(buf.bytes()),
        fresh,
        "the refusals inserted nothing in the session table"
    );
    assert!(session.is_some(), "an accepted request has its session");
    assert_eq!(counts(), (1, 0));
    // The control: dropping a handle is a cancel, and the counter sees it.
    drop(session);
    assert_eq!(counts(), (0, 1), "a cancel drops the plugin's session");

    // Transport: the same rules for `begin`.
    let control = transport::Proxy::bind(hosted::<transport::Marker>(
        &fixture::transport_fx::PLUGIN,
        transport::ALL,
    ))
    .expect("a transport instance");
    let mut buf = Pool::global().acquire(MAX_OUT);
    let (session, answer) = control
        .begin(&mut buf, &conn(ACCEPT))
        .expect("an accepted begin");
    assert!(answer.is_ok());
    let fresh = leading_token(buf.bytes());
    drop(session);
    drop(buf);
    let _ = counts();

    let inst = hosted::<transport::Marker>(&fixture::transport_fx::PLUGIN, transport::ALL);
    let proxy = transport::Proxy::bind(std::sync::Arc::clone(&inst)).expect("a transport instance");
    for (variant, status, code) in REFUSALS {
        let mut buf = Pool::global().acquire(MAX_OUT);
        let (session, answer) = proxy
            .begin(&mut buf, &conn(variant))
            .expect("a refusal is an answer, not a call error");
        assert!(session.is_none(), "a refused begin has no session");
        assert_eq!(answer.status, status);
        assert_eq!(answer.fail().map(|(code, _)| code), Some(code));
        assert_eq!(answer.records().count(), 0, "a refusal is exactly one FAIL");
        assert_eq!(
            tags(buf.bytes()),
            [tag::FAIL],
            "no TOKEN, and the record written before the refusal is gone"
        );
    }
    assert_eq!(counts(), (0, 0), "no session was made and none cancelled");
    assert!(inst.is_live(), "a refusal is not a fault");

    let mut buf = Pool::global().acquire(MAX_OUT);
    let (session, answer) = proxy
        .begin(&mut buf, &conn(ACCEPT))
        .expect("an accepted begin");
    assert!(answer.is_ok());
    assert_eq!(
        leading_token(buf.bytes()),
        fresh,
        "the refusals inserted nothing in the session table"
    );
    assert!(session.is_some(), "an accepted begin has its session");
    assert_eq!(counts(), (1, 0));
    drop(session);
    assert_eq!(counts(), (0, 1), "a cancel drops the plugin's session");
}

/// The opener fixtures (a plane and a transport `plugin!` image of the real kinds) and the host-side instance
/// over them. Each opener's variant comes from its input view: `PlaneReq::route`, `Target::attempt`,
/// `ConnInfo::role`. Every entry runs inline on the calling test's thread, so the counters are thread-locals.
pub(crate) mod fixture {
    use std::cell::Cell;
    use std::sync::Arc;

    use busbar_plugin_abi::fail::{failed, refused, Fail};
    use busbar_plugin_abi::host_side::caller::InstanceLimits;
    use busbar_plugin_abi::host_side::driver::{Image, Instance, InstanceParts, SlotCell};
    use busbar_plugin_abi::host_side::scrub::Scrub;
    use busbar_plugin_abi::host_side::HOST;
    use busbar_plugin_abi::plane::{PlaneReq, Target};
    use busbar_plugin_abi::plugin::__rt::host::{OpenAnswer, OutLease};
    use busbar_plugin_abi::plugin::__rt::image::Admitted;
    use busbar_plugin_abi::plugin::__rt::{Kind, LinkedPlugin};
    use busbar_plugin_abi::records::{Out, Writer};
    use busbar_plugin_abi::transport::ConnInfo;
    use busbar_plugin_abi::types::{Bytes, Slice, Status, Str};

    /// Ok(session) after one record of the kind.
    pub const ACCEPT: u32 = 1;
    /// Ok(session) with no record of its own.
    pub const ACCEPT_BARE: u32 = 2;
    /// One record, then Err(REFUSED R_DENIED).
    pub const REFUSE: u32 = 3;
    /// One record, then Err(FAILED F_UNAVAILABLE, [`FAILED_TEXT`]).
    pub const FAIL: u32 = 4;
    pub(super) const FAILED_TEXT: &str = "the upstream is down";
    /// The instance's max_out (what the registry passes from the image's describe).
    pub const MAX_OUT: usize = 1 << 20;
    /// A watchdog slot no registry of this test binary allocates (slots are dense from 0).
    const SLOT: u32 = 0x00FF_FF00;

    std::thread_local! {
        static BEGUN: Cell<usize> = const { Cell::new(0) };
        static DROPPED: Cell<usize> = const { Cell::new(0) };
        static PIECES: Cell<usize> = const { Cell::new(0) };
        static CHANNELS: Cell<usize> = const { Cell::new(0) };
        static SELECTS: Cell<usize> = const { Cell::new(0) };
    }

    /// The `select_resources` variant (`PlaneReq::route`) that asks a host service during the pure call.
    pub const ASK_HOST: u32 = 5;

    pub fn pieces() -> usize {
        PIECES.replace(0)
    }
    pub fn channels() -> usize {
        CHANNELS.replace(0)
    }
    /// `select_resources` entries the plane fixture ran on this thread since the last read; resets.
    pub fn selects() -> usize {
        SELECTS.replace(0)
    }

    /// (sessions the fixtures made, sessions they dropped) on this thread since the last read; resets both.
    pub fn counts() -> (usize, usize) {
        (BEGUN.replace(0), DROPPED.replace(0))
    }

    /// One plugin-side session: made and dropped are counted.
    pub struct Sess;
    impl Sess {
        fn begin() -> Sess {
            BEGUN.set(BEGUN.get() + 1);
            Sess
        }
    }
    impl Drop for Sess {
        fn drop(&mut self) {
            DROPPED.set(DROPPED.get() + 1);
        }
    }

    /// `plugin`, admitted and opened, as the host instance the registry builds from an OK + INSTANCE answer.
    pub fn hosted<K: Kind>(plugin: &'static LinkedPlugin, methods: u64) -> Arc<Instance> {
        hosted_with_limit::<K>(plugin, methods, MAX_OUT)
    }

    pub(super) fn hosted_with_limit<K: Kind>(
        plugin: &'static LinkedPlugin,
        methods: u64,
        max_out: usize,
    ) -> Arc<Instance> {
        hosted_with_facts::<K>(plugin, methods, max_out, 0)
    }

    pub(super) fn hosted_with_facts<K: Kind>(
        plugin: &'static LinkedPlugin,
        methods: u64,
        max_out: usize,
        facts: u64,
    ) -> Arc<Instance> {
        let admitted = match Admitted::linked(plugin) {
            Ok(admitted) => admitted,
            Err(e) => panic!("admit: {e:?}"),
        };
        let mut lease = OutLease::new(vec![0; 4096], max_out).expect("a free ACTIVE slot");
        let OpenAnswer::Done(Status::OK, Some(live)) =
            admitted.open::<K>(&HOST, b"{}".to_vec(), 0, &mut lease)
        else {
            panic!("open answers OK with INSTANCE");
        };
        drop(lease);
        Instance::new(
            InstanceParts {
                image: Arc::new(Image::Linked),
                identity: Arc::from("busbar-plugin-test"),
                name: Arc::from("opener"),
                id: 1,
                slot: SLOT,
                cell: Arc::new(SlotCell::new(1, &[0; 64])),
                epoch: 1,
                limits: InstanceLimits::default(),
                max_out,
                methods,
                facts,
                scrub: Arc::new(Scrub::new()),
                tether: Box::new(()),
            },
            live,
        )
    }

    pub fn plane_req(variant: u32) -> PlaneReq<'static> {
        PlaneReq {
            route: variant,
            flags: 0,
            auth: 0,
            _r: 0,
            method: Str::new("POST"),
            path: Str::new("/v1/op"),
            query: Str::EMPTY,
            headers: Slice::EMPTY,
            identity: Bytes::EMPTY,
            request_id: 7,
            carrier: 0,
            work: Str::EMPTY,
            ticket_record: Bytes::EMPTY,
        }
    }

    pub fn target(variant: u32) -> Target<'static> {
        Target {
            attempt: variant,
            flags: 0,
            dialect: Str::new("openai"),
            model: Str::EMPTY,
            base_path: Str::EMPTY,
            upstream: Str::new("member-0"),
            provider: Str::EMPTY,
            params: Slice::EMPTY,
            admission: Bytes::EMPTY,
        }
    }

    pub fn conn(variant: u32) -> ConnInfo<'static> {
        ConnInfo {
            role: variant,
            flags: 0,
            alpn: Str::EMPTY,
            sni: Str::EMPTY,
            peer: Str::new("192.0.2.1:443"),
            local: Str::new("192.0.2.2:8443"),
            tls_peer_cert: Bytes::EMPTY,
            leftover: Bytes::EMPTY,
            head: Bytes::EMPTY,
            local_fingerprint: Str::EMPTY,
            mono_ns: 0,
        }
    }

    /// The plane image: `request` and `probe` open by variant.
    pub mod plane_fx {
        use busbar_plugin_abi::fail::Fail;
        use busbar_plugin_abi::host::Host;
        use busbar_plugin_abi::need::ChainBytes;
        use busbar_plugin_abi::plane::{tag, PlaneReq, Target};
        use busbar_plugin_abi::plugin::{Endpoints, Open};
        use busbar_plugin_abi::records::{Out, Writer};
        use busbar_plugin_abi::types::Bytes;
        use busbar_plugin_abi::Plane;

        use super::{opener, Sess};

        pub struct Fx;

        impl Plane for Fx {
            type Session = Sess;
            fn request(
                &self,
                _h: &Host,
                req: &PlaneReq<'_>,
                _body: Bytes<'_>,
                out: &mut Out<'_>,
            ) -> Result<Sess, Fail> {
                opener(req.route, out, tag::END, b"")
            }
            fn upstream(
                &self,
                _h: &Host,
                _s: &mut Sess,
                _target: &Target<'_>,
                _out: &mut Out<'_>,
            ) -> Result<(), Fail> {
                Ok(())
            }
            fn piece(
                &self,
                _h: &Host,
                _s: &mut Sess,
                _from: u32,
                exchange: u32,
                _flags: u32,
                bytes: Bytes<'_>,
                out: &mut Out<'_>,
            ) -> Result<(), Fail> {
                super::PIECES.set(super::PIECES.get() + 1);
                if !bytes.get().is_empty() {
                    out.put_pod_tail(
                        tag::EX_MSG,
                        &busbar_plugin_abi::plane::ExMsg {
                            exchange,
                            flags: busbar_plugin_abi::plane::MSG_TEXT,
                            stream: 0,
                        },
                        bytes.get(),
                    )?;
                    if exchange == 99 {
                        out.put(u16::MAX, b"invalid trailing record")?;
                    }
                }
                Ok(())
            }
            fn channel(
                &self,
                h: &Host,
                _s: &mut Sess,
                target: &Target<'_>,
                out: &mut Out<'_>,
            ) -> Result<(), Fail> {
                use busbar_plugin_abi::{
                    host::HostExt,
                    plane,
                    records::{tag as generic, Reply, TokenRec},
                };
                super::CHANNELS.set(super::CHANNELS.get() + 1);
                if target.attempt == 3 {
                    let _ = h.now_ns();
                }
                let mut key = Reply::new();
                key.put_text(generic::TEXT, target.upstream.get())?;
                out.put_pod_tail(
                    tag::CHANNEL,
                    &plane::ChanRec {
                        exchange: 7,
                        carrier: plane::CARRIER_STDIO,
                        flags: 0,
                        framing: plane::CH_FRAME_NDJSON,
                    },
                    key.as_bytes(),
                )?;
                if target.attempt == 1 {
                    out.put(tag::UP_BODY, b"forbidden")?;
                }
                if target.attempt == 2 {
                    out.put_pod(
                        busbar_plugin_abi::records::tag::TOKEN,
                        &TokenRec { token: 99 },
                    )?;
                }
                Ok(())
            }
            /// Answers no records; on route [`super::ASK_HOST`] it first asks a host service (the clock).
            fn select_resources(
                &self,
                h: &Host,
                _mode: u32,
                req: &PlaneReq<'_>,
                _body: Bytes<'_>,
                _out: &mut Out<'_>,
            ) -> Result<(), Fail> {
                use busbar_plugin_abi::host::HostExt;
                super::SELECTS.set(super::SELECTS.get() + 1);
                if req.route == super::ASK_HOST {
                    let _ = h.now_ns();
                }
                Ok(())
            }
            fn end(&self, _h: &Host, _s: Sess, _out: &mut Out<'_>) -> Result<(), Fail> {
                Ok(())
            }
            fn probe(
                &self,
                _h: &Host,
                target: &Target<'_>,
                out: &mut Out<'_>,
            ) -> Result<Sess, Fail> {
                opener(target.attempt, out, tag::BODY, b"GET /v1/models")
            }
        }

        impl Open for Fx {
            async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
                Ok(Fx)
            }
            fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
                Ok(())
            }
        }

        busbar_plugin_abi::plugin!(Plane, Fx);
    }

    /// The transport image: `begin` opens by variant.
    pub mod transport_fx {
        use busbar_plugin_abi::fail::Fail;
        use busbar_plugin_abi::host::Host;
        use busbar_plugin_abi::need::ChainBytes;
        use busbar_plugin_abi::plugin::{Endpoints, Open};
        use busbar_plugin_abi::records::Out;
        use busbar_plugin_abi::transport::{tag, ConnInfo};
        use busbar_plugin_abi::Transport;

        use super::{opener, Sess};

        pub struct Fx;

        impl Transport for Fx {
            type Session = Sess;
            fn begin(
                &self,
                _h: &Host,
                conn: &ConnInfo<'_>,
                out: &mut Out<'_>,
            ) -> Result<Sess, Fail> {
                opener(conn.role, out, tag::RENDEZVOUS, b"hello")
            }
        }

        impl Open for Fx {
            async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
                Ok(Fx)
            }
            fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
                Ok(())
            }
        }

        busbar_plugin_abi::plugin!(Transport, Fx);
    }

    /// One opener's body for `variant`: `record` is the one record ACCEPT, REFUSE and FAIL write.
    fn opener(variant: u32, out: &mut Out<'_>, record: u16, body: &[u8]) -> Result<Sess, Fail> {
        match variant {
            ACCEPT => {
                out.put(record, body)?;
                Ok(Sess::begin())
            }
            ACCEPT_BARE => Ok(Sess::begin()),
            REFUSE => {
                out.put(record, body)?;
                Err(Fail::refused(refused::R_DENIED))
            }
            FAIL => {
                out.put(record, body)?;
                Err(Fail::failed_because(failed::F_UNAVAILABLE, FAILED_TEXT))
            }
            _ => Err(Fail::refused(refused::R_INVALID)),
        }
    }
}

/// Drives the real linked SDK image through PlaneAdapter and its fixed borrowed output path.
mod fixed_piece {
    use super::fixture;
    use busbar_plugin_abi::host_side::pool::Pool;
    use busbar_plugin_abi::plane;
    use busbar_plugin_abi::records::Records;
    use busbar_plugin_loader::adapters::plane::{PlaneAdapter, PlaneDescribe};
    use busbar_plugin_loader::call::kinds::plane::{Proxy, SessionHandle};
    use busbar_plugin_loader::call::Mono;
    use busbar_plugin_loader::instance::ErrorBook;
    use busbar_plugin_test::FakeNeeds;
    use busbar_ports::plane::PlanePort;
    use std::sync::Arc;

    #[test]
    fn real_selected_channel_callback_is_pure_and_publishes_only_complete_answers() {
        use busbar_ports::plane::TargetIn;
        for (facts, attempt, ok, calls) in [
            (plane::FB_CHANNEL_OPEN, 0, true, 1),
            (plane::FB_CHANNEL_OPEN, 1, false, 1),
            (plane::FB_CHANNEL_OPEN, 2, false, 1),
            (plane::FB_CHANNEL_OPEN, 3, false, 1),
            (0, 0, false, 0),
        ] {
            let inst = fixture::hosted_with_facts::<plane::Marker>(
                &fixture::plane_fx::PLUGIN,
                plane::ALL,
                fixture::MAX_OUT,
                facts,
            );
            let proxy = Proxy::bind(inst).unwrap();
            let mut initial = Pool::global().acquire(fixture::MAX_OUT);
            let (session, answer) = proxy
                .request(
                    &mut initial,
                    Mono::NONE,
                    &fixture::plane_req(fixture::ACCEPT_BARE),
                    b"",
                )
                .unwrap();
            assert!(answer.is_ok());
            let mut session = session.unwrap();
            let adapter = PlaneAdapter::new(
                proxy,
                Arc::new(FakeNeeds::new()),
                PlaneDescribe::default(),
                &ErrorBook::None,
            );
            let target = TargetIn {
                attempt,
                flags: 0,
                dialect: "mcp",
                model: "",
                base_path: "",
                upstream: "member-0",
                provider: "",
                params: &[],
                admission: &[],
            };
            fixture::channels();
            let mut delivered = 0;
            assert_eq!(
                adapter
                    .channel(&mut session, &target, &mut |_| delivered += 1)
                    .is_ok(),
                ok,
                "facts {facts:#x} attempt {attempt}"
            );
            assert_eq!(fixture::channels(), calls);
            assert_eq!(delivered, usize::from(ok));
        }
    }

    /// `select_resources` is pure (no host service authority): a selector that asks a host service is
    /// faulted even though it ignores the denial and answers OK; one that asks nothing answers OK.
    #[test]
    fn real_select_resources_callback_is_pure() {
        use busbar_plugin_abi::fail::{CallError, FaultReason};
        use busbar_plugin_abi::records::RecErr;
        for mode in [plane::RESOURCE_INVENTORY, plane::RESOURCE_SELECT] {
            for (route, ok) in [(fixture::ACCEPT_BARE, true), (fixture::ASK_HOST, false)] {
                let inst = fixture::hosted::<plane::Marker>(&fixture::plane_fx::PLUGIN, plane::ALL);
                let proxy = Proxy::bind(Arc::clone(&inst)).unwrap();
                let mut buf = Pool::global().acquire(fixture::MAX_OUT);
                fixture::selects();
                let answer = proxy.select_resources(
                    &mut buf,
                    Mono::NONE,
                    mode,
                    &fixture::plane_req(route),
                    b"",
                );
                assert_eq!(
                    fixture::selects(),
                    1,
                    "mode {mode} route {route}: one entry"
                );
                if ok {
                    let answer = answer.expect("a selector that asks nothing answers");
                    assert!(answer.is_ok(), "mode {mode} route {route}");
                    assert!(inst.is_live(), "a pure answer is not a fault");
                } else {
                    assert!(
                        matches!(
                            answer,
                            Err(CallError::Fault(FaultReason::BadRecords(RecErr::Reserved)))
                        ),
                        "mode {mode}: a host service asked during pure select_resources must fault, \
                         never succeed"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn actual_native_reply_crosses_the_real_saturated_channel_writer() {
        use busbar_contract::secure::SecureVec;
        use busbar_kernel::channels::budget::{ChannelBudget, Claim, REPLY_BYTES, UNIT_BYTES};
        use busbar_kernel::channels::frame::{Framing, MAX_MESSAGE};
        use busbar_kernel::channels::link::Link;
        use busbar_kernel::channels::protected::{ReplyStorage, OUTPUT_BYTES};
        use busbar_kernel::channels::Attachment;
        use busbar_plugin_loader::adapters::plane::protected_reply::{classify, Classification};
        use tokio::io::AsyncReadExt;
        use tokio::sync::mpsc;

        let (adapter, mut session) = opened_limit(OUTPUT_BYTES);
        let instance = ChannelBudget::new().instance();
        let unit = instance.unit();
        let link_budget = instance.link();
        let (link, mut queue) = Link::new(false, Framing::Ndjson, link_budget);
        let (_tx, rx) = mpsc::channel(1);
        let mut attachment =
            Attachment::linked(link, unit.clone(), 1, 1, true, Default::default(), rx).unwrap();

        // Input is already owned and charged INSIDE the saturated general capacity before entry.
        let input_charge = unit
            .reserve(
                Claim {
                    bytes: MAX_MESSAGE,
                    ..Claim::default()
                },
                None,
            )
            .unwrap();
        let mut input = SecureVec::zeroed(MAX_MESSAGE);
        input.fill(b'x');
        let general = unit
            .reserve(
                Claim {
                    bytes: UNIT_BYTES - REPLY_BYTES - MAX_MESSAGE,
                    ..Claim::default()
                },
                None,
            )
            .unwrap();
        let mut inspection = ReplyStorage::new(&unit).unwrap();
        let len = adapter
            .piece_fixed(
                &mut session,
                plane::FROM_CORE,
                7,
                0,
                input.as_slice(),
                inspection.output_mut(),
            )
            .unwrap();
        assert_eq!(fixture::pieces(), 1);
        assert_eq!(len, OUTPUT_BYTES);
        match classify(
            plane::FROM_CORE,
            true,
            &inspection.output()[..len],
            MAX_MESSAGE,
        )
        .unwrap()
        {
            Classification::Reply {
                exchange, payload, ..
            } => {
                assert_eq!(exchange, 7);
                assert_eq!(payload, input.as_slice());
            }
            _ => panic!("one protected native reply"),
        }
        let message = inspection
            .into_write(24..OUTPUT_BYTES, attachment.link_budget())
            .unwrap();
        attachment.send_owned(message).unwrap();
        assert!(
            ReplyStorage::new(&unit).is_err(),
            "queued writer still owns protected bytes"
        );

        let message = queue.recv().await.unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let run = tokio::spawn(async move { message.write(&mut writer).await });
        let mut first = [0; 1];
        reader.read_exact(&mut first).await.unwrap();
        assert_eq!(first, [b'x']);
        drop(attachment);
        assert!(
            ReplyStorage::new(&unit).is_err(),
            "started write survives its lease's cancellation"
        );
        let mut total = 1;
        let mut scratch = [0; 8192];
        while total < MAX_MESSAGE + 1 {
            let n = reader.read(&mut scratch).await.unwrap();
            assert!(n > 0);
            for (at, byte) in scratch[..n].iter().enumerate() {
                assert_eq!(
                    *byte,
                    if total + at == MAX_MESSAGE {
                        b'\n'
                    } else {
                        b'x'
                    }
                );
            }
            total += n;
        }
        run.await.unwrap().unwrap();
        assert_eq!(
            fixture::pieces(),
            0,
            "no callback replay while the writer was blocked"
        );
        drop(ReplyStorage::new(&unit).unwrap());
        drop(input);
        drop((input_charge, general));
    }

    fn opened() -> (PlaneAdapter<FakeNeeds>, SessionHandle) {
        opened_limit(fixture::MAX_OUT)
    }

    fn opened_limit(max_out: usize) -> (PlaneAdapter<FakeNeeds>, SessionHandle) {
        let inst = fixture::hosted_with_limit::<plane::Marker>(
            &fixture::plane_fx::PLUGIN,
            plane::ALL,
            max_out,
        );
        let proxy = Proxy::bind(inst).unwrap();
        let mut initial = Pool::global().acquire(fixture::MAX_OUT);
        let (session, answer) = proxy
            .request(
                &mut initial,
                Mono::NONE,
                &fixture::plane_req(fixture::ACCEPT_BARE),
                b"",
            )
            .unwrap();
        assert!(answer.is_ok());
        let adapter = PlaneAdapter::new(
            proxy,
            Arc::new(FakeNeeds::new()),
            PlaneDescribe::default(),
            &ErrorBook::None,
        );
        fixture::pieces();
        (adapter, session.unwrap())
    }

    #[test]
    fn fixed_piece_borrows_backing_and_calls_once() {
        let (adapter, mut session) = opened();
        let mut backing = [0xa5; 256];
        let len = adapter
            .piece_fixed(
                &mut session,
                plane::FROM_CORE,
                7,
                0,
                b"reply",
                &mut backing[8..248],
            )
            .unwrap();
        assert_eq!(fixture::pieces(), 1);
        assert_eq!(&backing[..8], &[0xa5; 8]);
        assert_eq!(&backing[248..], &[0xa5; 8]);
        let rec = Records::new(&backing[8..8 + len]).next().unwrap().unwrap();
        let (message, payload) = rec.pod_tail::<plane::ExMsg>().unwrap();
        assert_eq!(message.exchange, 7);
        assert_eq!(payload, b"reply");
    }

    #[test]
    fn fixed_answer_decoding_never_reinvokes_the_plugin_or_emits_a_partial_prefix() {
        let (adapter, mut session) = opened();
        let mut backing = [0; 256];
        let len = adapter
            .piece_fixed(&mut session, plane::FROM_CORE, 7, 0, b"reply", &mut backing)
            .unwrap();
        assert_eq!(fixture::pieces(), 1);
        let mut delivered = 0;
        adapter
            .decode_fixed_piece(plane::FROM_CORE, 7, &backing[..len], &mut |_| {
                delivered += 1
            })
            .unwrap();
        assert_eq!(delivered, 1);
        assert_eq!(
            fixture::pieces(),
            0,
            "decoding is not another native callback"
        );
        delivered = 0;
        assert!(adapter
            .decode_fixed_piece(plane::FROM_CORE, 7, &backing[..len + 1], &mut |_| {
                delivered += 1
            })
            .is_err());
        assert_eq!(delivered, 0);
        assert_eq!(fixture::pieces(), 0);
    }

    #[test]
    fn fixed_piece_refuses_a_foreign_instance_session_before_entry() {
        let (adapter, _own_session) = opened();
        let (_other_adapter, mut foreign) = opened();
        let mut backing = [0xa5; 256];
        assert!(matches!(
            adapter.piece_fixed(&mut foreign, plane::FROM_CORE, 7, 0, b"reply", &mut backing),
            Err(busbar_ports::PortError::Call(
                busbar_plugin_abi::fail::CallError::Fault(
                    busbar_plugin_abi::fail::FaultReason::BadInstance
                )
            ))
        ));
        assert_eq!(fixture::pieces(), 0);
        assert_eq!(backing, [0xa5; 256]);
    }

    #[test]
    fn fixed_piece_rejects_the_whole_malformed_answer() {
        let (adapter, mut session) = opened();
        let mut backing = [0; 256];
        assert!(adapter
            .piece_fixed(
                &mut session,
                plane::FROM_CORE,
                99,
                0,
                b"reply",
                &mut backing
            )
            .is_err());
        assert_eq!(fixture::pieces(), 1);
    }

    #[test]
    fn fixed_piece_never_grows_or_replays_when_the_lender_is_full() {
        let (adapter, mut session) = opened();
        let mut backing = [0xa5; 128];
        let result = adapter.piece_fixed(
            &mut session,
            plane::FROM_CORE,
            7,
            0,
            &[0; 128],
            &mut backing[8..120],
        );
        assert!(result.is_err());
        assert_eq!(fixture::pieces(), 1);
        assert_eq!(&backing[..8], &[0xa5; 8]);
        assert_eq!(&backing[120..], &[0xa5; 8]);
    }

    #[test]
    fn fixed_piece_preserves_instance_output_limit_and_quarantine() {
        let (adapter, mut session) = opened();
        let mut backing = vec![0xa5; fixture::MAX_OUT + 64];
        let input = vec![0; fixture::MAX_OUT];
        assert!(adapter
            .piece_fixed(&mut session, plane::FROM_CORE, 7, 0, &input, &mut backing)
            .is_err());
        assert_eq!(fixture::pieces(), 1);
        assert!(backing[fixture::MAX_OUT..].iter().all(|byte| *byte == 0xa5));
        adapter.proxy().instance().quarantine();
        assert!(adapter
            .piece_fixed(&mut session, plane::FROM_CORE, 7, 0, b"reply", &mut backing)
            .is_err());
        assert_eq!(fixture::pieces(), 0);
    }
}
