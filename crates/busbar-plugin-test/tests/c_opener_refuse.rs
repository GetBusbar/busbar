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
    drop(answer);
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
        drop(answer);
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
        drop(answer);
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
    drop(answer);
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
    drop(answer);
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
        drop(answer);
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
    drop(answer);
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
    pub const FAILED_TEXT: &str = "the upstream is down";
    /// The instance's max_out (what the registry passes from the image's describe).
    pub const MAX_OUT: usize = 1 << 20;
    /// A watchdog slot no registry of this test binary allocates (slots are dense from 0).
    const SLOT: u32 = 0x00FF_FF00;

    std::thread_local! {
        static BEGUN: Cell<usize> = const { Cell::new(0) };
        static DROPPED: Cell<usize> = const { Cell::new(0) };
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
        let admitted = match Admitted::linked(plugin) {
            Ok(admitted) => admitted,
            Err(e) => panic!("admit: {e:?}"),
        };
        let mut lease = OutLease::new(vec![0; 4096], MAX_OUT).expect("a free ACTIVE slot");
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
                max_out: MAX_OUT,
                methods,
                facts: 0,
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
        use busbar_plugin_abi::records::Out;
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
                _exchange: u32,
                _flags: u32,
                _bytes: Bytes<'_>,
                _out: &mut Out<'_>,
            ) -> Result<(), Fail> {
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
                opener(conn.role, out, tag::WRITE, b"hello")
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
