// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SESSION-DROP (ABI-MIN3-INTERFACE §14): Cancel and close drop every `Session`: drop counter == begin counter.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! W1-A4: a transport-shaped kind declared here with `kind!`, its plugin with `plugin!`, driven through the
//! host handles busbar-ffi owns (UNSAFE-MIN r3.1: `Instance`, `Session`), with no `unsafe`. Cancel is the
//! session handle's `Drop`. Close is `Inst`'s field order (chains, sessions, then the plugin): a host whose
//! sessions all hold the instance never reaches close with one open, so the close arm fills an `Inst` the
//! way the opener shim does and drops it the way `close` does.

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::{Host, HostFns};
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::__rt::host::{OpenAnswer, OutLease};
use busbar_plugin_abi::plugin::__rt::image::Admitted;
use busbar_plugin_abi::plugin::__rt::kind as marker;
use busbar_plugin_abi::plugin::{Endpoints, Open};
use busbar_plugin_abi::records::Out;
use busbar_plugin_abi::slots::Inst;
use busbar_plugin_abi::types::{Bytes, Status, Str};
use transport::ConnInfo;

busbar_plugin_abi::kind! {
    /// A transport-shaped kind for this case: one session per connection.
    pub trait Conns: kind = 7, abi = 2, session {
        views {
            pub struct ConnInfo<'a> {
                pub role: u32,
                pub flags: u32,
                pub alpn: Str<'a>,
                pub sni: Str<'a>,
                pub peer: Str<'a>,
                pub local: Str<'a>,
                pub tls_peer_cert: Bytes<'a>,
                pub leftover: Bytes<'a>,
                pub head: Bytes<'a>,
                pub local_fingerprint: Str<'a>,
                pub mono_ns: u64,
            }
        }
        pods {}
        tags {}
        consts { REQUIRED: u64 = 0b111_1111; }
        sync open fn begin(&self, h: &Host, conn: &ConnInfo<'_>, out: &mut Out<'_>) -> Result<Session, Fail>;
        sync fn ingest(&self, h: &Host, s: &mut Session, bytes: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
            let _ = (h, s, bytes, out);
            Ok(())
        }
        sync fn emit(
            &self, h: &Host, s: &mut Session, stream: u64, kind: u32, flags: u32, bytes: Bytes<'_>, out: &mut Out<'_>
        ) -> Result<(), Fail> {
            let _ = (h, s, stream, kind, flags, bytes, out);
            Ok(())
        }
        sync fn timer(&self, h: &Host, s: &mut Session, out: &mut Out<'_>) -> Result<(), Fail> {
            let _ = (h, s, out);
            Ok(())
        }
        sync fn datagram(
            &self, h: &Host, s: &mut Session, from: u32, flags: u32, bytes: Bytes<'_>, out: &mut Out<'_>
        ) -> Result<(), Fail> {
            let _ = (h, s, from, flags, bytes, out);
            Ok(())
        }
        sync fn event(&self, h: &Host, s: &mut Session, ev: u32, arg: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
            let _ = (h, s, ev, arg, out);
            Ok(())
        }
        sync fn offer(&self, h: &Host, role: u32, out: &mut Out<'_>) -> Result<(), Fail> {
            let _ = (h, role, out);
            Ok(())
        }
    }
}

std::thread_local! {
    static BEGUN: Cell<usize> = const { Cell::new(0) };
    static DROPPED: Cell<usize> = const { Cell::new(0) };
    static ORDER: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

/// One session; its drop is counted.
pub struct Counted;
impl Drop for Counted {
    fn drop(&mut self) {
        DROPPED.with(|n| n.set(n.get() + 1));
        ORDER.with_borrow_mut(|order| order.push("session"));
    }
}

/// The plugin value; its drop is logged after every session's.
pub struct Fx;
impl Drop for Fx {
    fn drop(&mut self) {
        ORDER.with_borrow_mut(|order| order.push("plugin"));
    }
}

impl Conns for Fx {
    type Session = Counted;
    fn begin(&self, _h: &Host, _conn: &ConnInfo<'_>, _out: &mut Out<'_>) -> Result<Counted, Fail> {
        BEGUN.with(|n| n.set(n.get() + 1));
        Ok(Counted)
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

busbar_plugin_abi::plugin!(@kind [transport] Fx);

static HOST: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: None,
        crypto: None,
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        service: None,
    },
);

fn lease() -> OutLease<'static> {
    OutLease::new(vec![0; 4096], 1 << 20).expect("a free ACTIVE slot")
}

fn counts() -> (usize, usize) {
    (BEGUN.with(Cell::get), DROPPED.with(Cell::get))
}

#[test]
fn cancel_and_close_drop_every_session() {
    let admitted = match Admitted::linked(&PLUGIN) {
        Ok(admitted) => admitted,
        Err(e) => panic!("admit: {e:?}"),
    };
    let mut out = lease();
    let OpenAnswer::Done(Status::OK, Some(inst)) =
        admitted.open::<marker::Transport>(&HOST, b"{}".to_vec(), 0, &mut out)
    else {
        panic!("open answers OK with INSTANCE");
    };
    drop(out);
    let inst = Arc::new(inst);
    let conn = ConnInfo {
        role: 0,
        flags: 0,
        alpn: Str::EMPTY,
        sni: Str::EMPTY,
        peer: Str::EMPTY,
        local: Str::EMPTY,
        tls_peer_cert: Bytes::EMPTY,
        leftover: Bytes::EMPTY,
        head: Bytes::EMPTY,
        local_fingerprint: Str::EMPTY,
        mono_ns: 0,
    };

    // Cancel: every handle the host drops cancels its session, and the plugin drops it.
    let mut sessions = Vec::new();
    for _ in 0..8 {
        let mut out = lease();
        let (status, session) = busbar_plugin_abi::transport::pack::begin(0, &conn, |call| {
            inst.open_session(busbar_plugin_abi::transport::slot::begin, call, &mut out)
        });
        assert_eq!(status, Status::OK);
        sessions.push(session.expect("an OK opener answer leads with its session TOKEN"));
    }
    let mut first = sessions.remove(0);
    let mut out = lease();
    assert_eq!(
        busbar_plugin_abi::transport::pack::timer(0, |call| {
            first.call(busbar_plugin_abi::transport::slot::timer, call, &mut out)
        }),
        Status::OK,
        "a live session answers"
    );
    drop(out);
    drop(first);
    assert_eq!(counts(), (8, 1));
    drop(sessions);
    assert_eq!(
        counts(),
        (8, 8),
        "drop counter == begin counter after cancel"
    );

    // Close: the instance drops the sessions still in its table, then the plugin.
    ORDER.with_borrow_mut(Vec::clear);
    let parked: Box<Inst<Fx, Counted, (), ()>> = Box::new(Inst::new(Fx));
    for _ in 0..3 {
        BEGUN.with(|n| n.set(n.get() + 1));
        // Deliberately leave this occupant for instance field teardown, not handle Drop.
        core::mem::forget(parked.sessions().insert(Counted).expect("a free slot"));
    }
    drop(parked);
    assert_eq!(
        counts(),
        (11, 11),
        "drop counter == begin counter after close"
    );
    assert_eq!(
        ORDER.with_borrow(Clone::clone),
        ["session", "session", "session", "plugin"],
        "sessions drop before the plugin they belong to"
    );

    // The real instance closes with nothing left open; its plugin value drops last.
    ORDER.with_borrow_mut(Vec::clear);
    drop(inst);
    assert_eq!(counts(), (11, 11));
    assert_eq!(ORDER.with_borrow(Clone::clone), ["plugin"]);
}
