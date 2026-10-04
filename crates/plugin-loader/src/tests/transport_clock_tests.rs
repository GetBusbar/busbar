// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER CLOCK SEAM, across the HOT lowering (the design's one clock, which also drives every
//! plugin's tick). A framer reads no clock of its own: the host's time reaches it on every
//! call, the framer states the instant it must next be called at, and the host calls `tick` then.
//! Proven here over a framer lowered by the contract's own sdk and admitted through the loader's one
//! admission, so what is proven is the lowering both doors use.

use super::*;
use busbar_contract::abi::hot::decl::DeclStr;
use busbar_contract::abi::hot::transport::{DeclClaim, FramerSlots};
use busbar_contract::abi::sdk::transport as sdk;
use busbar_contract::transport::{HostTime, TransportMeta};
use std::sync::OnceLock;

/// The interval the test framer keeps: it pings this long after the last time it was called.
const EVERY: u64 = 30_000_000_000;

/// A framer that keeps one deadline per state and, when it comes, sends `ping` stamped with the
/// host's wall time — so the test sees the host's clock reach it both ways.
#[derive(Default)]
struct Ticking(Mutex<HashMap<u64, u64>>);

impl Plugin for Ticking {
    fn key(&self) -> &'static str {
        "ticking"
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

impl TransportMeta for Ticking {
    const KEY: &'static str = "ticking";
    const SELECTOR_FORMS: &'static [busbar_contract::grammar::SelectorForm] = &[];
    const EGRESS_SELECTOR_FORMS: &'static [busbar_contract::grammar::SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = &["below"];
    const HANDOFF: Option<busbar_contract::transport::wire::Handoff> = None;
    const FRAMING: busbar_contract::transport::wire::Framing =
        busbar_contract::transport::wire::Framing::Stream;
    const SESSION: bool = false;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<busbar_contract::transport::wire::Unit0Trigger> = None;
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract::transport::wire::StatusAt> = None;
    const STATUS_NAMESPACE: Option<&'static str> = None;
}

impl Framer for Ticking {
    fn locate(&self, target: &str) -> Result<Located, TransportError> {
        Ok(Located {
            authority: target.to_string(),
            secure: false,
            server_name: None,
        })
    }
    fn open(
        &self,
        _: Side,
        _: &str,
        _: &ConnFacts,
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        let due = out.now().monotonic_nanos + EVERY;
        self.0.lock().unwrap().insert(1, due);
        out.wake_at(Some(due));
        Ok(1)
    }
    fn ingest(
        &self,
        _: u64,
        _: &[u8],
        _: bool,
        _: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        Ok(())
    }
    fn emit(
        &self,
        _: u64,
        _: StreamId,
        _: &[u8],
        _: bool,
        _: bool,
        _: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        Ok(())
    }
    fn encode_envelope(
        &self,
        _: &[(&str, &[u8])],
        _: &[u8],
        _: &mut dyn BytesOut,
    ) -> Result<(), busbar_contract::transport::wire::Encode> {
        Ok(())
    }
    fn refusal(
        &self,
        _: u64,
        _: Option<StreamId>,
        _: &[u8],
        _: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        Ok(())
    }
    fn close(&self, state: u64, _: CloseReason, out: &mut dyn FramerOut) {
        self.0.lock().unwrap().remove(&state);
        out.wake_at(None);
    }
    fn detach(&self, _: u64, _: &mut dyn BytesOut) -> Result<(), TransportError> {
        Err(TransportError::HandoffMismatch)
    }
    fn adopt(
        &self,
        side: Side,
        facts: &ConnFacts,
        _: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        self.open(side, "", facts, out)
    }
    fn tick(&self, state: u64, out: &mut dyn FramerOut) -> Result<(), TransportError> {
        let now = out.now();
        let mut due = self.0.lock().unwrap();
        let at = due.get_mut(&state).ok_or(TransportError::Closed)?;
        if now.monotonic_nanos < *at {
            // Not yet: the deadline stands.
            out.wake_at(Some(*at));
            return Ok(());
        }
        out.send(format!("ping {}", now.unix_nanos).as_bytes());
        *at = now.monotonic_nanos + EVERY;
        out.wake_at(Some(*at));
        Ok(())
    }
}

fn build(_: &TransportSettings) -> Ticking {
    Ticking::default()
}

extern "C-unwind" fn init(
    settings: *const busbar_contract::abi::hot::transport::WireSettings,
    waker: *const busbar_contract::abi::hot::transport::WireWaker,
    out_state: *mut core::mem::MaybeUninit<busbar_contract::abi::hot::OpaqueHandle>,
) -> RawWireOutcome {
    // SAFETY: the host calls `init` with its own live settings, waker handle and out slot.
    unsafe { sdk::init::<Ticking>(settings, waker, out_state, build) }
}

static SLOTS: FramerSlots = sdk::framer_slots::<Ticking>();
static COMPOSES: [DeclStr; 1] = [DeclStr::new("below")];
static CLAIMS: [DeclClaim; 1] = sdk::decl_claims(<Ticking as TransportMeta>::CLAIMS, &[], &[]);

/// The test framer's decl, lowered by the sdk exactly as `export_framer!` lowers one.
fn decl() -> &'static TransportDecl {
    static DECL: OnceLock<TransportDecl> = OnceLock::new();
    DECL.get_or_init(|| {
        sdk::decl::<Ticking>(
            sdk::RowLists {
                composes_over: &COMPOSES,
                selector_forms: &[],
                egress_selector_forms: &[],
                upgrades_to: &[],
                transport_facts: &[],
                claims: &CLAIMS,
            },
            init,
            None,
            Some(&SLOTS),
        )
    })
}

/// The decl-backed framer, admitted through the one admission.
fn lowered(decl: &'static TransportDecl) -> Arc<dyn Framer> {
    // SAFETY: `decl` is `'static` and borrows `'static` data.
    let row: &'static DynTransport = Box::leak(Box::new(
        unsafe { link_transport(decl, "ticking") }.expect("admitted"),
    ));
    match row.build(&crate::wire_settings(&TransportSettings::default())) {
        Ok(Built::Framer(f)) => f,
        _ => panic!("the test framer builds a framer"),
    }
}

/// A host sink at a fixed time, recording what the framer said.
struct At {
    now: HostTime,
    sent: Vec<u8>,
    wake: Option<Option<u64>>,
}

impl FramerOut for At {
    fn send(&mut self, bytes: &[u8]) {
        self.sent.extend_from_slice(bytes);
    }
    fn frame(&mut self, _: Framed<'_>) {}
    fn end(&mut self) {}
    fn now(&self) -> HostTime {
        self.now
    }
    fn wake_at(&mut self, monotonic_nanos: Option<u64>) {
        self.wake = Some(monotonic_nanos);
    }
}

fn at(monotonic_nanos: u64, unix_nanos: u64) -> At {
    At {
        now: HostTime {
            monotonic_nanos,
            unix_nanos,
        },
        sent: Vec::new(),
        wake: None,
    }
}

/// The host's time reaches the framer across the lowering, the framer's deadline reaches the host,
/// and `tick` at that deadline runs what was waiting on it — with the host's wall time, not one the
/// framer read.
#[test]
fn the_host_clock_and_the_framer_deadline_cross_the_lowering() {
    let f = lowered(decl());
    let mut out = at(5, 1_700_000_000_000_000_000);
    let state = f
        .open(Side::Dial, "t", &ConnFacts::default(), &mut out)
        .unwrap();
    assert_eq!(
        out.wake,
        Some(Some(5 + EVERY)),
        "the deadline reached the host"
    );

    let mut early = at(5 + EVERY - 1, 0);
    f.tick(state, &mut early).unwrap();
    assert!(early.sent.is_empty(), "nothing is due before the deadline");
    assert_eq!(early.wake, Some(Some(5 + EVERY)));

    let mut due = at(5 + EVERY, 1_700_000_030_000_000_000);
    f.tick(state, &mut due).unwrap();
    assert_eq!(
        due.sent, b"ping 1700000030000000000",
        "the host's wall time"
    );
    assert_eq!(due.wake, Some(Some(5 + 2 * EVERY)), "the next deadline");

    let mut closing = at(6 + EVERY, 0);
    f.close(state, CloseReason::Normal, &mut closing);
    assert_eq!(closing.wake, Some(None), "a closed state keeps no deadline");
    assert_eq!(
        f.tick(state, &mut at(7 + EVERY, 0)),
        Err(TransportError::Closed)
    );
}

/// A framer built before the clock seam (its slot table ends before `tick`) is admitted, keeps no
/// deadline, and is never due.
#[test]
fn a_framer_table_before_the_clock_seam_is_admitted_and_never_due() {
    static OLDER: OnceLock<FramerSlots> = OnceLock::new();
    static OLDER_DECL: OnceLock<TransportDecl> = OnceLock::new();
    let older = OLDER.get_or_init(|| FramerSlots {
        size: core::mem::offset_of!(FramerSlots, tick) as u32,
        tick: None,
        ..SLOTS
    });
    let d = OLDER_DECL.get_or_init(|| TransportDecl {
        framer: older,
        // SAFETY: a byte copy of the live decl; every pointer in it is `'static` data.
        ..unsafe { core::ptr::read(decl()) }
    });
    let f = lowered(d);
    let mut out = at(0, 0);
    let state = f
        .open(Side::Dial, "t", &ConnFacts::default(), &mut out)
        .unwrap();
    assert_eq!(f.tick(state, &mut at(u64::MAX, 0)), Ok(()));
}
