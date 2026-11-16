// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin images, the host-side `Instance` and the Need step driver (IF §10.4 generic part, §10.5). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H1 fills it.

use core::marker::PhantomData;
use std::sync::Arc;

use crate::host_side::caller::{Caller, InstanceLimits};
use crate::host_side::needs::Needs;
use crate::host_side::scrub::Scrub;
use crate::types::KindCode;

/// One mapped plugin image. `Linked` = compiled into the binary (never unmapped). `Loaded` owns the dl handle,
/// the staged memfd/temp file and the mapped segments, and is **resident** (I13): it is never `dlclose`d. Its
/// last `Arc` is held by the loader's process-wide image table (`instance.rs`: a cold `Mutex<HashMap<[u8; 32],
/// Arc<Image>>>` touched only by admit, keyed by image SHA-256, so re-admitting identical bytes on a
/// reconfigure or an upgrade-and-back reuses the mapping instead of loading it again); when the last instance of
/// an image goes away the table keeps the handle, and stage.rs retains its memfd (origin/dev `retire_memfd`,
/// stage.rs:520), so its name is never recycled. Cost: one mapping per distinct image admitted during the
/// process's life (gauge `plugin_images_resident`, bytes in `plugin_images_resident_bytes`); a restart reclaims it.
pub enum Image {
    Linked,
    Loaded(LoadedImage),
}

// IF §11.1: the loaded-image payload of `Image::Loaded`.
pub struct LoadedImage {
    // W0-ABI: private fields (stage.rs `Staged` (memfd or temp-file handle), dl handle, mapped segments
    // (dl_iterate_phdr), sha256) land with W1 (loader admit).
    _stub: PhantomData<()>,
}

pub struct Instance {
    // W0-ABI: the private fields `image: Arc<Image>` (keeps the image mapped; dropped after `close` returns),
    // `plugin: NonNull<Plugin>` (points into `image`), `lease: SlotLease` (the slot record's lease, §11.2; a
    // plugin-loader type) and `inst: *const c_void` are one `_stub` here; they land with W1-H1 together with
    // the IF's `Send`/`Sync` impls for `Instance` (omitted: rule 2).
    _stub: PhantomData<Arc<Image>>,
    pub kind: KindCode,
    /// The verified stamp name.
    pub identity: Arc<str>,
    /// The configured instance name (§10.3 `Caller::name`).
    pub name: Arc<str>,
    pub id: u64,
    /// Watchdog slot (index into the registry's slot table, < 2^24).
    pub slot: u32,
    /// Round 8 (§12.22), copied into every `Caller`.
    pub limits: InstanceLimits,
    pub max_out: usize,
    pub methods: u64,
    pub facts: u64,
    /// This instance's scrub set (§12.16), filled by custody as it resolves secrets for it.
    pub scrub: Arc<Scrub>,
    // Round 14: `ceilings_us` and `state` moved into the slot's `SlotCell` (§11.2), reached through `lease`
    // (`SlotLease::cell()`, one pointer, cells never move), so the watchdog reads ceilings and quarantines through
    // the slot alone and Image-owned entries have the same row and target.
}
impl Instance {
    /// One Acquire load of the slot's state word (LIVE in this lease's epoch).
    pub fn is_live(&self) -> bool {
        todo!()
    }
    /// CAS (epoch, LIVE) → (epoch, QUARANTINED) on the slot's state word; the watchdog's `SlotTable::hung` and the
    /// entry guard's FAULT path both land here.
    pub fn quarantine(&self) {
        todo!()
    }
    /// The slot's ceiling row (µs; index = kind method bit 0..=55 or ENTRY_*, §10.6).
    pub fn ceilings_us(&self) -> &[core::sync::atomic::AtomicU32; 64] {
        todo!()
    }
    pub fn image(&self) -> &Arc<Image> {
        todo!()
    }
}
// W0-ABI: `impl Drop for Instance` (IF §10.4: `close` runs inline under `entry::guard` with the Image owner,
// then the lease is released, `Arc<Image>` last) lands with W1-H1.

/// Round 14: built by the adapter per async call (plain stores: `Caller<'a>` is Copy and borrows, §10.3) and
/// borrowed by the proxy future for its whole life (round 15: `drv: &'a mut Driver<'a, N>`, §10.4, exclusive, so
/// no second chain can borrow it); the `ChainGuard` reborrows `&drv.caller` shared, so no field is moved or
/// cloned out of it.
/// **Round 15: one Driver is one chain.** Fields are private and `Driver::new` is the only constructor, so every
/// Driver carries a fresh `caller.chain` (§10.3 `next_chain`), and the proxy methods take `&'a mut Driver`
/// (§10.4), so the borrow checker refuses two concurrent futures on one Driver (two live chains can never share
/// a chain id). The adapter builds one per async call, on its stack or in its port future.
pub struct Driver<'a, N: Needs> {
    needs: &'a N,
    caller: Caller<'a>,
    max_steps: u32,
}
impl<'a, N: Needs> Driver<'a, N> {
    /// Sets `caller.chain = next_chain()` (whatever the adapter wrote is overwritten); `max_steps` = 10,000.
    pub fn new(needs: &'a N, caller: Caller<'a>) -> Self {
        let _ = (needs, caller);
        todo!()
    }
    /// Override the step cap (tests, Image-owned chains); never touches `chain`.
    pub fn with_max_steps(self, max_steps: u32) -> Self {
        let _ = (&self.needs, &self.caller, &self.max_steps, max_steps);
        todo!()
    }
    pub fn caller(&self) -> &Caller<'a> {
        let _ = (&self.needs, &self.caller, &self.max_steps);
        todo!()
    }
}

// W0-ABI: `pub(crate) enum ChainOwner<'a> { Instance(&'a Instance), Image { image: Arc<Image>, plugin:
// NonNull<Plugin>, lease: SlotLease } }` with `inst_ptr`/`entry_owner` and its `Send`/`Sync` impls (IF §10.5),
// and `pub(crate) struct ChainGuard<'a, N: Needs> { owner, needs, caller, vt_resume: RawResume, vt_cancel:
// RawCancel, tok: Token, needed: bool, bufs: ChainBufs }` with its Drop rule (IF §10.5) land with W1-H1: they
// are crate-private with no caller in wave 0 (dead code), `SlotLease` is a plugin-loader type, the Send/Sync
// impls are rule-2 items, and `RawResume`/`RawCancel` are raw entry fn-pointer types.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{Reply, Writer};
    use zerocopy::IntoBytes;

    /// A NEED body: the Pod (lens filled in) and its four arguments back to back.
    fn body(
        op: u32,
        flags: u32,
        a: u64,
        b: u64,
        secret: u32,
        trust: u32,
        args: [&[u8]; 4],
    ) -> Vec<u8> {
        let rec = NeedRec {
            op,
            flags,
            a,
            b,
            secret,
            trust,
            lens: args.map(|arg| arg.len() as u32),
        };
        let mut bytes = rec.as_bytes().to_vec();
        for arg in args {
            bytes.extend_from_slice(arg);
        }
        bytes
    }
    const E: &[u8] = &[];

    const DEST: &[u8] = b"db:5432";

    #[test]
    fn open_rows() {
        let ok = |flags: u32, secret: u32, trust: u32, args: [&[u8]; 4]| {
            decode_need_owned(op::OPEN, flags, 0, 0, secret, trust, args)
        };
        let plain = [DEST, E, E, E];
        assert!(matches!(
            ok(0, 0, 0, plain),
            Ok(Shape::Open(TlsKind::None, 0))
        ));
        assert!(matches!(
            ok(1 | (3 << 16), 0, 2, [DEST, &b"db"[..], &b"h2"[..], E]),
            Ok(Shape::Open(TlsKind::Required, 3))
        ));
        assert!(matches!(
            ok(2, 5, 0, plain),
            Ok(Shape::Open(TlsKind::Mutual, 0))
        ));
        assert!(matches!(
            ok(3, 0, 0, plain),
            Ok(Shape::Open(TlsKind::Inband(false), 0))
        ));
        assert!(matches!(
            ok(3, 4, 0, plain),
            Ok(Shape::Open(TlsKind::Inband(true), 0))
        ));
        let bad: [(u32, u32, u32, [&[u8]; 4], &str); 11] = [
            (2, 0, 0, plain, "MUTUAL without a cert"),
            (4, 0, 0, plain, "a mode past INBAND"),
            (5 << 16, 0, 0, plain, "an egress class past 4"),
            (0x200, 0, 0, plain, "the retired unverified bit"),
            (0x100, 0, 0, plain, "REUSABLE is CLOSE's"),
            (0, 1, 0, plain, "a cert on a plaintext dial"),
            (
                0,
                0,
                0,
                [DEST, &b"sni"[..], E, E],
                "SNI on a plaintext dial",
            ),
            (0, 0, 0, [E; 4], "no dest"),
            (0, 0, 0, [&[0xFF][..], E, E, E], "a dest that is not UTF-8"),
            (0, 0, 0, [DEST, E, E, &b"x"[..]], "an unused argument"),
            (1, 3, 0, plain, "a cert on REQUIRED"),
        ];
        for (flags, secret, trust, args, why) in bad {
            assert_eq!(
                ok(flags, secret, trust, args).err(),
                Some(NeedErr::Invalid),
                "{why}"
            );
        }
    }

    #[test]
    fn a_need_whose_lengths_do_not_add_up_is_invalid() {
        let mut bytes = body(op::SECRET, 0, 0, 0, 1, 0, [E; 4]);
        bytes.push(0);
        assert_eq!(
            decode_need(&bytes).err(),
            Some(NeedErr::Invalid),
            "a trailing byte"
        );
        let mut rec = NeedRec::read_from_prefix(&body(op::WRITE, 0, 1, 0, 0, 0, [b"abc", E, E, E]))
            .map(|(rec, _)| rec)
            .expect("pod");
        rec.lens[0] = 9;
        let mut short = rec.as_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert_eq!(
            decode_need(&short).err(),
            Some(NeedErr::Invalid),
            "an argument past the body"
        );
        assert_eq!(
            decode_need(&[0u8; 8]).err(),
            Some(NeedErr::Invalid),
            "shorter than NeedRec"
        );
        assert_eq!(
            decode_need(&body(0, 0, 0, 0, 0, 0, [E; 4])).err(),
            Some(NeedErr::Invalid),
            "op 0"
        );
        assert_eq!(
            decode_need(&body(10, 0, 0, 0, 0, 0, [E; 4])).err(),
            Some(NeedErr::Invalid),
            "op 10"
        );
    }

    #[test]
    fn the_need_row_is_the_kind_table() {
        use KindCode::*;
        let row = |kind, open| {
            let r = NeedRow::of(kind, open);
            [
                op::OPEN,
                op::STARTTLS,
                op::WRITE,
                op::READ,
                op::CLOSE,
                op::FETCH,
                op::SECRET,
                op::RECORD,
                op::DIRECTORY,
            ]
            .map(|op| r.allows(op))
        };
        let (y, n) = (true, false);
        assert_eq!(row(Store, false), [y, y, y, y, y, n, y, n, n]);
        assert_eq!(row(Secret, false), [y, y, y, y, y, y, y, n, n]);
        assert_eq!(row(Auth, false), [y, y, y, y, y, y, y, y, n]);
        assert_eq!(row(Hook, false), [n, n, n, n, n, y, y, y, n]);
        assert_eq!(row(Export, false), [y, y, y, y, y, y, y, n, n]);
        assert_eq!(row(Plane, false), [n, n, n, n, n, y, y, y, n]);
        assert_eq!(row(Transport, false), [n; 9]);
        assert_eq!(row(Transport, true), [n, n, n, n, n, n, y, n, n]);
        for kind in KindCode::ALL {
            if kind != Transport {
                assert_eq!(
                    NeedRow::of(kind, true),
                    NeedRow::of(kind, false),
                    "{kind:?}: open uses the kind's row"
                );
            }
        }
        assert!(
            NeedRow::of(Auth, false)
                .with_directory()
                .allows(op::DIRECTORY)
        );
        assert!((0..32).all(|op| !NeedRow::EMPTY.allows(op)));
        assert!(!NeedRow::of(Auth, false).allows(0) && !NeedRow::of(Auth, false).allows(16));
    }

    #[test]
    fn a_need_answer_is_checked_before_any_need_runs() {
        let row = NeedRow::of(KindCode::Secret, false);
        let tok: Token = (1 << 32) | 3;
        let answer = |token: Option<u64>, needs: &[u32], extra: Option<u16>| {
            let mut r = Reply::new();
            for &op in needs {
                r.put(tag::NEED, &body(op, 0, 0, 0, 1, 0, [E; 4]))
                    .expect("need");
            }
            if let Some(token) = token {
                r.put_pod(tag::TOKEN, &TokenRec { token }).expect("token");
            }
            if let Some(t) = extra {
                r.put(t, b"x").expect("extra");
            }
            r.as_bytes().to_vec()
        };
        assert_eq!(
            check_need_answer(&answer(Some(tok), &[op::SECRET; 2], None), tok, row),
            Ok(2)
        );
        assert_eq!(
            check_need_answer(&answer(None, &[op::SECRET], None), tok, row),
            Err(FaultReason::MissingToken)
        );
        assert_eq!(
            check_need_answer(&answer(Some(tok + 1), &[op::SECRET], None), tok, row),
            Err(FaultReason::BadToken),
            "a TOKEN that is not this chain's"
        );
        assert_eq!(
            check_need_answer(&answer(Some(tok), &[op::RECORD], None), tok, row),
            Err(FaultReason::NeedNotAllowed(op::RECORD))
        );
        assert_eq!(
            check_need_answer(&answer(Some(tok), &[], None), tok, row),
            Err(FaultReason::BadRecords(RecErr::Size)),
            "a NEED answer with no NEED"
        );
        assert_eq!(
            check_need_answer(&answer(Some(tok), &[op::SECRET; 65], None), tok, row),
            Err(FaultReason::BadRecords(RecErr::Size)),
            "65 NEEDs"
        );
        assert_eq!(
            check_need_answer(
                &answer(Some(tok), &[op::SECRET], Some(tag::ERROR)),
                tok,
                row
            ),
            Err(FaultReason::UnknownTag(tag::ERROR))
        );
        let mut two = answer(Some(tok), &[op::SECRET], None);
        two.extend(answer(Some(tok), &[], None));
        assert_eq!(
            check_need_answer(&two, tok, row),
            Err(FaultReason::BadToken),
            "two TOKENs"
        );
    }

    #[test]
    fn the_chain_guard_is_send() {
        struct NoNeeds;
        impl Needs for NoNeeds {
            async fn open(
                &self,
                _: &Caller<'_>,
                _: OpenNeed<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn starttls(
                &self,
                _: &Caller<'_>,
                _: ConnId,
                _: TlsMode<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn write(
                &self,
                _: &Caller<'_>,
                _: ConnId,
                _: &[u8],
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn read(
                &self,
                _: &Caller<'_>,
                _: ConnId,
                _: u32,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn close(&self, _: &Caller<'_>, _: ConnId, _: bool) {}
            async fn fetch(
                &self,
                _: &Caller<'_>,
                _: FetchNeed<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn secret(
                &self,
                _: &Caller<'_>,
                _: u32,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn record(
                &self,
                _: &Caller<'_>,
                _: RecordNeed<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn directory(
                &self,
                _: &Caller<'_>,
                _: DirNeed<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            fn release(&self, _: &Caller<'_>) {}
        }
        fn send<T: Send>() {}
        send::<ChainGuard<'static, 'static, NoNeeds, busbar_ffi::kind::Secret>>();
        send::<First<'static, busbar_ffi::kind::Store>>();
        send::<Finished<busbar_ffi::kind::Plane>>();
    }

    /// The decoded shape, for the row tests above.
    #[derive(Debug)]
    enum TlsKind {
        None,
        Required,
        Mutual,
        Inband(bool),
    }
    #[derive(Debug)]
    enum Shape {
        Open(TlsKind, u32),
    }
    fn decode_need_owned(
        op: u32,
        flags: u32,
        a: u64,
        b: u64,
        secret: u32,
        trust: u32,
        args: [&[u8]; 4],
    ) -> Result<Shape, NeedErr> {
        let bytes = body(op, flags, a, b, secret, trust, args);
        match decode_need(&bytes)? {
            Need::Open(OpenNeed { tls, egress, .. }) => Ok(Shape::Open(
                match tls {
                    TlsMode::None => TlsKind::None,
                    TlsMode::Required { .. } => TlsKind::Required,
                    TlsMode::Mutual { .. } => TlsKind::Mutual,
                    TlsMode::Inband { cert, .. } => TlsKind::Inband(cert.is_some()),
                },
                egress,
            )),
            _ => Err(NeedErr::Invalid),
        }
    }
}
