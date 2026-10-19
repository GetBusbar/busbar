// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE SIZE PER STRUCT, AT THE HOST (owner ruling 21 and THE DESIGN's R9): the loader and the
//! dispatcher accept exactly one v1 size for every struct a plugin hands them, and refuse any other
//! size, shorter or longer, with a declared code. A field a short struct lacks never reads as
//! "none". Each item of the sweep keeps its own REDs here.

// ── item: every kind tail is exactly its kind's tail ─────────────────────────────────────────────

mod kind_tails {
    use busbar_contract::abi::auth::AuthTail;
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::mechanism::door::{Door, KindTailHead, Statement};
    use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};
    use busbar_contract::abi::plane::{PlaneTail, ANSWER_LAYOUT};
    use busbar_contract::abi::store::StoreTail;
    use busbar_contract::abi::transport::{Claim, FramePiece, TransportTail};

    const NAMES: &[AbiStr] = &[busbar_contract::abi::sdk::door::abi_str("tele")];

    /// A `'static` tail buffer stating `size` bytes, backed by more than any tail, its kind's
    /// load-bearing words set as an honest plugin of that kind sets them.
    fn tail(kind: KindCode, size: usize) -> *const KindTailHead {
        let words = (size.max(512) + 64) / 8;
        let buf: &'static mut [u64] = Box::leak(vec![0_u64; words].into_boxed_slice());
        let p = buf.as_mut_ptr();
        // SAFETY: the buffer is larger than every kind tail, 8-aligned and zeroed (all-zero is a
        // valid value of every tail); each write stays inside it.
        unsafe {
            (*p.cast::<KindTailHead>()).size = size as u32;
            match kind {
                KindCode::Plane => (*p.cast::<PlaneTail>()).answer_layout = ANSWER_LAYOUT,
                KindCode::Transport => {
                    let row: &'static Claim = Box::leak(Box::new(std::mem::zeroed::<Claim>()));
                    let t = &mut *p.cast::<TransportTail>();
                    t.frame_piece_size = std::mem::size_of::<FramePiece>() as u32;
                    t.claim_rows = row;
                    t.claim_rows_len = 1;
                }
                _ => {}
            }
        }
        p.cast_const().cast()
    }

    /// The load path's own Statement read (`validate`, the pack tool's rendering and
    /// `statement_of` all go through it) over a door of `kind` stating `kind_tail`.
    fn load(
        kind: KindCode,
        kind_tail: *const KindTailHead,
    ) -> Result<(), crate::dispatch::LoadError> {
        let (claims, claims_len) = if kind == KindCode::Transport {
            (NAMES.as_ptr(), NAMES.len())
        } else {
            (std::ptr::null(), 0)
        };
        let st: &'static Statement = Box::leak(Box::new(Statement {
            size: std::mem::size_of::<Statement>() as u32,
            kind: kind as u32,
            kind_abi: kind.abi_version(),
            kind_tail,
            claims,
            claims_len,
            ..busbar_contract::abi::sdk::door::statement("sized", "1.0.0", 1)
        }));
        let door = Door {
            magic: DOOR_MAGIC,
            mechanism_version: MECHANISM_VERSION,
            size: std::mem::size_of::<Door>() as u32,
            kind: kind as u32,
            kind_abi: kind.abi_version(),
            statement: st,
            ops: std::ptr::null(),
            ready: None,
        };
        crate::dispatch::load::statement(&door).map(|_| ())
    }

    /// Each kind with a tail, and its tail's one size.
    fn tailed() -> [(KindCode, usize); 6] {
        use std::mem::size_of;
        [
            (KindCode::Store, size_of::<StoreTail>()),
            (KindCode::Auth, size_of::<AuthTail>()),
            (
                KindCode::Hook,
                size_of::<busbar_contract::abi::hook::Tail>(),
            ),
            (
                KindCode::Export,
                size_of::<busbar_contract::abi::export::Tail>(),
            ),
            (KindCode::Plane, size_of::<PlaneTail>()),
            (KindCode::Transport, size_of::<TransportTail>()),
        ]
    }

    /// GREEN: a tail at its kind's one size is admitted.
    #[test]
    fn a_kind_tail_at_its_one_size_is_admitted() {
        for (kind, whole) in tailed() {
            assert_eq!(load(kind, tail(kind, whole)), Ok(()), "{kind:?} at {whole}");
        }
    }

    /// RED (ruling 21): a kind tail of any other size, shorter or longer, is refused at admit. A
    /// short tail is never zero-filled into "none": a plane tail ending before its stream ceiling
    /// never loads with no ceiling, an auth tail of the old 40 bytes never loads with no operator.
    #[test]
    fn a_kind_tail_of_any_other_size_is_refused() {
        for (kind, whole) in tailed() {
            for size in [whole - 8, whole + 8] {
                assert_eq!(
                    load(kind, tail(kind, size)),
                    Err(crate::dispatch::LoadError::KindTailSize {
                        plugin: "sized".into(),
                        kind,
                        stated: size as u32,
                        host: whole as u32,
                    }),
                    "{kind:?}: a {size}-byte tail (its one size is {whole}) is refused"
                );
            }
        }
        let ceiling = std::mem::offset_of!(PlaneTail, stream_ceiling_secs);
        assert!(
            load(KindCode::Plane, tail(KindCode::Plane, ceiling)).is_err(),
            "a plane tail ending before its stream ceiling is refused, never read as no ceiling"
        );
        assert!(
            load(KindCode::Auth, tail(KindCode::Auth, 40)).is_err(),
            "the auth tail's old 40-byte size is refused"
        );
        let faults = std::mem::offset_of!(TransportTail, fault_rows);
        assert!(
            load(KindCode::Transport, tail(KindCode::Transport, faults)).is_err(),
            "a transport tail ending before its fault table is refused"
        );
    }

    /// RED (ruling 21): the secret kind states no tail, so any tail it states is refused.
    #[test]
    fn a_secret_tail_is_refused() {
        assert_eq!(load(KindCode::Secret, std::ptr::null()), Ok(()));
        let refused = load(KindCode::Secret, tail(KindCode::Secret, 8)).unwrap_err();
        assert_eq!(
            refused,
            crate::dispatch::LoadError::KindTailSize {
                plugin: "sized".into(),
                kind: KindCode::Secret,
                stated: 8,
                host: 0,
            }
        );
        assert!(refused.to_string().contains("has no tail"), "{refused}");
    }
}

// ── item: the door and the Statement are each exactly one size ───────────────────────────────────

mod door_and_statement {
    use busbar_contract::abi::mechanism::door::{Door, Statement};
    use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};

    /// A `'static` door stating `size` bytes, over a buffer longer than any door, with a Statement
    /// stating `st_size` bytes over a buffer longer than any Statement.
    fn door(size: usize, st_size: usize) -> *const Door {
        let st_words = (std::mem::size_of::<Statement>() + 64) / 8;
        let st_buf: &'static mut [u64] = Box::leak(vec![0_u64; st_words].into_boxed_slice());
        let st = st_buf.as_mut_ptr().cast::<Statement>();
        let words = (std::mem::size_of::<Door>() + 64) / 8;
        let buf: &'static mut [u64] = Box::leak(vec![0_u64; words].into_boxed_slice());
        let p = buf.as_mut_ptr().cast::<Door>();
        // SAFETY: both buffers are 8-aligned, zeroed and longer than their structs.
        unsafe {
            st.write(Statement {
                size: st_size as u32,
                kind: KindCode::Export as u32,
                kind_abi: KindCode::Export.abi_version(),
                ..busbar_contract::abi::sdk::door::statement("sized", "1.0.0", 1)
            });
            p.write(Door {
                magic: DOOR_MAGIC,
                mechanism_version: MECHANISM_VERSION,
                size: size as u32,
                kind: KindCode::Export as u32,
                kind_abi: KindCode::Export.abi_version(),
                statement: st,
                ops: std::ptr::null(),
                ready: None,
            });
        }
        p
    }

    /// RED (ruling 21): a door of any other size than `size_of::<Door>()` is refused, a door
    /// ending before `ready` included (it never reads as "no ready").
    #[test]
    fn a_door_of_any_other_size_is_refused() {
        let whole = std::mem::size_of::<Door>();
        let st = std::mem::size_of::<Statement>();
        assert!(crate::dispatch::load::read_door(door(whole, st), None).is_ok());
        for size in [std::mem::offset_of!(Door, ready), whole + 8] {
            assert!(
                crate::dispatch::load::read_door(door(size, st), None).is_err(),
                "a {size}-byte door (its one size is {whole}) is refused"
            );
        }
    }

    /// RED (ruling 21): a Statement of any other size than `size_of::<Statement>()` is refused.
    #[test]
    fn a_statement_of_any_other_size_is_refused() {
        let whole = std::mem::size_of::<Door>();
        let st = std::mem::size_of::<Statement>();
        let read = |st_size: usize| {
            // SAFETY: `door` answers a `'static` door over a live Statement.
            let d = unsafe { door(whole, st_size).read() };
            crate::dispatch::load::statement(&d).map(|_| ())
        };
        assert_eq!(read(st), Ok(()));
        for size in [st - 8, st + 8] {
            assert!(read(size).is_err(), "a {size}-byte Statement is refused");
        }
    }
}
