// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin};
use crate::store_v3::LoadedStore;
use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut, ValidateIn};
use busbar_contract::abi::store::{OpId, Ops};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex, OnceLock,
};

#[path = "actual_store.rs"]
mod actual_store;

const REFUSAL: &str = "invalid picky plugin config: `db_path` must be a string, got 5";
static OPENS: AtomicU32 = AtomicU32::new(0);
static TESTS: Mutex<()> = Mutex::new(());

fn parse(settings: &[u8]) -> Result<(), String> {
    match serde_json::from_slice::<serde_json::Value>(settings) {
        Ok(v) if v.get("db_path").is_some_and(|p| !p.is_string()) => Err(REFUSAL.to_string()),
        Ok(_) => Ok(()),
        Err(e) => Err(format!("invalid picky plugin config: {e}")),
    }
}

extern "C" fn validate(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: VALIDATE receives initialized ValidateIn and writable OutHead. Its
    // reason is copied into the host's lent buffer, never a temporary allocation.
    unsafe {
        let input = &*input.cast::<ValidateIn>();
        let out = &mut *output.cast::<OutHead>();
        let settings = std::slice::from_raw_parts(input.settings.ptr, input.settings.len);
        match parse(settings) {
            Ok(()) => {
                out.outcome = RawOutcome::of(Outcome::Ready);
            }
            Err(error) => {
                let len = error.len().min(input.err_cap);
                if len != 0 {
                    std::ptr::copy_nonoverlapping(error.as_ptr(), input.err_buf, len);
                }
                out.error = AbiStr {
                    ptr: input.err_buf.cast_const(),
                    len,
                };
                out.outcome = RawOutcome::of(Outcome::Failed);
            }
        }
        out.outcome
    }
}

extern "C" fn refused_open(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> RawOutcome {
    OPENS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: OPEN lends these exact initialized frames and reason buffer. This
    // existing validation refusal control creates no backend or business state.
    unsafe {
        let input = &*input.cast::<OpenIn>();
        let out = &mut *output.cast::<OpenOut>();
        let settings = std::slice::from_raw_parts(input.settings.ptr, input.settings.len);
        let error = parse(settings).expect_err("this control only opens the invalid configuration");
        let len = error.len().min(input.err_cap);
        if len != 0 {
            std::ptr::copy_nonoverlapping(error.as_ptr(), input.err_buf, len);
        }
        out.err_len = len;
        out.head.outcome = RawOutcome::of(Outcome::Failed);
        out.head.outcome
    }
}

extern "C" fn door() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let address = *DOOR.get_or_init(|| {
        let real = *actual_store::door();
        // SAFETY: actual_store retains the qualified Store's validated descriptor.
        // Only the two existing refusal/validation boundary controls are replaced.
        let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        ops.head.validate = Some(validate);
        ops.head.open = Some(refused_open);
        let ops = Box::leak(Box::new(ops));
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: the immutable validated descriptor and copied table are retained forever.
    unsafe { &*(address as *const Door) }
}

fn mint() -> OpId {
    actual_store::mint()
}
fn load() -> (Plugin<Store>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_linked::<Store>(
        &LinkedRow::of(door).expect("actual Store states itself"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the actual Store descriptor loads");
    (p, d)
}

#[test]
fn a_store_refusal_reaches_the_operator_in_its_own_words() {
    let _serial = TESTS.lock().unwrap();
    let (p, d) = load();
    let name = p.name().to_owned();
    let e = LoadedStore::open(p, d, br#"{"db_path":5}"#, mint).expect_err("refused");
    assert_eq!(
        e,
        format!("plugin '{name}' open failed: {REFUSAL}"),
        "the plugin's refusal words, verbatim"
    );
}

#[test]
fn validate_parses_and_never_opens_the_store() {
    let _serial = TESTS.lock().unwrap();
    let (p, _) = load();
    let before = OPENS.load(Ordering::SeqCst);
    assert_eq!(
        LoadedStore::validate(&p, br#"{"db_path":"/var/lib/busbar.db"}"#),
        Ok(())
    );
    assert_eq!(
        LoadedStore::validate(&p, br#"{"db_path":5}"#),
        Err(REFUSAL.to_string())
    );
    assert_eq!(
        OPENS.load(Ordering::SeqCst),
        before,
        "validate opened the store"
    );
}
