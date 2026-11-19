// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NULL-EMPTY (ABI-MIN3-INTERFACE §14 round 17): `{ptr, 0}` is the empty value whatever `ptr` is. The safe
//! arm, every empty view a Rust producer can build, is W1-A1's (merged). A raw `{NULL, 0}` or `{misaligned, 0}`
//! has no safe producer (UNSAFE-MIN): the C fixture's arm (a) is W1-A13's, and the host-to-shim arm (b), with
//! (c)'s raw values under Miri and its `from_raw_parts` negative control, is the shim boundary's.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::types::{Bytes, Slice, Str};

#[test]
fn every_empty_view_reads_empty() {
    let tail = [1u8, 2, 3];
    assert!(Bytes::EMPTY.get().is_empty());
    assert!(Bytes::new(&[]).get().is_empty());
    assert!(Bytes::new(&tail[3..]).get().is_empty());
    assert_eq!(Str::EMPTY.get(), "");
    assert_eq!(Str::new("").get(), "");
    assert!(Slice::<'static, Bytes<'static>>::EMPTY.get().is_empty());
    let views = [Bytes::EMPTY];
    assert!(Slice::new(&views[1..]).get().is_empty());
}

#[test]
#[ignore = "blocked: needs a C fixture sending {NULL,0} in CryptoReq fields; no C fixture and no unsafe allowed here (UNSAFE-MIN); owner W1-A13"]
fn a_c_fixture_sends_null_zero_in_every_crypto_req_field() {
    todo!("owner: W1-A13 (C-NULL-EMPTY)")
}

/// W1-A4's shim arm: config and arguments that arrive empty reach the plugin as empty, through DRY_RUN's
/// `check`, `open` and an async method (busbar-ffi's `open`/`start` shims and this crate's `kind!`/`plugin!`).
/// The host's empty buffers are the only empty values a safe host can make (`{dangling, 0}`); the literal
/// `{NULL, 0}` and `{misaligned, 0}` have no safe producer (UNSAFE-MIN), so their arm runs where the types
/// live, under Miri: busbar-ffi `raw::tests::an_empty_view_reads_empty_whatever_its_pointer`.
#[test]
fn raw_null_zero_results_and_config_reach_a_rust_shim_as_empty() {
    use busbar_plugin_abi::plugin::__rt::host::{ChainBufs, OpenAnswer, Started};
    use busbar_plugin_abi::plugin::__rt::kind as marker;
    use busbar_plugin_abi::plugin::OPEN_DRY_RUN;
    use busbar_plugin_abi::types::Status;
    use empty_arm::{admitted, lease, seen, Saw, HOST};

    let mut out = lease();
    let OpenAnswer::Done(status, None) =
        admitted().open::<marker::Secret>(&HOST, Vec::new(), OPEN_DRY_RUN, &mut out)
    else {
        panic!("DRY_RUN builds no instance");
    };
    assert_eq!(status, Status::OK);
    drop(out);
    let mut out = lease();
    let OpenAnswer::Done(Status::OK, Some(inst)) =
        admitted().open::<marker::Secret>(&HOST, Vec::new(), 0, &mut out)
    else {
        panic!("open answers OK with INSTANCE");
    };
    drop(out);
    let mut out = lease();
    let mut bufs = ChainBufs::new();
    let at = bufs.push(Vec::new());
    let started = inst.start(
        busbar_plugin_abi::secret::slot::resolve,
        bufs,
        |bufs, cross| busbar_plugin_abi::secret::pack::resolve(0, bufs.get(at), cross),
        &mut out,
    );
    assert!(matches!(started, Started::Done(Status::OK)));
    drop(started);
    drop(out);
    let mut out = lease();
    let started = inst.start(
        busbar_plugin_abi::secret::slot::resolve,
        ChainBufs::new(),
        |_, cross| busbar_plugin_abi::secret::pack::resolve(0, Bytes::EMPTY, cross),
        &mut out,
    );
    assert!(matches!(started, Started::Done(Status::OK)));
    assert_eq!(
        seen(),
        [
            Saw::Check(0),
            Saw::Open(0),
            Saw::Resolve(0),
            Saw::Resolve(0)
        ]
    );
}

/// The fixture for the shim arm: a secret-shaped plugin that records the length of every input it is given.
mod empty_arm {
    use std::cell::RefCell;

    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::{Host, HostFns};
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plugin::__rt::host::OutLease;
    use busbar_plugin_abi::plugin::__rt::image::Admitted;
    use busbar_plugin_abi::plugin::{Endpoints, Open};
    use busbar_plugin_abi::records::Reply;

    busbar_plugin_abi::kind! {
        /// A secret-shaped kind for this case.
        pub trait Empties: kind = 2, abi = 3 {
            views {}
            pods {}
            tags {}
            consts { REQUIRED: u64 = 0b1; }
            async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail>;
        }
    }

    /// What the plugin was handed, by entry, as a length.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Saw {
        Check(usize),
        Open(usize),
        Resolve(usize),
    }

    std::thread_local! {
        static SAW: RefCell<Vec<Saw>> = const { RefCell::new(Vec::new()) };
    }

    pub fn seen() -> Vec<Saw> {
        SAW.with_borrow_mut(std::mem::take)
    }

    pub struct Fx;
    impl Empties for Fx {
        async fn resolve(&self, _h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
            let len = reference.with(<[u8]>::len);
            SAW.with_borrow_mut(|saw| saw.push(Saw::Resolve(len)));
            Ok(Reply::new())
        }
    }
    impl Open for Fx {
        async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            let len = config.with(<[u8]>::len);
            SAW.with_borrow_mut(|saw| saw.push(Saw::Open(len)));
            Ok(Fx)
        }
        fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            SAW.with_borrow_mut(|saw| saw.push(Saw::Check(config.len())));
            Ok(())
        }
    }

    busbar_plugin_abi::plugin!(@kind [secret] Fx);

    pub static HOST: Host = Host::new(
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

    pub fn lease() -> OutLease<'static> {
        OutLease::new(vec![0; 4096], 1 << 20).expect("a free ACTIVE slot")
    }

    pub fn admitted() -> Admitted {
        match Admitted::linked(&PLUGIN) {
            Ok(admitted) => admitted,
            Err(e) => panic!("admit: {e:?}"),
        }
    }
}
