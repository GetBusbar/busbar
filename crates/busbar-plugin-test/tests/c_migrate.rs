// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MIGRATE (ABI-MIN3-INTERFACE §14): Read through `open` and `Open::settled` (round 31, WBS rule 12): every
//! "migrate" below is the plugin's `open`.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! W1-A4's arm: the macro side. A kind declared with `kind!` has no `migrate` slot, so a plugin's migration is
//! its `open`: an older bag opens, and the `open` shim answers INSTANCE then what `Open::settled` wrote (CONFIG,
//! CORE_CFG); a current bag answers INSTANCE alone; newer data refuses R_VERSION NEWER with no instance; and
//! `check` (DRY_RUN) accepts every shape `open` accepts.
use busbar_plugin_abi::fail::{refused, Fail};
use busbar_plugin_abi::host::{Host, HostFns};
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::__rt::host::{OpenAnswer, OutLease};
use busbar_plugin_abi::plugin::__rt::image::Admitted;
use busbar_plugin_abi::plugin::__rt::kind as marker;
use busbar_plugin_abi::plugin::{Endpoints, Open, OPEN_DRY_RUN};
use busbar_plugin_abi::records::{core_cfg, settled, tag, CoreCfgRec, FailRec, Full, Out, Records};
use busbar_plugin_abi::types::Status;

busbar_plugin_abi::kind! {
    /// A secret-shaped kind for this case.
    pub trait Source: kind = 2, abi = 2 {
        views {}
        pods {}
        tags { VALUE = 0x0100; }
        consts { REQUIRED: u64 = 0b1; }
        async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
            let _ = (h, reference);
            Err(busbar_plugin_abi::fail::Fail::unsupported())
        }
    }
}

const V1: &[u8] = br#"{"v":1,"timeout":500}"#;
const V2: &[u8] = br#"{"v":2}"#;
const V3: &[u8] = br#"{"v":3}"#;

/// The plugin value remembers whether `open` converted an older bag.
pub struct Fx {
    converted: bool,
}
impl Source for Fx {}

fn shape(config: &[u8]) -> Result<bool, Fail> {
    match config {
        V1 => Ok(true),
        V2 => Ok(false),
        V3 => Err(Fail::refused_because(
            refused::R_VERSION,
            "NEWER: settings version 3; this plugin knows 2",
        )),
        _ => Err(Fail::refused(refused::R_VERSION)),
    }
}

impl Open for Fx {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        let converted = shape(&config.to_vec())?;
        Ok(Fx { converted })
    }
    fn settled(&self, w: &mut Out<'_>) -> Result<(), Full> {
        if self.converted {
            settled::config(w, V2)?;
            settled::core_cfg(w, core_cfg::LIMITS, "timeout_ms", b"500")?;
        }
        Ok(())
    }
    fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        shape(config).map(|_| ())
    }
}

busbar_plugin_abi::plugin!(@kind [secret] Fx);

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
        migrate_admit: None,
    },
);

/// (status, an instance was built, the answer's tags, the answer's bytes).
fn open(config: &[u8], flags: u32) -> (Status, bool, Vec<u16>, Vec<u8>) {
    let admitted = match Admitted::linked(&PLUGIN) {
        Ok(admitted) => admitted,
        Err(e) => panic!("admit: {e:?}"),
    };
    let mut out = OutLease::new(vec![0; 4096], 1 << 20).expect("a free ACTIVE slot");
    let OpenAnswer::Done(status, instance) =
        admitted.open::<marker::Secret>(&HOST, config.to_vec(), flags, &mut out)
    else {
        panic!("an open that needs nothing answers at once");
    };
    let answer = out.with_answer(<[u8]>::to_vec);
    let tags = Records::new(&answer)
        .map(|rec| rec.expect("framing").tag)
        .collect();
    (status, instance.is_some(), tags, answer)
}

#[test]
fn the_macro_echo_and_the_settled_shim() {
    // An older bag: INSTANCE, then the canonical bag and the core config it used to hold.
    let (status, built, tags, answer) = open(V1, 0);
    assert_eq!((status, built), (Status::OK, true));
    assert_eq!(tags, [tag::INSTANCE, tag::CONFIG, tag::CORE_CFG]);
    let recs: Vec<_> = Records::new(&answer).map(|r| r.expect("rec")).collect();
    assert_eq!(recs[1].body, V2, "CONFIG is the canonical bag");
    let (head, tail) = recs[2].pod_tail::<CoreCfgRec>().expect("core cfg");
    assert_eq!(head.section, core_cfg::LIMITS);
    assert_eq!(&tail[..head.name_len as usize], b"timeout_ms");
    assert_eq!(&tail[head.name_len as usize..], b"500");

    // A current bag: INSTANCE alone (the default `settled` writes nothing).
    let (status, built, tags, _) = open(V2, 0);
    assert_eq!(
        (status, built, tags),
        (Status::OK, true, vec![tag::INSTANCE])
    );

    // Newer data: REFUSED R_VERSION, text NEWER, and no instance.
    let (status, built, tags, answer) = open(V3, 0);
    assert_eq!(
        (status, built, tags),
        (Status::REFUSED, false, vec![tag::FAIL])
    );
    let rec = Records::new(&answer).next().expect("one").expect("rec");
    let (head, text) = rec.pod_tail::<FailRec>().expect("fail");
    assert_eq!(head.code, refused::R_VERSION);
    assert!(text.starts_with(b"NEWER"));

    // DRY_RUN: `check` accepts every shape `open` accepts, and builds nothing.
    for config in [V1, V2] {
        let (status, built, tags, _) = open(config, OPEN_DRY_RUN);
        assert_eq!((status, built, tags), (Status::OK, false, vec![]));
    }
    let (status, built, _, _) = open(V3, OPEN_DRY_RUN);
    assert_eq!((status, built), (Status::REFUSED, false));
}

#[test]
#[ignore = "owner: W1-L2 + W1-K9; blocked (re-checked on dev 2026-11-16): the CORE_CFG collision clause runs as busbar_migrate::settle::tests::a_named_section_is_one_entry_when_two_instances_state_it_identically_else_refused; the $secret round trip, the invented n and the former_names mismatch need a booted fixture's settled answer through the boot, and the boot passes none (busbar root::migrate::finish() calls finish_settled(Vec::new()), no Registry::take_settled: K9 remainder)"]
fn core_cfg_conflicts_secret_round_trip_and_former_names_mismatch() {
    todo!("owner: W1-L2 (C-MIGRATE)")
}

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): the boot writes no settled answer back: busbar root::migrate::write_back_settled is #[cfg(test)] only and finish() passes finish_settled an empty list (no Registry::take_settled), so a through-boot arm is red. The write-back itself runs as busbar::root::migrate::tests::a_stamped_boot_writes_the_settled_answer_back_once; the through-boot arm then moves there (crates/busbar is a bin crate, so nothing can depend on it)"]
fn the_settled_write_back_through_boot() {
    todo!("owner: W1-K9 (C-MIGRATE)")
}
