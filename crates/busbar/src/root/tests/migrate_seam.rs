// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r42 §3 step 1, decided by the seam from the one field.

use super::*;

#[test]
fn the_stamp_decides_step_one() {
    assert_eq!(admit(0, false, false), Ok(Stamp::Older(0)));
    assert_eq!(admit(CONFIG_FORMAT, false, false), Ok(Stamp::Current));
    assert_eq!(admit(CONFIG_FORMAT, true, true), Ok(Stamp::Current));
    // (c) a config written by a newer busbar.
    let newer = admit(CONFIG_FORMAT + 1, false, false).unwrap_err();
    assert_eq!(newer.word(), "NEWER");
    assert!(newer.to_string().starts_with("NEWER: "), "{newer}");
    // The re-executed image found no stamp: VERIFY, never a second upgrade.
    assert_eq!(admit(0, true, false), Err(Refusal::Verify));
    // `--providers` on an unstamped config.
    let providers = admit(0, false, true).unwrap_err();
    assert_eq!(providers.word(), "CONFIG");
    assert!(providers.to_string().contains("--providers"), "{providers}");
}

/// (b) a stamped config boots with nothing planned; a newer one is refused before anything runs;
/// an absent one is left to the config reader's own refusal.
#[test]
fn step_one_reads_one_field() {
    let dir = std::env::temp_dir().join(format!("busbar-migrate-seam-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.yaml");
    assert_eq!(run(&config, false), Ok(()));
    std::fs::write(&config, "config_version: 1\nlisten: 0.0.0.0:8080\n").unwrap();
    assert_eq!(run(&config, true), Ok(()));
    assert!(PENDING.get().is_none(), "a stamped boot plans nothing");
    std::fs::write(&config, "config_version: 2\nlisten: 0.0.0.0:8080\n").unwrap();
    let refused = run(&config, false).unwrap_err();
    assert!(refused.starts_with("NEWER: "), "{refused}");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "step 1 writes nothing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A scratch config directory, removed on drop.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("busbar-migrate-seam-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn config(&self, text: &str) -> std::path::PathBuf {
        let path = self.0.join("config.yaml");
        std::fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A 1.5.5 deployment (no stamp).
const CONFIG_1_5_5: &str = "listen: 127.0.0.1:0\nstore: {module: memory}\n";

/// The boot's strict parse as the seam's tests stand it in: it accepts, and names no listener.
fn accept(_: &str) -> Result<Vec<String>, String> {
    Ok(Vec::new())
}

/// §3 step 2, the binding: while a plan is held, the boot reads the planned (stamped) document
/// for config.yaml's own path, and nothing for any other file; a stamped boot holds nothing.
#[test]
fn the_boot_reads_the_planned_document_while_a_plan_is_held() {
    let scratch = Scratch::new("held");
    let config = scratch.config(CONFIG_1_5_5);
    let plan = step1(&config, false, false, &accept)
        .unwrap()
        .expect("an unstamped config is planned");
    let held = held_in(Some(&plan), &config).expect("config.yaml is held");
    assert_eq!(&*held, plan.planned());
    assert_eq!(config_version(&held), Ok(CONFIG_FORMAT));
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        CONFIG_1_5_5,
        "the disk still holds the 1.5.5 bytes, which the boot does not read"
    );
    assert!(held_in(Some(&plan), &scratch.0.join("providers.yaml")).is_none());
    assert!(
        held_in(None, &config).is_none(),
        "a stamped boot holds nothing"
    );
}

/// CHECK parses what the boot reads: the planned text after `interpolate_env_with(Strict)`. An
/// unset variable is the interpolation's refusal (1.5.5 would not have booted), before any parse.
#[test]
fn the_planned_document_is_checked_interpolated_as_the_boot_reads_it() {
    let unset = "BUSBAR_MIGRATE_SEAM_TEST_NEVER_SET";
    let refused = parse_planned(&format!("public_url: ${{{unset}}}\n")).unwrap_err();
    assert!(refused.contains(unset), "{refused}");
}

/// (sz2) cold and once, with the test-build call counter: a stamped config enters no
/// `busbar_migrate` function; an unstamped one plans once, probes its listeners once, writes once,
/// and the process re-executes once, after every instance was closed.
#[test]
fn a_stamped_boot_enters_nothing_and_an_unstamped_one_plans_writes_and_execs_once() {
    use busbar_migrate::counted::entries;

    let scratch = Scratch::new("sz2");
    let config = scratch.config(CONFIG_1_5_5);
    let before = entries();
    let plan = step1(&config, false, false, &accept)
        .unwrap()
        .expect("planned");
    let planned = entries();
    assert_eq!(planned.plan - before.plan, 1, "plan runs once");
    assert_eq!(
        planned.probe - before.probe,
        1,
        "the listener probe runs once"
    );
    assert_eq!(planned.write, before.write, "step 1 writes nothing");

    let order = std::cell::RefCell::new(Vec::new());
    let written = busbar_migrate::write(&plan, &|_: &str| Ok(())).expect("step 5 writes");
    assert_eq!(written, Written::Stamped);
    let failure = restart(
        written,
        "every instance",
        |owned| order.borrow_mut().push(format!("close {owned}")),
        || {
            order.borrow_mut().push("exec".to_owned());
            "exec failed".to_owned()
        },
    );
    assert_eq!(failure, "exec failed");
    assert_eq!(
        order.into_inner(),
        ["close every instance", "exec"],
        "every instance is closed, then the process re-executes, once"
    );
    let done = entries();
    assert_eq!(done.write - before.write, 1, "write runs once");
    assert_eq!(done.plan - before.plan, 1);

    // The re-executed image: stamped, so step 1 enters no busbar_migrate function at all.
    let stamped = entries();
    assert_eq!(step1(&config, true, false, &accept), Ok(None));
    assert_eq!(
        entries(),
        stamped,
        "a stamped boot enters no busbar_migrate function"
    );
}

/// (q) the gateway that lost the race: its write found the peer's stamp (StampedByPeer); it
/// closes its instances and re-executes onto the stamped file, once, like the winner.
#[test]
fn the_gateway_that_finds_a_peer_stamp_closes_and_reexecs() {
    let closed = std::cell::Cell::new(0);
    let execs = std::cell::Cell::new(0);
    let failure = restart(
        Written::StampedByPeer,
        (),
        |()| closed.set(closed.get() + 1),
        || {
            assert_eq!(closed.get(), 1, "closed before the exec");
            execs.set(execs.get() + 1);
            "exec failed".to_owned()
        },
    );
    assert_eq!(failure, "exec failed");
    assert_eq!((closed.get(), execs.get()), (1, 1));
}

/// 1f in step 1: a planned document whose `listen` another process holds is refused LIVE_WRITER
/// before anything is written or opened.
#[test]
fn step_one_refuses_a_listen_address_in_use() {
    let scratch = Scratch::new("listen");
    let config = scratch.config(CONFIG_1_5_5);
    let serving = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = serving.local_addr().unwrap().to_string();
    let parse = |_: &str| -> Result<Vec<String>, String> { Ok(vec![address.clone()]) };
    let refused = step1(&config, false, false, &parse).unwrap_err();
    assert!(refused.starts_with("LIVE_WRITER: "), "{refused}");
    assert!(refused.contains(&address), "{refused}");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), CONFIG_1_5_5);
    assert_eq!(
        std::fs::read_dir(&scratch.0).unwrap().count(),
        1,
        "nothing written"
    );
}
