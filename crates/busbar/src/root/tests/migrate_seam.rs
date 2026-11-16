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
    assert_eq!(run(&config, false, false), Ok(()));
    std::fs::write(&config, "config_version: 1\nlisten: 0.0.0.0:8080\n").unwrap();
    assert_eq!(run(&config, true, false), Ok(()));
    assert!(PENDING.get().is_none(), "a stamped boot plans nothing");
    std::fs::write(&config, "config_version: 2\nlisten: 0.0.0.0:8080\n").unwrap();
    let refused = run(&config, false, false).unwrap_err();
    assert!(refused.starts_with("NEWER: "), "{refused}");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "step 1 writes nothing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// (sl2)-(sl5) THE RECOVERABLE GATE, core's side (§3 step 2 (a)): `migrate_admit(n)` is answered
/// from core's own config alone. No recoverable row asks nothing; a resolved at-rest key admits;
/// a configured key that did not resolve refuses with the resolver's own text (sl4); no key at all
/// refuses with TEXT_ADD_KEY, naming the count and the absolute config directory (sl2).
#[test]
fn the_recoverable_gate_answers_from_the_at_rest_key() {
    let dir = Path::new("/etc/busbar");
    for keys in [
        None,
        Some(Ok(false)),
        Some(Ok(true)),
        Some(Err("x".to_owned())),
    ] {
        assert_eq!(admit_answer(0, keys.clone(), dir), Ok(()), "{keys:?}");
    }
    assert_eq!(admit_answer(2, Some(Ok(true)), dir), Ok(()));
    let no_key = admit_answer(2, Some(Ok(false)), dir).unwrap_err();
    assert_eq!(no_key, text_add_key(2, dir));
    assert!(
        no_key.starts_with(
            "CONFIG: this 1.5.5 store holds `2` recoverable credentials (SigV4 secret keys) stored \
             in the clear, and 1.6.0 stores them only sealed. Nothing was written."
        ),
        "{no_key}"
    );
    assert!(
        no_key.contains(
            "`openssl rand -hex 32 > /etc/busbar/signing.key && chmod 600 /etc/busbar/signing.key`"
        ),
        "{no_key}"
    );
    assert!(
        no_key.contains("`auth: {signing_key: {file: /etc/busbar/signing.key}}`"),
        "{no_key}"
    );
    let unresolved = admit_answer(
        2,
        Some(Err("auth.signing_key did not resolve: gone".to_owned())),
        dir,
    )
    .unwrap_err();
    assert_eq!(unresolved, "CONFIG: auth.signing_key did not resolve: gone");
    let unknown = admit_answer(1, None, dir).unwrap_err();
    assert!(unknown.starts_with("CONFIG: "), "{unknown}");
    assert_ne!(unknown, text_add_key(1, dir), "no verdict is not 'no key'");
}

/// TEXT_ADD_KEY names an absolute directory, whatever path the boot was given.
#[test]
fn the_gate_names_the_absolute_config_directory() {
    let relative = config_dir(Path::new("config.yaml"));
    assert!(relative.is_absolute(), "{}", relative.display());
    assert_eq!(relative, std::env::current_dir().unwrap());
    assert_eq!(
        config_dir(Path::new("/srv/busbar/config.yaml")),
        Path::new("/srv/busbar")
    );
}

/// `run` installs the gate's answer for the loader before anything opens, on every boot (a
/// stamped config can still meet a 1.5.5 store restored beside it).
#[test]
fn run_installs_the_gate_for_the_loader() {
    let _ = run(Path::new("/nonexistent/busbar/config.yaml"), false, false);
    assert!(
        !busbar_plugin_loader::dispatch::migrate::install_admit(migrate_admit),
        "the seam's answer is installed already"
    );
}

/// (f2, r17) a stamped boot reads config.yaml's one field and nothing else: with a writable
/// regular file at the default overlay path and at `$BUSBAR_CONFIG_OVERLAY`, step 1 opens exactly
/// one path (config.yaml) and reads no environment variable but the re-exec marker.
#[test]
fn a_stamped_boot_reads_config_yaml_alone() {
    use std::cell::RefCell;
    let dir = std::env::temp_dir().join(format!("busbar-migrate-seam-f2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.yaml");
    std::fs::write(&config, "config_version: 1\nlisten: 0.0.0.0:8080\n").unwrap();
    std::fs::write(dir.join("busbar-overlay.json"), r#"{"groups":{"G":{}}}"#).unwrap();
    let selected = dir.join("selected.json");
    std::fs::write(&selected, r#"{"groups":{"G":{}}}"#).unwrap();
    let paths = RefCell::new(Vec::new());
    let variables = RefCell::new(Vec::new());
    let env = |name: &str| {
        variables.borrow_mut().push(name.to_owned());
        (name == "BUSBAR_CONFIG_OVERLAY").then(|| selected.clone().into_os_string())
    };
    let read = |path: &Path| {
        paths.borrow_mut().push(path.to_path_buf());
        read_config(path)
    };
    let probe = Probe {
        env: &env,
        read: &read,
    };
    assert_eq!(run_in(&config, false, false, &probe), Ok(()));
    assert_eq!(*paths.borrow(), [config.clone()]);
    assert!(
        !variables
            .borrow()
            .iter()
            .any(|name| name == "BUSBAR_CONFIG_OVERLAY"),
        "{:?}",
        variables.borrow()
    );
    assert!(PENDING.get().is_none());
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

    /// config.yaml with `text`, beside the providers.yaml a 1.5.5 deployment reads (§3 1k).
    fn config(&self, text: &str) -> std::path::PathBuf {
        std::fs::write(self.0.join("providers.yaml"), "{}\n").unwrap();
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

/// CHECK parses what the boot reads: the planned text after the boot's Strict interpolation. An
/// unset variable is the interpolation's refusal (1.5.5 would not have booted), before any parse.
/// The migration interpolates (1t, proof three), so step 1 is driven whole and the parse never
/// sees the template.
#[test]
fn the_planned_document_is_checked_interpolated_as_the_boot_reads_it() {
    let unset = "BUSBAR_MIGRATE_SEAM_TEST_NEVER_SET";
    let scratch = Scratch::new("interpolated");
    let config = scratch.config(&format!(
        "public_url: ${{{unset}}}\nstore: {{module: memory}}\n"
    ));
    let parsed = std::cell::Cell::new(false);
    let parse = |_: &str| -> Result<Vec<String>, String> {
        parsed.set(true);
        Ok(Vec::new())
    };
    let refused = step1(&config, false, false, &parse).unwrap_err();
    assert!(refused.contains(unset), "{refused}");
    assert!(!parsed.get(), "the template is never parsed");
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
    let written =
        busbar_migrate::write(&plan, &|_: &str, _: Option<&str>| Ok(())).expect("step 5 writes");
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
        2,
        "nothing written beside config.yaml and providers.yaml"
    );
}

/// Step 5's exec, behind its primary rule (every instance is closed first): a descriptor a plugin
/// opened without close-on-exec and never closed does not reach the re-executed image. Nothing
/// else guards it: closing the instances covers only what they still own.
#[cfg(unix)]
#[test]
fn a_descriptor_a_plugin_left_inheritable_does_not_reach_the_new_image() {
    use std::os::fd::AsRawFd;

    let left = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    left.set_cloexec(false).unwrap();
    let fd = left.as_raw_fd();
    assert!(fd >= 3, "{fd}");
    let reaches_a_new_image = || {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("[ -e /dev/fd/{fd} ]"))
            .status()
            .unwrap()
            .success()
    };
    assert!(
        reaches_a_new_image(),
        "the probe sees an inheritable descriptor"
    );
    close_on_exec_from_3();
    assert!(
        !reaches_a_new_image(),
        "descriptor {fd} reached the new image"
    );
}

/// 5W (MIGRATE-ON-BOOT r42 §3): a stamped boot writes what an instance settled back through the patch
/// writer; the same answer twice writes nothing the second time; an operator edit between the read
/// and the write-back keeps the file as the operator left it.
#[test]
fn a_stamped_boot_writes_the_settled_answer_back_once() {
    let scratch = Scratch::new("write-back");
    let stamped = "config_version: 1\nstore: {module: m, settings: {url: old, junk: 1}}\n";
    let config = scratch.config(stamped);
    let settled = [busbar_migrate::Settled {
        index: 0,
        path: vec!["store".to_owned()],
        settings: Some(busbar_contract::secure::SecureString::from(
            r#"{"url": "new"}"#,
        )),
        core_cfg: Vec::new(),
    }];
    assert_eq!(
        write_back_settled(&config, stamped, &settled),
        Ok(busbar_migrate::WroteBack::Written)
    );
    let written = std::fs::read_to_string(&config).unwrap();
    assert!(
        written.contains("url: new") && !written.contains("junk"),
        "{written}"
    );
    assert!(written.starts_with("config_version: 1\n"));
    assert_eq!(
        write_back_settled(&config, &written, &settled),
        Ok(busbar_migrate::WroteBack::Unchanged),
        "equal bytes are not written"
    );
    assert_eq!(
        write_back_settled(&config, stamped, &settled),
        Ok(busbar_migrate::WroteBack::Changed),
        "a file that is no longer the one read is left alone"
    );
    let fragment = [busbar_migrate::Settled {
        core_cfg: vec![busbar_migrate::CoreCfg {
            section: busbar_migrate::core_cfg_section::LIMITS,
            name: String::new(),
            value: busbar_contract::yaml::from_str(r#"{"timeout_ms": 1}"#).unwrap(),
        }],
        ..settled[0].clone()
    }];
    let refused = write_back_settled(&config, &written, &fragment).unwrap_err();
    assert!(
        refused.starts_with("CONFIG: ") && refused.contains("instance 0"),
        "{refused}"
    );
}
