// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r42 §3 step 1, decided by the seam from the one field.

use super::*;

#[test]
fn native_refusal_uses_its_own_verdict_and_full_width_count() {
    assert_eq!(
        native_admission_refusal(9, Err("key resolver refused".to_owned())),
        "CONFIG: key resolver refused"
    );
    let message = native_admission_refusal(u64::MAX, Ok(false));
    assert!(message.contains("18446744073709551615"));
    assert!(message.contains("Set `auth.signing_key`"));
}

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
    let stepped = step1(&config, true, false, &accept);
    assert!(matches!(stepped, Ok(None)), "{stepped:?}");
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
        placement: busbar_migrate::BagPlacement::Settings,
        allowed_lifts: Default::default(),
        known_secrets: Vec::new(),
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

// ---- Step 4 and 5S/5C over the opened store (MIGRATE-ON-BOOT r42 §3 4a, 4b, 5; §6; §9 C2) ----

mod records_step {
    use super::Scratch;
    use crate::root::migrate_records::{self, Keys, Store, AUDIT_NS};
    use busbar_contract::persistence::cells::{self, table, Cell, HEADLESS, IMPORT_NS};
    use busbar_contract::persistence::NamespaceId;
    use busbar_contract::secure::SecureVec;
    use busbar_migrate::records::{Candidate, RecordStore};

    /// A runtime that drives the store while the step blocks on the test thread, as the boot's
    /// runtime drives it while the step runs on a blocking thread.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    fn store(rt: &tokio::runtime::Runtime) -> Store {
        Store::new(
            rt.block_on(crate::root::real_store::core()),
            rt.handle().clone(),
        )
    }

    fn put(store: &Store, ns: NamespaceId, rows: &[(Vec<u8>, Vec<u8>)]) {
        let mut c = Candidate::default();
        for (key, value) in rows {
            c.put
                .push((ns, key.clone(), SecureVec::from(value.clone())));
        }
        assert_eq!(
            store.commit(c).unwrap(),
            busbar_migrate::records::Committed::Applied
        );
    }

    fn all(store: &Store, ns: NamespaceId) -> Vec<(Vec<u8>, Vec<u8>)> {
        store
            .scan(ns, None, 4096)
            .unwrap()
            .rows
            .into_iter()
            .map(|(k, v)| (k, v.to_vec()))
            .collect()
    }

    fn key_row(id: &str) -> (Vec<u8>, Vec<u8>) {
        (
            cells::key(table::KEY, &[Cell::Text(id)]),
            cells::value(&[
                Cell::Text(id),
                Cell::Text("growth"),
                Cell::Text("team"),
                Cell::Null,
                Cell::Text("{}"),
                Cell::Int(1),
                Cell::Text("gh1"),
                Cell::Int(1_700_000_000),
                Cell::Int(1_700_000_100),
                Cell::Null,
                Cell::Null,
                Cell::Int(7),
            ]),
        )
    }

    const PLAIN_SECRET: &str = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";

    fn credential_row(id: &str) -> (Vec<u8>, Vec<u8>) {
        let secret = format!("v1:plain:{PLAIN_SECRET}");
        (
            cells::key(table::CREDENTIAL, &[Cell::Text(id)]),
            cells::value(&[
                Cell::Text(id),
                Cell::Text("vk_1"),
                Cell::Text("sigv4"),
                Cell::Int(0),
                Cell::Text("AKIAEXAMPLE"),
                Cell::Text(&secret),
                Cell::Text("recoverable"),
                Cell::Int(1_700_000_000),
                Cell::Int(1_700_000_000),
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Int(9),
            ]),
        )
    }

    fn usage_row(bucket: &str, window: i64, model: &str) -> (Vec<u8>, Vec<u8>) {
        (
            cells::key(table::USAGE, &[Cell::Text(bucket), Cell::Int(window)]),
            cells::value(&[
                Cell::Int(0),
                Cell::Text(bucket),
                Cell::Int(window),
                Cell::Int(3),
                Cell::Int(2),
                Cell::Text(model),
                Cell::Int(3),
                Cell::Int(2),
                Cell::Int(100),
                Cell::Int(40),
                Cell::Int(0),
                Cell::Int(0),
            ]),
        )
    }

    fn metering_row(model: &str) -> (Vec<u8>, Vec<u8>) {
        let key = [
            Cell::Text("1767225600"),
            Cell::Text("vk_1"),
            Cell::Text("openai"),
            Cell::Text(model),
        ];
        let mut value = key.to_vec();
        value.extend([
            Cell::Text("team"),
            Cell::Text("p1"),
            Cell::Int(3),
            Cell::Int(3),
            Cell::Int(100),
            Cell::Int(5),
            Cell::Int(0),
            Cell::Int(0),
        ]);
        (cells::key(table::METERING, &key), cells::value(&value))
    }

    fn audit_row(seq: i64) -> (Vec<u8>, Vec<u8>) {
        (
            cells::key(table::AUDIT, &[Cell::Int(seq)]),
            cells::value(&[
                Cell::Int(seq),
                Cell::Int(1_700_000_000 + seq),
                Cell::Text("key.create"),
                Cell::Text("vk_1"),
                Cell::Text("ok"),
                Cell::Text("admin"),
                Cell::Text(""),
                Cell::Text("h1"),
            ]),
        )
    }

    fn fold_of(key: &[u8], value: &[u8]) -> i64 {
        if cells::tag_of(key) != Some(table::USAGE) {
            return 1;
        }
        let cells = cells::decode(value).unwrap();
        let headless = matches!(cells[0], Cell::Int(f) if f & HEADLESS != 0);
        i64::from(!headless) + ((cells.len() - 5) / 7) as i64
    }

    /// IMPORT as a store's data step leaves it: `rows` and a SUMMARY that closes over them.
    fn with_summary(rows: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let last = usize::from(table::LAST);
        let mut counts = vec![[0i64; 2]; last + 1];
        for (key, value) in &rows {
            let tag = usize::from(cells::tag_of(key).unwrap());
            counts[tag][0] += fold_of(key, value);
            counts[tag][1] += 1;
        }
        let digest = [0xab; 32];
        let mut summary = vec![Cell::Int(6), Cell::Int(7)];
        for count in counts.iter().skip(1) {
            summary.extend([Cell::Int(count[0]), Cell::Int(count[1]), Cell::Int(0)]);
        }
        summary.extend([Cell::Int(0), Cell::Int(0), Cell::Blob(&digest)]);
        let mut out = rows;
        out.push((cells::key(table::SUMMARY, &[]), cells::value(&summary)));
        out
    }

    fn fixture() -> Vec<(Vec<u8>, Vec<u8>)> {
        with_summary(vec![
            key_row("vk_1"),
            credential_row("cr_1"),
            credential_row("cr_2"),
            usage_row("vk_1", 1_767_225_600, "gpt"),
            usage_row("team", 1_767_225_600, "gpt"),
            metering_row("gpt"),
            metering_row("o1"),
            audit_row(1),
        ])
    }

    fn keyed() -> Keys {
        Keys {
            at_rest: Some(busbar_kernel::governance::at_rest::AtRestKeys::new(
                &[7u8; 32], None,
            )),
            seed: None,
        }
    }

    fn keyless() -> Keys {
        Keys {
            at_rest: None,
            seed: None,
        }
    }

    fn native_key_address() -> busbar_contract::persistence::Address {
        let key = busbar_contract::records::VirtualKey {
            id: "vk_1".to_owned(),
            ..Default::default()
        };
        busbar_kernel::persistence::import_target::records::identity::migration_key(&key)
            .unwrap()
            .remove(0)
            .0
    }

    fn has_native_key(store: &Store) -> bool {
        let address = native_key_address();
        all(store, NamespaceId(address.namespace))
            .iter()
            .any(|(key, _)| *key == address.key)
    }

    /// Red (a)/(sl1), C2: IMPORT rows written by a store's data step become native records over the
    /// real kernel store, the recoverable secrets sealed (never the plaintext), the usage and metering
    /// index rows they share written once; the final commit consumes SUMMARY, IMPORT is empty, and a
    /// stamped boot's audit is MIGRATION_COMPLETED.
    #[test]
    fn import_rows_become_native_records_sealed_and_import_is_emptied() {
        let rt = runtime();
        let store = store(&rt);
        put(&store, IMPORT_NS, &fixture());
        let scratch = Scratch::new("records-a");
        let config = scratch.config(super::CONFIG_1_5_5);
        let report = migrate_records::run_blocking(&store, &keyed(), &config, true)
            .expect("the records step runs")
            .expect("IMPORT held rows");
        assert_eq!(report.rows[usize::from(table::KEY)], 1);
        assert_eq!(report.rows[usize::from(table::CREDENTIAL)], 2);
        assert_eq!(report.rows[usize::from(table::USAGE)], 2);
        assert_eq!(report.rows[usize::from(table::METERING)], 2);
        assert!(all(&store, IMPORT_NS).is_empty(), "IMPORT is consumed");
        assert!(has_native_key(&store), "the key is a native record");
        assert!(
            native_rows_mentioning(&store, PLAIN_SECRET.as_bytes()).is_empty()
                && native_rows_mentioning(&store, b"v1:plain:").is_empty(),
            "no plaintext secret reaches a native record"
        );
        let audits = all(&store, AUDIT_NS);
        assert_eq!(audits.len(), 1);
        assert!(audits[0].0.starts_with(b"MIGRATION_COMPLETED/"));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Every identity row (the key and credential namespaces) whose bytes mention `needle`.
    fn native_rows_mentioning(store: &Store, needle: &[u8]) -> Vec<Vec<u8>> {
        use busbar_kernel::persistence::import_target::records::identity::{
            CONFIDENTIAL, NAMESPACE,
        };
        [NAMESPACE, CONFIDENTIAL]
            .into_iter()
            .flat_map(|ns| all(store, ns))
            .filter(|(_, value)| contains(value, needle))
            .map(|(_, value)| value)
            .collect()
    }

    /// Red (sl1b)/(sl5)(5), C2: plain rows reach the step and no at-rest key is configured (a
    /// stamped, records-pending boot whose key was removed, or a store that skipped its gate): CONFIG
    /// with the "already migrated by its plugin" text, IMPORT byte-identical, no native record.
    #[test]
    fn plain_rows_without_a_key_refuse_config_and_import_is_untouched() {
        let rt = runtime();
        let store = store(&rt);
        put(&store, IMPORT_NS, &fixture());
        let before = all(&store, IMPORT_NS);
        let scratch = Scratch::new("records-sl1b");
        let config = scratch.config(super::CONFIG_1_5_5);
        let refused = migrate_records::run_blocking(&store, &keyless(), &config, true).unwrap_err();
        assert!(refused.starts_with("CONFIG: "), "{refused}");
        assert!(
            refused.contains("already migrated by its plugin"),
            "{refused}"
        );
        assert_eq!(all(&store, IMPORT_NS), before, "IMPORT is byte-identical");
        assert!(!has_native_key(&store), "no native record was written");
        assert!(all(&store, AUDIT_NS).is_empty());
    }

    /// Red (c), C2: a native record already where a 1.5.5 row lands → VERIFY, nothing of the page
    /// written, IMPORT byte-identical.
    #[test]
    fn a_pre_existing_native_address_is_refused_verify() {
        let rt = runtime();
        let store = store(&rt);
        put(&store, IMPORT_NS, &fixture());
        let address = native_key_address();
        put(
            &store,
            NamespaceId(address.namespace),
            &[(address.key.clone(), b"foreign".to_vec())],
        );
        let before = all(&store, IMPORT_NS);
        let scratch = Scratch::new("records-c");
        let config = scratch.config(super::CONFIG_1_5_5);
        let refused = migrate_records::run_blocking(&store, &keyed(), &config, true).unwrap_err();
        assert!(refused.starts_with("VERIFY: "), "{refused}");
        assert_eq!(all(&store, IMPORT_NS), before);
    }

    /// Red (i), C2: SUMMARY counts one more source row than IMPORT holds → VERIFY before any core
    /// commit: no native record, IMPORT byte-identical.
    #[test]
    fn counts_that_do_not_close_refuse_verify_before_any_commit() {
        let rt = runtime();
        let store = store(&rt);
        let mut rows = fixture();
        rows.retain(|(key, _)| cells::tag_of(key) != Some(table::AUDIT));
        // The SUMMARY still counts the dropped AUDIT row.
        put(&store, IMPORT_NS, &rows);
        let before = all(&store, IMPORT_NS);
        let scratch = Scratch::new("records-i");
        let config = scratch.config(super::CONFIG_1_5_5);
        let refused = migrate_records::run_blocking(&store, &keyed(), &config, true).unwrap_err();
        assert!(refused.starts_with("VERIFY: "), "{refused}");
        assert_eq!(all(&store, IMPORT_NS), before);
        assert!(!has_native_key(&store));
    }

    /// Stamped-path cost (257c): an empty IMPORT is one one-row scan, nothing written, nothing settled.
    #[test]
    fn an_empty_import_writes_nothing() {
        let rt = runtime();
        let store = store(&rt);
        let scratch = Scratch::new("records-empty");
        let config = scratch.config(super::CONFIG_1_5_5);
        assert_eq!(
            migrate_records::run_blocking(&store, &keyless(), &config, true),
            Ok(None)
        );
        assert!(all(&store, AUDIT_NS).is_empty());
    }

    /// 4b (§A6 "Attempts"): an attempt past its expiry that this directory never stamped is
    /// MIGRATION_ABANDONED; the one whose 5d ran here (the marker names it, config.yaml is stamped
    /// with the bytes it recorded) is MIGRATION_COMPLETED; both leave IMPORT.
    #[test]
    fn step4_settles_the_attempts() {
        use busbar_migrate::records::attempts;
        let rt = runtime();
        let store = store(&rt);
        let scratch = Scratch::new("records-attempts");
        let stamped = "config_version: 1\nlisten: 127.0.0.1:0\nstore: {module: memory}\n";
        let config = scratch.config(stamped);
        let mine = attempts::Attempt {
            digest: [1; 32],
            nonce: [2; 16],
            expires_at: u64::MAX,
            written_sha256: busbar_contract::crypto::sha256_parts(&[stamped.as_bytes()]),
        };
        let stale = attempts::Attempt {
            digest: [1; 32],
            nonce: [3; 16],
            expires_at: 1,
            written_sha256: [0; 32],
        };
        attempts::begin(&store, &mine).unwrap();
        attempts::begin(&store, &stale).unwrap();
        std::fs::write(
            migrate_records::attempt_file(&config),
            hex::encode([2u8; 16]),
        )
        .unwrap();
        assert_eq!(
            migrate_records::run_blocking(&store, &keyless(), &config, true),
            Ok(None)
        );
        assert!(
            all(&store, IMPORT_NS).is_empty(),
            "both attempts are settled"
        );
        let mut words: Vec<String> = all(&store, AUDIT_NS)
            .into_iter()
            .map(|(key, _)| {
                String::from_utf8_lossy(&key)
                    .split('/')
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        words.sort();
        assert_eq!(words, ["MIGRATION_ABANDONED", "MIGRATION_COMPLETED"]);
        assert!(
            !migrate_records::attempt_file(&config).exists(),
            "the marker goes once its attempt completed"
        );
    }

    /// #328 (UPG-2): a step-5 refusal fires before the store is converted. The records step and the
    /// write run together, and a document the check refuses leaves IMPORT, the native records and
    /// config.yaml exactly as found.
    #[test]
    fn a_step5_refusal_leaves_the_store_and_config_unconverted() {
        let rt = runtime();
        let store = store(&rt);
        put(&store, IMPORT_NS, &fixture());
        let scratch = Scratch::new("records-328");
        let config = scratch.config(super::CONFIG_1_5_5);
        let plan = super::step1(&config, false, false, &super::accept)
            .unwrap()
            .expect("planned");
        let refused = migrate_records::convert_and_write(
            &store,
            &keyed(),
            &plan,
            &[],
            &|_: &str, _: Option<&str>| Err("a plane refused the settled document".to_owned()),
            &config,
            false,
        )
        .expect_err("the step-5 check refuses");
        assert!(
            refused.contains("a plane refused the settled document"),
            "{refused}"
        );
        assert!(
            !all(&store, IMPORT_NS).is_empty(),
            "IMPORT is untouched: the store was not converted"
        );
        assert!(!has_native_key(&store), "no native record was written");
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            super::CONFIG_1_5_5,
            "config.yaml is unchanged"
        );
    }
    /// 5S, 5d and 5C (§A6 "Attempts", red (n)(9)'s store half): step 5 over the opened store records
    /// the attempt before writing, names it beside config.yaml before the rename, and consumes it
    /// with MIGRATION_COMPLETED once config.yaml is stamped; IMPORT is empty afterwards.
    #[test]
    fn step5_records_and_completes_its_attempt() {
        let rt = runtime();
        let store = store(&rt);
        let scratch = Scratch::new("records-5s");
        let config = scratch.config(super::CONFIG_1_5_5);
        let plan = super::step1(&config, false, false, &super::accept)
            .unwrap()
            .expect("planned");
        let written = migrate_records::write_with_attempt(
            &store,
            &plan,
            &[],
            &|_: &str, _: Option<&str>| Ok(()),
            &config,
        )
        .expect("step 5 writes");
        assert_eq!(written, busbar_migrate::Written::Stamped);
        assert!(all(&store, IMPORT_NS).is_empty(), "the attempt is consumed");
        let audits = all(&store, AUDIT_NS);
        assert_eq!(audits.len(), 1, "one completion record");
        assert!(audits[0].0.starts_with(b"MIGRATION_COMPLETED/"));
        assert!(!migrate_records::attempt_file(&config).exists());
    }

    /// Step 3 (§6a, red (h) with the production chain): a store whose format record a newer busbar
    /// wrote (format 2, or format 1 migrating to 2) is refused NEWER at admission, before any write.
    #[test]
    fn a_newer_format_record_is_refused_newer() {
        let rt = runtime();
        for (format, tail) in [(2u32, 0u32), (1, 2)] {
            let backend = rt.block_on(crate::root::real_store::native_backend());
            let core = rt.block_on(crate::root::real_store::core_over(backend.clone()));
            let store = Store::new(core, rt.handle().clone());
            let address = busbar_kernel::persistence::import_target::target::manifest_address();
            let ns = NamespaceId(address.namespace);
            let (key, mut bytes) = all(&store, ns)
                .into_iter()
                .find(|(key, _)| *key == address.key)
                .expect("the admitted store holds its format record");
            for at in [8, 12, 16, 20] {
                bytes[at..at + 4].copy_from_slice(&format.to_le_bytes());
            }
            bytes[72..76].copy_from_slice(&tail.to_le_bytes());
            put(&store, ns, &[(key, bytes)]);
            let refused = rt
                .block_on(crate::root::boot::admit_format(backend, false))
                .map(drop)
                .unwrap_err();
            assert!(refused.contains("NEWER"), "{refused}");
        }
    }
}

/// #293 (CM-4): removing a retired cloud-metadata carve-out is a warning, and the completed step-5
/// write owes one audit row naming the removed paths, never a value; an uncoded report line stays
/// information and owes no row.
#[test]
fn a_carve_out_removal_warns_and_is_audited_by_path() {
    let removal = format!(
        "{}: removed the retired cloud-metadata carve-out key(s) security.allow_metadata_hosts, \
         providers.bedrock.allow_metadata_hosts; 1.6.0 refuses cloud metadata for every outbound \
         connection and no configuration admits it",
        busbar_kernel::diagnostics::MIGRATE_METADATA_CARVE_OUT_REMOVED.banner()
    );
    let plain = "providers.bedrock.unused_key: removed (1.5.5 ignored this catalog key)".to_owned();
    assert!(warns(&removal), "{removal}");
    assert!(!warns(&plain), "{plain}");
    assert_eq!(
        audit_rows(&[removal, plain]),
        [(
            "migrate.metadata_carve_out_removed",
            "security.allow_metadata_hosts, providers.bedrock.allow_metadata_hosts".to_owned()
        )]
    );
}

/// #293: the binding the migration writes to keep 1.5.5's ungoverned access (BUSBAR-3408) is a
/// security-relevant grant: a warning, and the completed step-5 write owes one audit row per
/// binding naming its path.
#[test]
fn an_ungoverned_binding_grant_warns_and_is_audited_by_path() {
    let grant: String = busbar_kernel::diagnostics::coded::migrate_ungoverned_binding_added(
        "sso",
        "*",
        "every principal it identifies",
    )
    .into();
    assert!(warns(&grant), "{grant}");
    assert_eq!(
        audit_rows(&[grant]),
        [(
            "migrate.ungoverned_binding_added",
            "auth.role_bindings.sso.\"*\"".to_owned()
        )]
    );
}
