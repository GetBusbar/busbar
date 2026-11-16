// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r42 §9 C1 reds (a), (b), (c), (e), (r)(2), (u)(1) and (y)(1) for the config chain.

use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::scratch::{accept, facts, Scratch};

/// A 1.5.5 deployment whose core sections 1.6.0 reads unchanged (it names its store: AGREED QM2
/// writes the block a store-less 1.5.5 config implied, which red (j) pins).
const CONFIG_1_5_5: &str = "\
# production gateway
listen: 0.0.0.0:8080   # data plane
admin_listen: '127.0.0.1:8081'

models:
  sonnet:
    provider: anthropic
store:
  module: sqlite
";

/// (c) a file stamped by a newer busbar is never planned.
#[test]
fn a_newer_stamp_is_refused_newer() {
    let scratch = Scratch::new();
    let path = scratch.config("config_version: 2\nlisten: x\n");
    let refused = plan(&Inputs::new(&path, &facts(), &accept)).unwrap_err();
    assert_eq!(refused, Refusal::Newer { found: 2 });
    assert!(refused.to_string().starts_with("NEWER: "), "{refused}");
    assert_eq!(scratch.names(), ["config.yaml"]);
}

#[test]
fn the_one_field_is_config_version() {
    assert_eq!(read_version(CONFIG_1_5_5), Ok(0));
    assert_eq!(read_version("config_version: 1\nlisten: x\n"), Ok(1));
    assert_eq!(read_version("listen: x\nconfig_version: 7\n"), Ok(7));
    assert_eq!(read_version("- a\n- b\n"), Ok(0));
    let refused = read_version("config_version: one\n").unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert_eq!(read_version("a: [\n").unwrap_err().word(), "CONFIG");
}

/// (a) and (u)(1): a 1.5.5 config is rewritten once, in place: `config_version: 1` is its first key,
/// every other byte is the operator's, and `config.yaml.1.5.5` holds the original bytes.
#[test]
fn a_1_5_5_config_is_stamped_once_in_place_with_its_backup() {
    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    let seen = Cell::new(0);
    let check = |text: &str, catalog: Option<&str>| -> Result<(), String> {
        seen.set(seen.get() + 1);
        assert_eq!(read_version(text), Ok(CONFIG_FORMAT));
        assert_eq!(catalog, None, "the 1.5.5 catalog is kept as it is");
        Ok(())
    };
    let plan = plan(&Inputs::new(&path, &facts(), &check)).expect("planned");
    assert_eq!(seen.get(), 1, "plan runs the strict parse once");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        CONFIG_1_5_5,
        "plan writes nothing"
    );
    assert_eq!(scratch.names(), ["config.yaml", "providers.yaml"]);
    assert_eq!(write(&plan, &check), Ok(Written::Stamped));
    let written = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        written,
        "# production gateway\nconfig_version: 1\nlisten: 0.0.0.0:8080   # data plane\n\
         admin_listen: '127.0.0.1:8081'\n\nmodels:\n  sonnet:\n    provider: anthropic\n\
         store:\n  module: sqlite\n"
    );
    assert_eq!(
        std::fs::read_to_string(backup_path(&path)).unwrap(),
        CONFIG_1_5_5
    );
    assert_eq!(
        scratch.names(),
        [
            // 5c: the writable default overlay path is guarded (P), present or absent.
            "busbar-overlay.json",
            "config.yaml",
            "config.yaml.1.5.5",
            "config.yaml.busbar-lock",
            "providers.yaml"
        ],
        "no temporary is left"
    );
    // A stamped file is never planned again.
    let again = super::plan(&Inputs::new(&path, &facts(), &accept)).unwrap_err();
    assert_eq!(again.word(), "CONFIG");
}

/// (b) a peer stamped config.yaml while this boot waited on the lock: nothing is written.
#[test]
fn a_config_stamped_by_a_peer_is_not_written_again() {
    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    let plan = plan(&Inputs::new(&path, &facts(), &accept)).unwrap();
    let peer = patch::stamp(CONFIG_1_5_5, CONFIG_FORMAT).unwrap();
    std::fs::write(&path, &peer).unwrap();
    assert_eq!(write(&plan, &accept), Ok(Written::StampedByPeer));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), peer);
    assert!(!backup_path(&path).exists());
}

/// 5R: config.yaml changed between the plan and the write (a running 1.5.5's admin write).
#[test]
fn a_config_changed_after_the_plan_is_a_live_writer() {
    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    let plan = plan(&Inputs::new(&path, &facts(), &accept)).unwrap();
    let edited = format!("{CONFIG_1_5_5}groups: {{}}\n");
    std::fs::write(&path, &edited).unwrap();
    let refused = write(&plan, &accept).unwrap_err();
    assert_eq!(refused.word(), "LIVE_WRITER", "{refused}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    assert!(!backup_path(&path).exists());
}

/// The strict parse refuses the planned document: its text, then the upgrade line; nothing written.
/// (`budget_period` is a 1.4.x key that no 1.5.5 marker names: it reaches the parse unchanged.)
#[test]
fn a_planned_document_the_strict_parse_refuses_is_config_with_the_upgrade_line() {
    let scratch = Scratch::new();
    let path = scratch.deployment("budget_period: month\nstore: {module: sqlite}\n");
    let refuse = |_: &str, _: Option<&str>| -> Result<(), String> {
        Err("config.yaml: unknown field `budget_period`".to_owned())
    };
    let refused = plan(&Inputs::new(&path, &facts(), &refuse)).unwrap_err();
    let text = refused.to_string();
    assert!(
        text.starts_with("CONFIG: config.yaml: unknown field `budget_period`\n"),
        "{text}"
    );
    assert!(text.ends_with(UPGRADE_FIRST), "{text}");
    assert_eq!(scratch.names(), ["config.yaml", "providers.yaml"]);
}

/// (r)(2): a backup present with other bytes is refused at 5R, nothing written.
#[test]
fn a_backup_with_other_bytes_refuses_the_write() {
    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    let plan = plan(&Inputs::new(&path, &facts(), &accept)).unwrap();
    std::fs::write(backup_path(&path), "listen: elsewhere\n").unwrap();
    let refused = write(&plan, &accept).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(
        refused.to_string().contains("config.yaml.1.5.5"),
        "{refused}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), CONFIG_1_5_5);
}

#[test]
fn a_conflicting_config_backup_refuses_before_store_migration() {
    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    let backup = backup_path(&path);
    std::fs::write(&backup, "listen: elsewhere\n").unwrap();
    let refused = plan(&Inputs::new(&path, &facts(), &accept)).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("config.yaml.1.5.5"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), CONFIG_1_5_5);
    assert_eq!(
        std::fs::read_to_string(backup).unwrap(),
        "listen: elsewhere\n"
    );
}

/// (e): a crash after the backup link and before the rename leaves the original config.yaml and an
/// identical backup; the next boot plans again and converges.
#[test]
fn a_crash_between_backup_and_rename_converges() {
    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    std::fs::hard_link(&path, backup_path(&path)).unwrap();
    std::fs::write(
        scratch.dir().join("config.yaml.busbar-new.4194304"),
        "half written",
    )
    .unwrap();
    let plan = plan(&Inputs::new(&path, &facts(), &accept)).unwrap();
    assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
    assert_eq!(read_version(&read_config(&path).unwrap()), Ok(1));
    assert_eq!(
        std::fs::read_to_string(backup_path(&path)).unwrap(),
        CONFIG_1_5_5
    );
    assert_eq!(
        scratch.names(),
        [
            "busbar-overlay.json",
            "config.yaml",
            "config.yaml.1.5.5",
            "config.yaml.busbar-lock",
            "providers.yaml"
        ],
        "the dead holder's temporary is swept under the lock"
    );
}

/// (y)(1): the rewritten config.yaml keeps the source's mode, whatever the umask.
#[test]
fn the_rewritten_config_keeps_the_source_mode() {
    for mode in [0o600, 0o640, 0o644] {
        let scratch = Scratch::new();
        let path = scratch.deployment(
            "listen: 0.0.0.0:8080\nstore:\n  module: postgres\n  url: postgres://u:pw@db/b\n",
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let plan = plan(&Inputs::new(&path, &facts(), &accept)).unwrap();
        assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
        let new_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(new_mode, mode, "config.yaml");
        let backup_mode = std::fs::metadata(backup_path(&path))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(backup_mode, mode, "config.yaml.1.5.5");
    }
}

/// (q) two gateways race on one directory: both plan the same 1.5.5 file; A's write holds the lock
/// (paused inside its re-run's strict parse) while B waits on it. A stamps; B, holding the lock
/// after it, re-reads the stamp and answers StampedByPeer (the seam then re-executes onto it).
/// config.yaml is stamped once and the backup holds the 1.5.5 bytes.
#[test]
fn two_gateways_race_and_the_second_finds_the_peer_stamp() {
    use std::sync::mpsc;
    use std::time::Duration;

    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    let facts = facts();
    let inputs = Inputs::new(&path, &facts, &accept);
    let (plan_a, plan_b) = (plan(&inputs).unwrap(), plan(&inputs).unwrap());
    let (inside, paused) = mpsc::channel::<()>();
    let (resume, go) = mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let plan_a = &plan_a;
        let a = scope.spawn(move || {
            let pause = |_: &str, _: Option<&str>| -> Result<(), String> {
                inside.send(()).expect("A reports it holds the lock");
                go.recv().expect("A is resumed");
                Ok(())
            };
            write(plan_a, &pause)
        });
        paused.recv().expect("A holds the lock, paused");
        let b = scope.spawn(|| write(&plan_b, &accept));
        std::thread::sleep(Duration::from_millis(600));
        assert!(!b.is_finished(), "B waits on the lock while A holds it");
        resume.send(()).expect("resume A");
        assert_eq!(a.join().expect("A"), Ok(Written::Stamped));
        assert_eq!(b.join().expect("B"), Ok(Written::StampedByPeer));
    });
    let stamped = std::fs::read_to_string(&path).unwrap();
    assert_eq!(stamped, patch::stamp(CONFIG_1_5_5, CONFIG_FORMAT).unwrap());
    assert_eq!(stamped.matches("config_version").count(), 1);
    assert_eq!(
        std::fs::read_to_string(backup_path(&path)).unwrap(),
        CONFIG_1_5_5
    );
    assert_eq!(
        scratch.names(),
        [
            "busbar-overlay.json",
            "config.yaml",
            "config.yaml.1.5.5",
            "config.yaml.busbar-lock",
            "providers.yaml"
        ]
    );
}

/// §3 step 2: the boot reads the planned config.yaml in place of the file, and only that file.
#[test]
fn the_plan_holds_the_planned_config_for_its_own_path_only() {
    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    let plan = plan(&Inputs::new(&path, &facts(), &accept)).unwrap();
    assert_eq!(plan.held(&path), Some(plan.planned()));
    assert_eq!(read_version(plan.held(&path).unwrap()), Ok(CONFIG_FORMAT));
    assert_eq!(plan.held(&scratch.dir().join("providers.yaml")), None);
    assert_eq!(plan.held(&backup_path(&path)), None);
}

/// (sz2) in this crate: `plan` and `write` each count one entry, and nothing else is entered.
#[test]
fn plan_and_write_are_entered_once_each() {
    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    let before = counted::entries();
    let plan = plan(&Inputs::new(&path, &facts(), &accept)).unwrap();
    assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
    let after = counted::entries();
    assert_eq!(after.plan - before.plan, 1);
    assert_eq!(after.write - before.write, 1);
    assert_eq!(after.probe, before.probe);
    assert_eq!(after.write_back, before.write_back);
    assert_eq!(after.other, before.other);
}

/// The stamped document a 1.6.0 config.yaml is, as 5W finds it.
const STAMPED: &str = "\
config_version: 1
# production gateway
listen: 0.0.0.0:8080
store:
  module: sqlite
  settings: {path: /var/lib/busbar/busbar.db}   # 1.5.5 key
";

/// A settled bag as the plugin's open returned it, filed by the patch writer: here one span.
fn settle(text: &str) -> Result<String, Refusal> {
    Ok(text.replacen(
        "{path: /var/lib/busbar/busbar.db}   # 1.5.5 key",
        "{db_path: /var/lib/busbar/busbar.db}   # 1.5.5 key",
        1,
    ))
}

/// 5W: the settled bag is written back in place, under the lock, keeping config.yaml's mode; the
/// stamp is unchanged and no backup is made.
#[test]
fn a_settled_bag_is_written_back_on_a_stamped_boot() {
    let scratch = Scratch::new();
    let path = scratch.config(STAMPED);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let seen = digest(STAMPED);
    assert_eq!(write_back(&path, &seen, &settle), Ok(WroteBack::Written));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        settle(STAMPED).unwrap()
    );
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o640);
    assert_eq!(scratch.names(), ["config.yaml", "config.yaml.busbar-lock"]);
}

/// 5W: config.yaml changed since step 1 read it (an operator edit): nothing is written.
#[test]
fn a_write_back_onto_changed_bytes_writes_nothing() {
    let scratch = Scratch::new();
    let path = scratch.config(STAMPED);
    let seen = digest(STAMPED);
    let edited = format!("{STAMPED}groups: {{}}\n");
    std::fs::write(&path, &edited).unwrap();
    assert_eq!(write_back(&path, &seen, &settle), Ok(WroteBack::Changed));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
}

/// 5W: equal bytes are not written (the file is the same inode).
#[test]
fn an_unchanged_write_back_writes_nothing() {
    use std::os::unix::fs::MetadataExt;
    let scratch = Scratch::new();
    let path = scratch.config(STAMPED);
    let inode = std::fs::metadata(&path).unwrap().ino();
    let same = |text: &str| -> Result<String, Refusal> { Ok(text.to_owned()) };
    assert_eq!(
        write_back(&path, &digest(STAMPED), &same),
        Ok(WroteBack::Unchanged)
    );
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
}

/// 5W never drops or changes the stamp: such an edit is refused and nothing is written.
#[test]
fn a_write_back_that_loses_the_stamp_is_refused() {
    let scratch = Scratch::new();
    let path = scratch.config(STAMPED);
    let unstamp =
        |text: &str| -> Result<String, Refusal> { Ok(text.replacen("config_version: 1\n", "", 1)) };
    let refused = write_back(&path, &digest(STAMPED), &unstamp).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), STAMPED);
}
