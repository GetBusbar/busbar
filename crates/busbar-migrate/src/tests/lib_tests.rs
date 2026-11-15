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
    let refused = plan(&Inputs {
        path: &path,
        facts: &facts(),
        check: &accept,
    })
    .unwrap_err();
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
    let plan = plan(&Inputs {
        path: &path,
        facts: &facts(),
        check: &check,
    })
    .expect("planned");
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
            "config.yaml",
            "config.yaml.1.5.5",
            "config.yaml.busbar-lock",
            "providers.yaml"
        ],
        "no temporary is left"
    );
    // A stamped file is never planned again.
    let again = super::plan(&Inputs {
        path: &path,
        facts: &facts(),
        check: &accept,
    })
    .unwrap_err();
    assert_eq!(again.word(), "CONFIG");
}

/// (b) a peer stamped config.yaml while this boot waited on the lock: nothing is written.
#[test]
fn a_config_stamped_by_a_peer_is_not_written_again() {
    let scratch = Scratch::new();
    let path = scratch.deployment(CONFIG_1_5_5);
    let plan = plan(&Inputs {
        path: &path,
        facts: &facts(),
        check: &accept,
    })
    .unwrap();
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
    let plan = plan(&Inputs {
        path: &path,
        facts: &facts(),
        check: &accept,
    })
    .unwrap();
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
    let refused = plan(&Inputs {
        path: &path,
        facts: &facts(),
        check: &refuse,
    })
    .unwrap_err();
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
    std::fs::write(backup_path(&path), "listen: elsewhere\n").unwrap();
    let plan = plan(&Inputs {
        path: &path,
        facts: &facts(),
        check: &accept,
    })
    .unwrap();
    let refused = write(&plan, &accept).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(
        refused.to_string().contains("config.yaml.1.5.5"),
        "{refused}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), CONFIG_1_5_5);
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
    let plan = plan(&Inputs {
        path: &path,
        facts: &facts(),
        check: &accept,
    })
    .unwrap();
    assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
    assert_eq!(read_version(&read_config(&path).unwrap()), Ok(1));
    assert_eq!(
        std::fs::read_to_string(backup_path(&path)).unwrap(),
        CONFIG_1_5_5
    );
    assert_eq!(
        scratch.names(),
        [
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
        let plan = plan(&Inputs {
            path: &path,
            facts: &facts(),
            check: &accept,
        })
        .unwrap();
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
