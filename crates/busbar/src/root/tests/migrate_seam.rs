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
            "`openssl rand -hex 32 > /etc/busbar/at-rest.key && chmod 600 /etc/busbar/at-rest.key`"
        ),
        "{no_key}"
    );
    assert!(
        no_key.contains("`credentials: {at_rest: {key: {file: /etc/busbar/at-rest.key}}}`"),
        "{no_key}"
    );
    assert!(no_key.contains("`config.yaml.1.5.5`"), "{no_key}");
    assert!(no_key.contains("\"At-rest key\""), "{no_key}");
    let unresolved = admit_answer(
        2,
        Some(Err(
            "credentials.at_rest.key did not resolve: gone".to_owned()
        )),
        dir,
    )
    .unwrap_err();
    assert_eq!(
        unresolved,
        "CONFIG: credentials.at_rest.key did not resolve: gone"
    );
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
    let _ = run(Path::new("/nonexistent/busbar/config.yaml"), false);
    assert!(
        !busbar_plugin_loader::dispatch::migrate::install_admit(migrate_admit),
        "the seam's answer is installed already"
    );
}
