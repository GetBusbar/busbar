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
