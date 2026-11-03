// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn the_registry_build_keeps_the_preflights_boot_lines_in_order() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let dir = crate::tests::tmp_plugin_dir("boot-lines");
    let skip = crate::tests::skipped_in(
        "lines.tar.gz",
        "acme-lines",
        "lines",
        crate::tests::UNSIGNED_SKIPPED,
    );
    let lines = |enabled: bool,
                 rows: &[busbar_contract::plugin_rows::Row],
                 skipped: &[busbar_contract::plugin_rows::Skipped]| {
        let path = dir.join("captured.log");
        let file = std::fs::File::create(&path).unwrap();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_level(false)
                .with_target(false)
                .with_ansi(false)
                .with_writer(move || file.try_clone().unwrap()),
        );
        tracing::subscriber::with_default(subscriber, || {
            if enabled {
                super::log_scanned_rows(rows, skipped, &[], &dir.to_string_lossy());
            } else {
                super::log_build(super::BuildNote::Off, &dir.to_string_lossy());
            }
        });
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|m| m.starts_with("plugin"))
            .map(|m| m.trim_end().to_owned())
            .collect::<Vec<_>>()
    };
    let d = dir.to_string_lossy().into_owned();
    let off = lines(false, &[], &[]);
    assert_eq!(
        off,
        ["plugins: disabled (plugins.enabled is false; tarballs in the directory are inert)"]
    );
    let skipped = lines(true, &[], &[skip]);
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert_eq!(
        skipped[0],
        format!("plugins: enabled dir={d} loadable=0 skipped=1")
    );
    assert!(
        skipped[1].starts_with("plugin present but NOT loaded (trust policy) ")
            && skipped[1].contains("plugin=acme-lines")
            && skipped[1].contains("lines.tar.gz"),
        "{skipped:?}"
    );

    let allowed = lines(
        true,
        &[crate::tests::dropped(
            "acme-lines",
            "lines",
            busbar_contract::abi::mechanism::kind::STORE,
        )],
        &[],
    );
    assert_eq!(allowed.len(), 2, "{allowed:?}");
    assert_eq!(
        allowed[0],
        format!("plugins: enabled dir={d} loadable=1 skipped=0")
    );
    assert!(
        allowed[1].starts_with(
            "plugin validated as UNVERIFIED (permitted by an explicit plugins.trust opt-in) "
        ) && allowed[1].contains("plugin=acme-lines"),
        "{allowed:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
