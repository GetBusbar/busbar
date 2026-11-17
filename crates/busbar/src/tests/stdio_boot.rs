// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `--stdio`'s boot judgement (WP1-GAP r3 §1.3, A-C4, B1) over the actual signed Store image.

fn listing(directory: &std::path::Path) -> Vec<(std::ffi::OsString, u64, std::time::SystemTime)> {
    let mut entries: Vec<_> = std::fs::read_dir(directory)
        .expect("the fixture directory reads")
        .map(|entry| {
            let entry = entry.expect("the fixture directory entry reads");
            let meta = entry.metadata().expect("the fixture entry has metadata");
            (
                entry.file_name(),
                meta.len(),
                meta.modified()
                    .expect("the fixture entry has a modification time"),
            )
        })
        .collect();
    entries.sort();
    entries
}

/// No admitted plane serves a line route: `--stdio` is refused with the named reason before
/// `build` or the boot plan opens any instance, so the configured Store's directory is exactly
/// as staged. The same boot without `--stdio` goes on to judge the Store.
#[tokio::test(flavor = "multi_thread")]
async fn stdio_without_a_line_route_is_refused_before_any_write() {
    const CHILD: &str = "BUSBAR_STDIO_BOOT_5B1D0C7E21A4";
    const WITNESS: &str = "actual root case stdio_without_a_line_route_is_refused completed";
    isolated!(CHILD, WITNESS);
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("stdio-without-a-line-route");
    // JSON is YAML flow syntax: the staged settings are carried exactly as the rig wrote them.
    let document = format!(
        "providers: {{}}\nmodels: {{}}\nstore: {{module: {module:?}, settings: {settings}}}\n"
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the deployment parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the deployment resolves");
    let plugins = crate::root::test_plugins::trusted_config(&directory);
    let resources = crate::root::min3_boot::fixture::resources().expect("loader resources");
    let staged = listing(&directory);

    let images = crate::root::boot::images::fixture(resources, &plugins).expect("images admit");
    let refused = crate::root::min3_boot::prepare_bootstrap(
        resources,
        images,
        &cfg,
        crate::root::connector::dest_judge(&cfg).guard().clone(),
        true,
    )
    .await
    .err()
    .expect("no plane serves a line route");
    assert_eq!(
        refused,
        "`--stdio`: no configured plane serves a line route"
    );
    assert_eq!(listing(&directory), staged, "the Store is untouched");
    println!("{WITNESS}");
}
