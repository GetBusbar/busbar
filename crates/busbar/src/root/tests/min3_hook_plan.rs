// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn config() -> RootCfg {
    let grammar =
        busbar_kernel::config::Grammar::new(Default::default(), Default::default(), Vec::new());
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: fixture-store, settings: {}}\nproviders: {}\nmodels: {}\n",
        &grammar,
    )
    .unwrap();
    busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap()
}

fn instance(kind: KindCode, name: &str) -> Configured {
    Configured {
        kind,
        identity: format!("image-{name}"),
        name: name.into(),
        config: b"{}".to_vec(),
        limits: Default::default(),
    }
}

#[test]
fn captured_plan_survives_config_consumption_and_requires_its_exact_plane_set() {
    fn send<T: Send>() {}
    send::<Plan>();
    let cfg = config();
    let instances = [
        instance(KindCode::Plane, "first"),
        instance(KindCode::Plane, "second"),
        instance(KindCode::Hook, "guard"),
    ];
    let plan = Plan::capture(&cfg, &instances).unwrap();
    drop(cfg);
    plan.check_instances(&instances).unwrap();
    let reordered = [
        instance(KindCode::Plane, "second"),
        instance(KindCode::Plane, "first"),
    ];
    plan.check_instances(&reordered).unwrap();
    assert!(plan.check_instances(&instances[..1]).is_err());
    assert!(plan
        .check_instances(&[instance(KindCode::Plane, "replacement")])
        .is_err());
}

#[test]
fn duplicate_plane_names_refuse_capture_and_late_rebinding() {
    let cfg = config();
    let duplicates = [
        instance(KindCode::Plane, "same"),
        instance(KindCode::Plane, "same"),
    ];
    assert!(Plan::capture(&cfg, &duplicates).is_err());
    let plan = Plan::capture(&cfg, &duplicates[..1]).unwrap();
    assert!(plan.check_instances(&duplicates).is_err());
}

#[test]
fn pool_attachment_requires_an_actual_plane_walk() {
    let mut cfg = config();
    cfg.pools
        .entry("missing".into())
        .or_default()
        .gates
        .push("guard".into());
    let refusal = Plan::capture(&cfg, &[instance(KindCode::Hook, "missing")])
        .err()
        .unwrap();
    assert!(refusal.contains("no configured plane walk"), "{refusal}");
    Plan::capture(&cfg, &[instance(KindCode::Plane, "missing")]).unwrap();
}
