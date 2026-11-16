// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;
use busbar_ports::binder::{BindError, DestDef, TrustAnchor};

struct Binder;
impl ConfigBinder for Binder {
    fn bind(
        &self,
        _: u64,
        config: &[u8],
        _: &[&str],
        _: &[&str],
        _: &[&str],
        _: &[&str],
    ) -> Result<Vec<u8>, BindError> {
        Ok(config.to_vec())
    }
    fn bind_any(
        &self,
        id: u64,
        config: &[u8],
        secret: &[&str],
        trust: &[&str],
        dest: &[&str],
        refs: &[&str],
    ) -> Result<Vec<u8>, BindError> {
        self.bind(id, config, secret, trust, dest, refs)
    }
    fn resolve_refs<'a>(
        &'a self,
        _: u64,
        _: u32,
        bound: Vec<u8>,
        _: &'a dyn RefSource,
    ) -> BoxFut<'a, Result<SecureVec, BindError>> {
        Box::pin(async move { Ok(SecureVec::from(bound)) })
    }
    fn unbind(&self, _: u64) {}
    fn unbind_refs(&self, _: u64, bound: &[u8]) -> Result<Vec<u8>, BindError> {
        Ok(bound.to_vec())
    }
    fn secret(&self, _: u64, _: u32) -> Option<SecretRef> {
        None
    }
    fn trust(&self, _: u64, _: u32) -> Option<Arc<TrustAnchor>> {
        None
    }
    fn unix_path(&self, _: u64, _: &str) -> bool {
        false
    }
    fn dest(&self, _: u64, _: u32) -> Option<Arc<DestDef>> {
        None
    }
}

fn registry(ids: Arc<crate::process::InstanceIds>, slots: Arc<SlotTable>) -> Registry {
    let mut builder = ImagesBuilder::new(
        &busbar_plugin_abi::host_side::host_vt::HOST,
        slots,
        Ceilings::DEFAULT,
    );
    builder
        .admit_described(
            "test-secret",
            &[0; 64],
            &[],
            true,
            Described {
                kind: KindCode::Secret,
                methods: 0,
                facts: 0,
                items: Vec::new(),
                schema: None,
                metrics: Vec::new(),
                error_codes_refused: None,
            },
        )
        .expect("valid described image");
    Registry::new(builder.finish(), Arc::new(Binder), ids)
}

fn spec(name: &str) -> InstanceSpec<'_> {
    InstanceSpec {
        purpose: OpenPurpose::Canonical,
        identity: "test-secret",
        name,
        config_json: b"{}",
        limits: InstanceLimits::default(),
        public_url: None,
        caller_upstreams: &[],
    }
}

#[test]
fn reserved_identity_survives_candidates_and_dropped_reservations_burn_ids() {
    let ids = Arc::new(crate::process::InstanceIds::default());
    let slots = Arc::new(SlotTable::new());
    let first = registry(Arc::clone(&ids), Arc::clone(&slots));
    let second = registry(ids, Arc::clone(&slots));
    let one = first.reserve(&spec("one")).expect("reserve one");
    let two = second.reserve(&spec("two")).expect("reserve two");
    assert_ne!(one.id(), two.id());
    assert_ne!(one.slot(), two.slot());
    assert_eq!(one.name(), "one");
    assert_eq!(one.identity(), "test-secret");
    assert_eq!(one.kind(), KindCode::Secret);
    let burnt = two.id();
    let released = two.slot();
    drop(two);
    assert!(slots.scrub_of(released).is_none());
    let three = second.reserve(&spec("three")).expect("reserve three");
    assert!(three.id() > burnt);
    assert!(slots.scrub_of(one.slot()).is_some());
}

#[tokio::test]
async fn failed_reopen_preserves_version_and_bound_needs_lifetime() {
    let registry = registry(
        Arc::new(crate::process::InstanceIds::default()),
        Arc::new(SlotTable::new()),
    );
    let needs = Arc::new(crate::chains::DeniedNeeds);
    let weak = Arc::downgrade(&needs);
    registry.remember(
        &spec("bound"),
        KindCode::Secret,
        &needs,
        &(Arc::new(crate::chains::DeniedRefs) as Arc<dyn RefSource>),
        None,
    );
    registry
        .applied
        .lock()
        .expect("applied")
        .get_mut(&(KindCode::Secret, Box::from("bound")))
        .expect("saved")
        .version = 17;
    drop(needs);
    assert!(weak.upgrade().is_some(), "saved open owns its actual Needs");
    assert!(
        registry.reopen(KindCode::Secret, "bound").await.is_err(),
        "fixture has no loaded image"
    );
    assert_eq!(
        registry
            .applied
            .lock()
            .expect("applied")
            .get(&(KindCode::Secret, Box::from("bound")))
            .expect("saved")
            .version,
        17
    );
    drop(registry);
    assert!(
        weak.upgrade().is_none(),
        "no registry/Needs cycle survives drop"
    );
}

#[test]
fn secret_dependency_names_never_fall_back_to_an_image_identity() {
    let registry = registry(
        Arc::new(crate::process::InstanceIds::default()),
        Arc::new(SlotTable::new()),
    );
    let instances = [
        (KindCode::Secret, spec("primary")),
        (KindCode::Secret, spec("test-secret")),
    ];
    assert_eq!(
        registry.secret_index("test-secret", &instances, &Sugars::default()),
        Some(1)
    );
    let only_primary = [(KindCode::Secret, spec("primary"))];
    assert_eq!(
        registry.secret_index("test-secret", &only_primary, &Sugars::default()),
        None
    );
}

#[test]
fn a_missing_core_secret_dependency_refuses_before_the_store_walk() {
    let registry = registry(
        Arc::new(crate::process::InstanceIds::default()),
        Arc::new(SlotTable::new()),
    );
    let instances = [(KindCode::Secret, spec("primary"))];
    assert!(registry
        .boot_plan_with_core(&instances, &Sugars::default(), &["missing"])
        .is_err());
}
