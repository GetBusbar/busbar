// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::appbuild::{self, RootRules};
use busbar_kernel::config::grammar::{Grammar, GrammarRefusal, PhaseOneIn, PreparedConfigRead};
use busbar_kernel::config::{self, EnvSubst, RootCfg};
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};

struct ImageOwner(&'static str);

struct Reader {
    owner: Arc<ImageOwner>,
    reads: Arc<AtomicUsize>,
}

impl RootRules for Reader {
    fn check(&self, _: &RootCfg) -> Result<(), String> { Ok(()) }

    fn prepare_read(&self, _: &PhaseOneIn<'_>) -> Result<PreparedConfigRead, GrammarRefusal> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(PreparedConfigRead::new(Grammar::empty()).with_context(self.owner.clone()))
    }

    fn grammar(&self, _: &PhaseOneIn<'_>) -> Result<Grammar, GrammarRefusal> {
        panic!("the serving read must retain admission, not reconstruct metadata")
    }
}

struct Inputs(std::path::PathBuf);
impl Drop for Inputs {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn inputs() -> Inputs {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "busbar-prepared-read-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("config.yaml"), "providers: {}\nmodels: {}\nauth:\n  admin_auth: []\n").unwrap();
    std::fs::write(path.join("providers.yaml"), "{}\n").unwrap();
    Inputs(path)
}

#[test]
fn actual_reader_keeps_each_admitted_owner_through_resolution_and_retained_config() {
    let files = inputs();
    let reads = Arc::new(AtomicUsize::new(0));
    let first = Arc::new(ImageOwner("first image"));
    let first_weak = Arc::downgrade(&first);
    let reader = Reader { owner: first, reads: reads.clone() };
    let loaded = appbuild::load_config_from_disk_judged(
        &files.0.join("config.yaml"), None, true, EnvSubst::Strict, &reader,
    ).unwrap();
    let old = config::resolve(&loaded.deploy, &loaded.defs).unwrap();
    let retained = old.grammar.clone();
    drop(loaded);
    drop(reader);
    assert_eq!(reads.load(Ordering::SeqCst), 1, "one admission per read");
    assert_eq!(old.grammar.prepared().unwrap().context::<ImageOwner>().unwrap().0, "first image");
    assert!(first_weak.upgrade().is_some());

    let next = Reader { owner: Arc::new(ImageOwner("second image")), reads: reads.clone() };
    let loaded = appbuild::load_config_from_disk_judged(
        &files.0.join("config.yaml"), None, true, EnvSubst::Strict, &next,
    ).unwrap();
    let new = config::resolve(&loaded.deploy, &loaded.defs).unwrap();
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert_eq!(new.grammar.prepared().unwrap().context::<ImageOwner>().unwrap().0, "second image");
    assert!(!Arc::ptr_eq(old.grammar.prepared().unwrap(), new.grammar.prepared().unwrap()));
    drop(old);
    assert!(first_weak.upgrade().is_some(), "retained old configuration owns its image");
    drop(retained);
    assert!(first_weak.upgrade().is_none(), "new config retains no predecessor");
}

#[test]
fn metadata_from_another_read_cannot_be_attached_to_the_typed_document() {
    let first = Grammar::new(Default::default(), Default::default(), vec!["first".into()]);
    let second = Grammar::new(Default::default(), Default::default(), vec!["second".into()]);
    let mut deploy = config::deploy_from_yaml_str("auth:\n  admin_auth: []\n", &first).unwrap();
    let wrong = Arc::new(PreparedConfigRead::new(second).with_context(Arc::new(ImageOwner("wrong"))));
    assert!(wrong.attach(&mut deploy).is_err());
    assert!(deploy.grammar.prepared().is_none());
    assert_eq!(deploy.grammar.get().unwrap(), &first);
}

#[test]
fn failed_typed_read_releases_its_candidate_image_owner() {
    let files = inputs();
    std::fs::write(files.0.join("config.yaml"), "unknown_configuration_key: true\n").unwrap();
    let image = Arc::new(ImageOwner("rejected"));
    let weak = Arc::downgrade(&image);
    let reader = Reader { owner: image, reads: Arc::new(AtomicUsize::new(0)) };
    assert!(appbuild::load_config_from_disk_judged(
        &files.0.join("config.yaml"), None, true, EnvSubst::Strict, &reader,
    ).is_err());
    drop(reader);
    assert!(weak.upgrade().is_none());
}
