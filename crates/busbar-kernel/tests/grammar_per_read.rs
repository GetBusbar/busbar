// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-SHORTHAND-BOOT MR-B (§3.1): a configuration read parses under the grammar its own
//! `plugins:` block admits, computed for that read. What the last generation left on the live
//! secret axis never decides what a read means. The axis is process-global, so this binary owns
//! it and publishes a stale one: it still declares a word no module the read admits declares.

use std::sync::Arc;

use busbar_contract::abi::mechanism::door::REWRITE_SUGAR;
use busbar_contract::plugin_settings::Settings;
use busbar_contract::secret::{SecretAxis, SecretBytes, SecretCalls};
use busbar_contract::secret_ref::context::UNDECLARED_MARKER;
use busbar_contract::secret_ref::{SecretRef, Sugars};
use busbar_kernel::config::EnvSubst;

const MODULE: &str = "fixture-secret";
const WORD: &str = "fixture-word";

/// The live axis as a previous generation left it: it still answers a module and declares its word.
struct StaleAxis;
impl SecretAxis for StaleAxis {
    fn sugars(&self) -> Sugars {
        let mut sugars = Sugars::default();
        sugars
            .declare(MODULE, &[(REWRITE_SUGAR, WORD.into(), "slot".into())])
            .expect("one module declares one word");
        sugars
    }
    fn answers(&self, module: &str) -> bool {
        module == MODULE
    }
    fn linked(&self, _module: &str) -> bool {
        false
    }
    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        Err(format!("no linked module {module}"))
    }
    fn open(
        &self,
        module: &str,
        _settings: Option<&Settings>,
        _resolve: &dyn Fn(&SecretRef) -> Result<SecretBytes, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        Err(format!("this test opens nothing ({module})"))
    }
}

static STALE_AXIS: StaleAxis = StaleAxis;

fn publish() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_kernel::preflight::publish_root_rows(busbar_kernel::preflight::RootInstall {
            secret_axis: Some(&STALE_AXIS),
            ..Default::default()
        });
    });
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-grammar-per-read-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// S4 / F6: a document whose own `plugins:` block admits no module declaring `fixture-word` is
/// refused for using it, even though the live axis still declares it.
#[test]
fn a_word_only_the_live_axis_declares_is_refused_by_a_read_that_does_not_admit_it() {
    publish();
    let dir = scratch("stale-axis");
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!("providers: {{}}\nmodels: {{}}\nauth:\n  signing_key: {{{WORD}: signing}}\n"),
    )
    .expect("config");
    let refused = busbar_kernel::load_config_from_disk(&config, None, false, EnvSubst::Lenient)
        .map(|_| ())
        .expect_err("the read's own block admits no module declaring the word");
    assert!(
        refused.contains(UNDECLARED_MARKER) && refused.contains(WORD),
        "the read refuses the word as undeclared, not as the live axis has it: {refused}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
