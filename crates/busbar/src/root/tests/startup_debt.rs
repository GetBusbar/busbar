// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A boot refused for migration debt says why: the plugin preflight when a named plugin is not
//! present, otherwise the decisions themselves (UPG-A12).
use std::path::Path;
use std::sync::Arc;

use busbar_kernel::appbuild::ConfigDocument;
use busbar_kernel::config_validate::Refusal;

use super::{explain_debt, Documents};
use crate::root::cli::{validate_judged, ValidateRefusal};

const BASELINE: &str = include_str!("fixtures/oracle_config_baseline.yaml");
const PLUGINS_TEXT: &str = "identity-providers.oracle-oidc (module 'oidc') require(s) the plugin \
     subsystem, but plugins.enabled is false (the default). Set plugins.enabled: true and install \
     the plugin, or name a built-in.";
const SIGNALS_TODO: &str = "hook 'h': the `signals:` declaration did not carry over \
     automatically; re-add it under the named `hooks:` entry if the hook still needs it";

#[test]
fn explain_debt_by_class() {
    let config = Path::new("/etc/busbar/config.yaml");

    // (a) The plugin preflight names the field and the remedy, exactly.
    let plugins = ValidateRefusal::Check(Refusal::Plugins(PLUGINS_TEXT.to_owned()));
    let detail = explain_debt(
        &["identity-providers.oracle-oidc: current settings were refused by the registered owner"],
        Some(&plugins),
        config,
    );
    assert_eq!(detail, PLUGINS_TEXT);

    // (b) No refusing diagnosis: the decisions are listed.
    let detail = explain_debt(&[SIGNALS_TODO], None, config);
    assert!(
        detail.starts_with(
            "configuration migration requires 1 unresolved configuration decision(s):"
        ),
        "{detail}"
    );
    assert!(
        detail.contains("\n  * hook 'h': the `signals:` declaration"),
        "{detail}"
    );
    assert!(detail.ends_with(", then boot again."), "{detail}");

    // (c) A config-class verdict on the unmigrated bytes does not replace a real decision.
    let config_class = ValidateRefusal::Check(Refusal::Config(vec![
        "auth.chain references 'tokens', which is not defined in identity-providers: Define it, \
         or remove it from the chain"
            .to_owned(),
    ]));
    let detail = explain_debt(
        &["auth.chain: the static-token module is GONE in 1.5.0; callers' bearer tokens stop working"],
        Some(&config_class),
        config,
    );
    assert!(detail.contains("static-token module is GONE"), "{detail}");
    assert!(!detail.contains("Define it"), "{detail}");

    // (d) Grammar the boot normalization rewrites is not evidence about the migrated document.
    let unknown = "config.yaml: invalid YAML: hooks.h: unknown field `socket`, expected one of \
                   `module`, `settings`";
    for refusal in [
        ValidateRefusal::Load(unknown.to_owned()),
        ValidateRefusal::Resolve(vec![unknown.to_owned()]),
        ValidateRefusal::Check(Refusal::Root(unknown.to_owned())),
        ValidateRefusal::Check(Refusal::Unresolved(unknown.to_owned())),
    ] {
        let detail = explain_debt(&[SIGNALS_TODO], Some(&refusal), config);
        assert!(detail.contains(SIGNALS_TODO), "{refusal:?}: {detail}");
        assert!(!detail.contains("unknown field"), "{refusal:?}: {detail}");
    }
}

#[test]
fn legacy_hook_debt_is_explained_not_replaced_by_validate() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!(
        "busbar-startup-debt-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("config.yaml");
    let raw = format!(
        "{BASELINE}store: {{module: memory}}\nhooks:\n  h: {{socket: /tmp/x.sock, signals: [a]}}\n"
    );
    std::fs::write(&path, &raw).expect("config.yaml");
    std::fs::write(dir.join("providers.yaml"), "").expect("providers.yaml");

    let documents = Arc::new(Documents::default());
    let refused = documents.normalize(ConfigDocument::Deployment, &path, &raw);
    assert!(
        refused.is_err(),
        "a legacy hook config carries migration debt"
    );
    let todos = documents
        .take_debt()
        .expect("the refused normalization keeps its decisions");
    assert!(
        todos
            .iter()
            .any(|t| t.contains("hook 'h': the `signals:` declaration")),
        "the signals decision is kept"
    );
    assert!(
        documents.take_debt().is_none(),
        "the decisions are taken once"
    );

    let diagnosis = validate_judged(&path, None, false).err();
    assert!(
        matches!(diagnosis, Some(ValidateRefusal::Load(_))),
        "--validate judges the unmigrated bytes: {diagnosis:?}"
    );
    let detail = explain_debt(&todos, diagnosis.as_ref(), &path);
    assert!(
        detail.contains("hook 'h': the `signals:` declaration"),
        "{detail}"
    );
    assert!(!detail.contains("unknown field"), "{detail}");

    let _ = std::fs::remove_dir_all(&dir);
}
