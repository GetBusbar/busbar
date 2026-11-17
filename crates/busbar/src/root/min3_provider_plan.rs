// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_preserve_operator_values_and_credential_reference() {
        let mut config = serde_json::json!({"style":"bearer","credential":{"file":"key"},"settings":{"audience":"authored"}});
        fill_config(&mut config, &[("audience", "generated".into()), ("scope", "scope-a".into())]).unwrap();
        assert_eq!(config["settings"]["audience"], "authored");
        assert_eq!(config["settings"]["scope"], "scope-a");
        assert_eq!(config["credential"], serde_json::json!({"file":"key"}));
    }

    #[test]
    fn fills_refuse_non_object_settings_without_echoing_values() {
        let mut config = serde_json::json!({"settings":"private-value"});
        let error = fill_config(&mut config, &[("scope", "private-fill".into())]).unwrap_err();
        assert!(!error.contains("private"));
    }

    #[test]
    fn provider_provenance_is_not_reinterpreted_as_an_instance_name() {
        let mut selections = BTreeMap::new();
        selection(&mut selections, "p", &ProviderAuthSelection::Style("shared".into())).unwrap();
        assert!(selection(&mut selections, "p", &ProviderAuthSelection::Instance("shared".into())).is_err());
    }
}
