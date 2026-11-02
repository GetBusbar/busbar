// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn secrets_block_rejects_alias_and_canonical_for_one_module() {
    // The real registry supplies the canonical key to this production policy owner.
    // These are inert operator spelling/canonical metadata, not executable rows.
    let mut claimed_by = std::collections::BTreeMap::new();
    let canonical = "acme-secret-vault";
    let mut refusal = None;
    for spelling in ["vault", "acme-secret-vault"] {
        if let Err(error) = super::check_secret_module_claim(&claimed_by, canonical, spelling) {
            refusal = Some(error);
            break;
        }
        claimed_by.insert(canonical.to_string(), spelling.to_string());
    }
    let err = refusal.expect("two spellings of one secret module must be a loud error");
    assert!(
        err.contains("acme-secret-vault") && err.contains("vault") && err.contains("TWICE"),
        "the error names the module and both spellings: {err}"
    );
    for spelling in ["vault", "acme-secret-vault"] {
        assert!(
            super::check_secret_module_claim(&Default::default(), canonical, spelling).is_ok(),
            "a single '{spelling}' block still configures the module"
        );
    }
}
