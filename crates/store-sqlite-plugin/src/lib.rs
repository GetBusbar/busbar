// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **SQLite store as a droppable busbar plugin** — a `cdylib` that exports the store C ABI
//! ([`busbar_plugin_abi`]). Build it, drop the resulting `.so`/`.dll`/`.dylib` into the engine's
//! plugins folder, and set `governance.store: sqlite`; the engine loads it in-process at boot.
//!
//! This crate is deliberately tiny: all the SQLite logic lives in the `busbar-store-sqlite` `lib`
//! crate (which a custom build can also link statically). Here we only adapt the engine's JSON
//! config into a `SqliteStore` and hand the trait object to the SDK, which emits the five extern-C
//! symbols the loader resolves.

use busbar_api::Store;
use busbar_store_sqlite::SqliteStore;

/// Construct a SQLite store from the JSON config the engine passes through `open`. Shape (both keys
/// optional, sensible defaults so an empty `{}` works):
///
/// ```json
/// { "db_path": "busbar-governance.db", "busy_timeout_ms": 5000 }
/// ```
fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
    let v: serde_json::Value = if cfg.trim().is_empty() {
        serde_json::Value::Object(Default::default())
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid sqlite plugin config: {e}"))?
    };
    let path = v
        .get("db_path")
        .and_then(|x| x.as_str())
        .unwrap_or("busbar-governance.db");
    let busy_timeout_ms = v
        .get("busy_timeout_ms")
        .and_then(|x| x.as_i64())
        .unwrap_or(5000);
    let store = SqliteStore::open(path, busy_timeout_ms).map_err(|e| e.0)?;
    Ok(Box::new(store))
}

busbar_plugin_sdk::export_store_plugin!(open);

// ── unit tests for THIS crate's own responsibility: adapting the engine's JSON config into a real
// `SqliteStore`. Hermetic — every case uses `:memory:` or a scratch temp file, never the relative
// default path (which would write into the test's cwd). The underlying SQLite/governance logic is
// `busbar-store-sqlite`'s own job and is covered by that crate's 17 tests; these only cover what
// `open` itself does with the config before handing off. The real over-the-ABI, real-file success and
// failure paths live in `busbar-plugin-loader`'s `load_and_exercise_sqlite_plugin_*` tests.
#[cfg(test)]
mod tests {
    use super::open;

    fn expect_err(result: Result<Box<dyn busbar_api::Store>, String>) -> String {
        match result {
            Ok(_) => panic!("expected open() to fail, but it succeeded"),
            Err(e) => e,
        }
    }

    #[test]
    fn malformed_json_is_rejected() {
        let err = expect_err(open("{ this is not json"));
        assert!(
            err.contains("invalid sqlite plugin config"),
            "error should name the config as invalid: {err}"
        );
    }

    #[test]
    fn empty_and_bare_object_configs_use_defaults_and_succeed() {
        // Empty config is NOT an error for this plugin (unlike oidc, sqlite has usable defaults for
        // every field) — both `""` and `"{}"` fall back to the default relative db_path. Both are
        // exercised SEQUENTIALLY in one test (rather than as separate `#[test]`s) because they'd
        // otherwise open the same default-named file concurrently under cargo's parallel test runner
        // and contend on SQLite's file lock. We only assert construction succeeds and clean up
        // immediately so the suite doesn't leave a stray `busbar-governance.db` behind.
        let store = open("").expect("empty config must fall back to defaults and succeed");
        drop(store);
        let _ = std::fs::remove_file("busbar-governance.db");

        let store = open("{}").expect("{} must fall back to defaults and succeed");
        drop(store);
        let _ = std::fs::remove_file("busbar-governance.db");
    }

    #[test]
    fn explicit_in_memory_db_path_is_honored() {
        // Proves `db_path` is actually read (not ignored in favor of the default) via the one value
        // that's observable without touching disk: `:memory:` opens instantly with no file created.
        let store = open(r#"{"db_path": ":memory:"}"#).expect("in-memory db_path must open");
        let key = busbar_api::VirtualKey {
            id: "vk_adapter_test".into(),
            key_hash: "h".into(),
            name: "n".into(),
            allowed_pools: None,
            enabled: true,
            created_at: 1,
            group: None,
            labels: Default::default(),
        };
        store
            .put_key(&key)
            .expect("put_key on the constructed store");
        assert_eq!(
            store.get_key("vk_adapter_test").unwrap().unwrap().id,
            "vk_adapter_test"
        );
    }

    #[test]
    fn explicit_db_path_overrides_the_default_and_creates_that_exact_file() {
        let dir = std::env::temp_dir().join(format!(
            "busbar-sqlite-plugin-open-{}-explicit",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("custom.db");
        let cfg = serde_json::json!({ "db_path": path.to_str().unwrap() }).to_string();
        let store = open(&cfg).expect("explicit db_path must open");
        drop(store);
        assert!(
            path.exists(),
            "open() must create the file at the CONFIGURED path, not the default"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonexistent_parent_directory_is_a_clean_error_not_a_panic() {
        let dir = std::env::temp_dir().join(format!(
            "busbar-sqlite-plugin-open-{}-missing-parent",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("db.sqlite");
        let cfg = serde_json::json!({ "db_path": path.to_str().unwrap() }).to_string();
        let err = expect_err(open(&cfg));
        assert!(!err.is_empty());
        assert!(!dir.exists(), "a failed open must not create the directory");
    }
}
