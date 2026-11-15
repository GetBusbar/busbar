// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one definition of an absent providers catalog, shared by the loader and startup custody.

use super::{catalog_from_str, CatalogLocation, CatalogSource, ABSENT_CATALOG};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-catalog-source-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
fn an_absent_default_catalog_is_the_empty_unchanged_catalog() {
    let dir = scratch("absent");
    let location = CatalogLocation::select(&dir.join("config.yaml"), None, None);
    assert_eq!(location.path, dir.join("providers.yaml"));
    assert!(!location.named);
    let source = location
        .read()
        .expect("an absent default catalog is not refused");
    assert_eq!(source, CatalogSource::AbsentDefault);
    assert_eq!(source.text(), ABSENT_CATALOG);
    assert!(
        catalog_from_str(source.text(), &crate::config::Grammar::empty())
            .expect("parses")
            .is_empty()
    );
    assert!(!location.path.exists(), "reading never creates the file");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_present_default_catalog_is_authored_even_when_empty() {
    let dir = scratch("present");
    std::fs::write(dir.join("providers.yaml"), "{}\n").expect("providers");
    let source = CatalogLocation::select(&dir.join("config.yaml"), None, None)
        .read()
        .expect("reads");
    assert_eq!(source, CatalogSource::Authored("{}\n".into()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_named_missing_catalog_is_refused_naming_the_file() {
    let dir = scratch("named");
    let config = dir.join("config.yaml");
    let file = CatalogLocation::select(&config, None, Some("absent.yaml"));
    assert_eq!(file.path, dir.join("absent.yaml"));
    assert!(file.named);
    let refusal = file.read().expect_err("a named file must exist");
    assert!(refusal.contains("absent.yaml"), "{refusal}");

    let named = dir.join("override.yaml");
    let flag = CatalogLocation::select(&config, Some(&named), Some("absent.yaml"));
    assert_eq!(flag.path, named, "the override wins over providers_file");
    assert!(flag.named);
    let refusal = flag.read().expect_err("an override must exist");
    assert!(refusal.contains("override.yaml"), "{refusal}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn an_absolute_providers_file_is_used_as_written() {
    let absolute = Path::new("/etc/busbar/catalog.yaml");
    let location = CatalogLocation::select(
        Path::new("/srv/busbar/config.yaml"),
        None,
        absolute.to_str(),
    );
    assert_eq!(location.path, absolute);
}

#[test]
fn an_unreadable_default_catalog_is_refused_not_read_as_absent() {
    let dir = scratch("unreadable");
    std::fs::create_dir(dir.join("providers.yaml")).expect("a directory where the file goes");
    let refusal = CatalogLocation::select(&dir.join("config.yaml"), None, None)
        .read()
        .expect_err("only NotFound is absence");
    assert!(refusal.contains("providers.yaml"), "{refusal}");
    let _ = std::fs::remove_dir_all(&dir);
}
