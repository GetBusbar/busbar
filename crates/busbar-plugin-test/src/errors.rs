// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ERRORS (ABI-MIN3-INTERFACE §14 round 34; PLUGIN-ERROR-CODES §2.7): a plugin repository's
//! `docs/diagnostics.json` held against its binary. [`diagnostics`] checks the file on its own (row grammar,
//! ascending numbers, slugs, the `code` spelling); [`same_numbers`] holds its non-retired numbers against
//! describe's D_ERRORS and every number the suite saw on an ERROR record or a `log_error` call. A repository with
//! no D_ERRORS and no `docs/diagnostics.json` passes trivially.

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};

/// The highest number a plugin may declare (§3 D_ERRORS).
const MAX_NUMBER: u64 = 9_999;

/// `[a-z0-9]+(-[a-z0-9]+)*`.
fn kebab(slug: &str) -> bool {
    !slug.is_empty()
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.contains("--")
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Checks `docs/diagnostics.json` (a JSON array of `{code, number, plugin, slug, title, summary, action, since,
/// retired}` rows) for the plugin whose stamp name is `stamp`, and answers its non-retired numbers in order.
/// Rows are strictly ascending by `number` in 1..=9999, slugs are unique kebab case, `title`, `summary`, `action`
/// and `since` are non-empty, `plugin` is `stamp`, `code` is `BUSBAR-<stamp>-<NNNN>` and `retired` is a boolean
/// (absent = false). The first fault is the error, naming the row.
pub fn diagnostics(file: &[u8], stamp: &str) -> Result<Vec<u16>, String> {
    let value = json::parse_value(file).map_err(|e| format!("diagnostics.json: {e}"))?;
    let rows = value
        .as_array()
        .ok_or_else(|| "diagnostics.json: not a JSON array".to_owned())?;
    let mut live = Vec::new();
    let mut slugs: Vec<&str> = Vec::new();
    let mut last = 0u64;
    for (at, row) in rows.iter().enumerate() {
        let text = |key: &str| row.get(key).and_then(|v| v.as_str()).unwrap_or_default();
        let number = row
            .get("number")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("row {at}: no integer \"number\""))?;
        if number == 0 || number > MAX_NUMBER {
            return Err(format!("row {at}: number {number} is outside 1..=9999"));
        }
        if number <= last {
            return Err(format!("row {at}: number {number} after {last}"));
        }
        last = number;
        let slug = text("slug");
        if !kebab(slug) {
            return Err(format!("row {at}: slug {slug:?} is not kebab case"));
        }
        if slugs.contains(&slug) {
            return Err(format!("row {at}: slug {slug:?} twice"));
        }
        slugs.push(slug);
        for key in ["title", "summary", "action", "since"] {
            if text(key).trim().is_empty() {
                return Err(format!("row {at}: empty {key:?}"));
            }
        }
        if text("plugin") != stamp {
            return Err(format!(
                "row {at}: plugin {:?} is not {stamp:?}",
                text("plugin")
            ));
        }
        let code = format!("BUSBAR-{stamp}-{number:04}");
        if text("code") != code {
            return Err(format!("row {at}: code {:?} is not {code:?}", text("code")));
        }
        let retired = match row.get("retired") {
            None => false,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| format!("row {at}: \"retired\" is not a boolean"))?,
        };
        if !retired {
            live.push(u16::try_from(number).map_err(|_| format!("row {at}: number {number}"))?);
        }
    }
    Ok(live)
}

/// The file's non-retired numbers equal describe's D_ERRORS (both ascending), and every number seen on an ERROR
/// record or a `log`/`log_error` call during the suite is declared.
pub fn same_numbers(file: &[u16], declared: &[u16], seen: &[u32]) -> Result<(), String> {
    if file != declared {
        return Err(format!(
            "docs/diagnostics.json lists {file:?} but describe's D_ERRORS is {declared:?}"
        ));
    }
    match seen
        .iter()
        .find(|n| u16::try_from(**n).map_or(true, |n| !declared.contains(&n)))
    {
        Some(n) => Err(format!("number {n} was used but is not declared")),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"[
      {"code": "BUSBAR-busbar-auth-oidc-0001", "number": 1, "plugin": "busbar-auth-oidc", "slug": "issuer-unreachable",
       "title": "Issuer unreachable", "summary": "The issuer did not answer.", "action": "Check the issuer URL.", "since": "1.6.0"},
      {"code": "BUSBAR-busbar-auth-oidc-0007", "number": 7, "plugin": "busbar-auth-oidc", "slug": "old-claim",
       "title": "Old claim", "summary": "Retired.", "action": "None.", "since": "1.6.0", "retired": true},
      {"code": "BUSBAR-busbar-auth-oidc-0042", "number": 42, "plugin": "busbar-auth-oidc", "slug": "jwks-stale",
       "title": "JWKS stale", "summary": "Keys are old.", "action": "Wait for the refresh.", "since": "1.6.0", "retired": false}
    ]"#;

    #[test]
    fn a_good_file_answers_its_live_numbers() {
        assert_eq!(
            diagnostics(GOOD.as_bytes(), "busbar-auth-oidc"),
            Ok(vec![1, 42])
        );
        assert_eq!(diagnostics(b"[]", "busbar-auth-oidc"), Ok(Vec::new()));
    }

    #[test]
    fn every_row_fault_is_named() {
        let bad = [
            (GOOD.replace("\"number\": 7", "\"number\": 1"), "after 1"),
            (
                GOOD.replace("\"number\": 42", "\"number\": 10000"),
                "outside",
            ),
            (GOOD.replace("old-claim", "Old_claim"), "kebab"),
            (GOOD.replace("old-claim", "issuer-unreachable"), "twice"),
            (
                GOOD.replace("\"title\": \"JWKS stale\"", "\"title\": \" \""),
                "empty \"title\"",
            ),
            (
                GOOD.replace("BUSBAR-busbar-auth-oidc-0042", "BUSBAR-busbar-auth-oidc-42"),
                "code",
            ),
            (
                GOOD.replacen(
                    "\"plugin\": \"busbar-auth-oidc\"",
                    "\"plugin\": \"busbar-auth-oauth\"",
                    1,
                ),
                "plugin",
            ),
            (
                GOOD.replace("\"retired\": true", "\"retired\": \"yes\""),
                "boolean",
            ),
            ("{}".to_owned(), "not a JSON array"),
        ];
        for (file, want) in bad {
            let got = diagnostics(file.as_bytes(), "busbar-auth-oidc").expect_err(want);
            assert!(got.contains(want), "{got:?} should name {want:?}");
        }
    }

    #[test]
    fn the_file_describe_and_every_seen_number_agree() {
        assert_eq!(same_numbers(&[1, 42], &[1, 42], &[1, 42, 42]), Ok(()));
        assert_eq!(same_numbers(&[], &[], &[]), Ok(()));
        assert!(same_numbers(&[1, 42], &[1], &[]).is_err());
        assert!(same_numbers(&[1], &[1], &[7]).is_err());
        assert!(same_numbers(&[1], &[1], &[65_537]).is_err());
    }
}
