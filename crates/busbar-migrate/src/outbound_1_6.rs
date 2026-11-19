// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND SETTINGS CONVERSION, 1.5.5 to 1.6.0: one logic.
//!
//! The engine behaves one way for every install; nothing in it branches on the age of an install.
//! The upgrade brings an old settings file to the 1.6.0 standard, and where the standard asks
//! something of the deployment that a file cannot give (a name service, a proxy's allow list, a
//! consent), the upgrade says so, once, naming exactly what it found.
//!
//! [`TABLE`] is the whole conversion: every outbound behaviour of v1.5.5 that a settings file or
//! the process environment selected, what 1.6.0 does, and what the upgrade does about it. A row
//! whose upgrade is [`Does::Nothing`] is there so that "nothing" is a decision that can be read,
//! not an omission.

use busbar_contract::yaml::{Value, ValueExt};

use crate::Facts;

/// What the upgrade does for one row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Does {
    /// The setting means the same and is read as written.
    Nothing,
    /// The upgrade writes no setting and reports a line when the row applies to this install.
    Reports,
}

/// One row of the conversion.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Row {
    /// The row's name in reports and tests.
    pub(crate) id: &'static str,
    /// What v1.5.5 did.
    pub(crate) was: &'static str,
    /// What 1.6.0 does, for every install.
    pub(crate) now: &'static str,
    /// What the upgrade does.
    pub(crate) does: Does,
}

/// THE CONVERSION TABLE.
pub(crate) const TABLE: &[Row] = &[
    Row {
        id: "proxy-name-lookup",
        was: "behind HTTPS_PROXY / HTTP_PROXY / ALL_PROXY the proxy looked up the provider's name",
        now: "the engine looks the name up, checks every address, and asks the proxy to connect \
              to the checked address; `outbound.proxy_resolution: proxy` is an operator's \
              deliberate choice and is never written by the upgrade",
        does: Does::Reports,
    },
    Row {
        id: "proxy-over-tls",
        was: "a proxy address written https:// was reached over TLS",
        now: "the same: the engine runs its own TLS session to the proxy",
        does: Does::Nothing,
    },
    Row {
        id: "proxy-exemptions",
        was: "NO_PROXY exempted the hosts it listed",
        now: "the same list; a host that does not read back unchanged is never exempt",
        does: Does::Nothing,
    },
    Row {
        id: "plaintext-provider",
        was: "a provider whose base_url is http:// on a private or loopback host was sent to in \
              the clear, credential included, with no setting",
        now: "no address is exempt: plaintext to a provider needs the owning instance's \
              `insecure_transport: { accept: plaintext, reason: \"...\" }`; the upgrade does not \
              invent consent",
        does: Does::Reports,
    },
    Row {
        id: "idle-connections",
        was: "`limits.pool_max_idle_per_host` was divided across the worker threads",
        now: "the same figure, divided across the cores, at least one per core",
        does: Does::Nothing,
    },
    Row {
        id: "idle-timeout",
        was: "`limits.pool_idle_timeout_secs` closed an idle connection",
        now: "the same",
        does: Does::Nothing,
    },
    Row {
        id: "upstream-protocol",
        was: "`advanced.upstream_h2_prior_knowledge` and `advanced.upstream_http1_only` chose the \
              upstream protocol",
        now: "the same two settings, read by the HTTP transport",
        does: Does::Nothing,
    },
    Row {
        id: "request-timeout",
        was: "`limits.upstream_request_timeout_secs` bounded a whole upstream request",
        now: "the same",
        does: Does::Nothing,
    },
];

/// The proxy variables v1.5.5's client honoured, in both spellings.
const PROXY_VARIABLES: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// A name as a report prints it: control characters never reach an operator's terminal.
fn printable(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The row `id`.
fn row(id: &str) -> Option<&'static Row> {
    TABLE.iter().find(|row| row.id == id)
}

/// The proxy variables set in the upgrading process's environment, by name (never by value: a
/// proxy address can carry a password).
pub(crate) fn proxy_variables_set(facts: &Facts) -> Vec<&'static str> {
    PROXY_VARIABLES
        .into_iter()
        .filter(|name| (facts.env)(name).is_some_and(|value| !value.trim().is_empty()))
        .collect()
}

/// `proxy-name-lookup`: the line an install behind a proxy reads.
pub(crate) fn proxy_lines(facts: &Facts, resolved: &Value) -> Vec<String> {
    let set = proxy_variables_set(facts);
    if set.is_empty() || row("proxy-name-lookup").is_none() {
        return Vec::new();
    }
    // An operator who already stated the choice has decided: nothing to say.
    let stated = resolved
        .at("outbound")
        .at("proxy_resolution")
        .as_str()
        .or_else(|| resolved.at("advanced").at("proxy_resolution").as_str())
        .is_some();
    if stated {
        return Vec::new();
    }
    vec![format!(
        "outbound proxy ({vars} set): 1.5.5 sent a provider's name to the proxy; 1.6.0 looks the \
         name up on this host, checks every address, and asks the proxy to connect to the checked \
         address. This host must be able to look up provider names, and a proxy that allows by \
         host name must allow those addresses. To have the proxy look names up instead (the \
         address check is then the proxy's), set `outbound.proxy_resolution: proxy` deliberately; \
         the upgrade does not write it",
        vars = set.join(", "),
    )]
}

/// The providers whose `base_url` is plaintext, by name, in the file's order.
pub(crate) fn plaintext_providers(resolved: &Value) -> Vec<(String, String)> {
    let Some(providers) = resolved.at("providers").as_mapping() else {
        return Vec::new();
    };
    providers
        .iter()
        .filter_map(|(name, provider)| {
            let name = name.as_str()?;
            let url = provider.at("base_url").as_str()?;
            let plain = url
                .get(..7)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"));
            plain.then(|| (printable(name), host_of(url)))
        })
        .collect()
}

/// The host and port of a URL, with any userinfo, path and query left out of the report.
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    printable(host)
}

/// `plaintext-provider`: one line per provider the boot will refuse to send to in the clear.
pub(crate) fn plaintext_provider_lines(resolved: &Value) -> Vec<String> {
    if row("plaintext-provider").is_none() {
        return Vec::new();
    }
    plaintext_providers(resolved)
        .into_iter()
        .map(|(name, host)| {
            format!(
                "`providers.{name}.base_url` is plaintext (http://{host}): 1.5.5 sent to a \
                 private or loopback provider in the clear with no setting; 1.6.0 exempts no \
                 address and the upgrade writes no plaintext acceptance, so calls to this \
                 provider are refused until you use https://, or accept the plaintext \
                 deliberately on the instance that serves it: `insecure_transport: {{ accept: \
                 plaintext, reason: \"<why>\" }}` with your real reason"
            )
        })
        .collect()
}

/// The pass: every reporting row, in the table's order. Writes nothing.
pub(crate) fn run(resolved: &Value, facts: &Facts, report: &mut Vec<String>) {
    report.extend(proxy_lines(facts, resolved));
    report.extend(plaintext_provider_lines(resolved));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> Value {
        busbar_contract::yaml::from_str::<Value>(text).expect("yaml")
    }

    fn facts(env: crate::Env) -> Facts {
        let mut facts = Facts::of_process(Vec::new(), Vec::new());
        facts.env = env;
        facts
    }

    fn no_proxy(_: &str) -> Option<String> {
        None
    }

    fn behind_proxy(name: &str) -> Option<String> {
        (name == "HTTPS_PROXY").then(|| "http://user:hunter2@proxy.corp:3128".to_owned())
    }

    fn blank_proxy(name: &str) -> Option<String> {
        (name == "ALL_PROXY").then(|| "  ".to_owned())
    }

    const LOCAL_MODEL: &str = "providers:\n  ollama:\n    base_url: http://localhost:11434\n  \
                               cloud:\n    base_url: https://api.example.com\n  lan:\n    \
                               base_url: HTTP://user:pw@10.0.0.5:8080/v1?x=1\n";

    #[test]
    fn an_install_with_no_proxy_and_no_plaintext_provider_reads_nothing() {
        let mut report = Vec::new();
        run(
            &doc("providers:\n  cloud:\n    base_url: https://api.example.com\n"),
            &facts(no_proxy),
            &mut report,
        );
        assert!(report.is_empty(), "{report:?}");
    }

    #[test]
    fn behind_a_proxy_the_upgrade_says_the_engine_now_looks_names_up_and_writes_no_setting() {
        let lines = proxy_lines(&facts(behind_proxy), &doc("{}"));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("HTTPS_PROXY"));
        assert!(lines[0].contains("look up provider names"));
        assert!(lines[0].contains("outbound.proxy_resolution: proxy"));
        assert!(
            !lines[0].contains("hunter2") && !lines[0].contains("proxy.corp"),
            "the proxy's address and password are never printed"
        );
    }

    #[test]
    fn a_blank_proxy_variable_is_not_a_proxy() {
        assert!(proxy_lines(&facts(blank_proxy), &doc("{}")).is_empty());
    }

    #[test]
    fn an_operator_who_stated_the_choice_is_told_nothing() {
        for stated in [
            "outbound:\n  proxy_resolution: proxy\n",
            "outbound:\n  proxy_resolution: local\n",
            "advanced:\n  proxy_resolution: proxy\n",
        ] {
            assert!(
                proxy_lines(&facts(behind_proxy), &doc(stated)).is_empty(),
                "{stated}"
            );
        }
    }

    #[test]
    fn each_plaintext_provider_is_named_with_its_host_and_no_secret() {
        let lines = plaintext_provider_lines(&doc(LOCAL_MODEL));
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("`providers.ollama.base_url`"));
        assert!(lines[0].contains("http://localhost:11434"));
        assert!(lines[1].contains("`providers.lan.base_url`"));
        assert!(lines[1].contains("10.0.0.5:8080"));
        assert!(
            !lines[1].contains("pw") && !lines[1].contains("/v1"),
            "userinfo, path and query are left out: {}",
            lines[1]
        );
        assert!(lines
            .iter()
            .all(|line| line.contains("insecure_transport") && line.contains("writes no")));
    }

    #[test]
    fn a_control_character_in_a_provider_name_never_reaches_the_terminal() {
        let lines = plaintext_provider_lines(&doc(
            "providers:\n  \"bad\\u001bname\":\n    base_url: http://127.0.0.1:1\n",
        ));
        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains('\u{1b}'));
        assert!(lines[0].contains("bad?name"));
    }

    #[test]
    fn every_row_states_what_it_was_what_it_is_and_what_the_upgrade_does() {
        let mut ids: Vec<&str> = TABLE.iter().map(|row| row.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), TABLE.len(), "row names are distinct");
        assert!(TABLE
            .iter()
            .all(|row| !row.was.is_empty() && !row.now.is_empty()));
        let reporting: Vec<&str> = TABLE
            .iter()
            .filter(|row| row.does == Does::Reports)
            .map(|row| row.id)
            .collect();
        assert_eq!(
            reporting,
            ["proxy-name-lookup", "plaintext-provider"],
            "each reporting row has its pass in `run`"
        );
    }

    #[test]
    fn the_pass_reports_in_the_tables_order() {
        let mut report = Vec::new();
        run(&doc(LOCAL_MODEL), &facts(behind_proxy), &mut report);
        assert_eq!(report.len(), 3);
        assert!(report[0].starts_with("outbound proxy"));
        assert!(report[1].contains("ollama") && report[2].contains("lan"));
    }
}
