// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's outbound style vocabulary (IF §12.18): `CORE_DIALECT_STYLES` turns a plane's typed D_DIALECT_AUTH row
//! into a binding `{style, settings}`, and `CORE_UPSTREAM_STYLES` turns an `upstreams.<name>.auth` form into one.
//! Every style word and settings key here is core vocabulary: an auth plugin that declares one of these words as
//! a D_OUTBOUND_STYLE item accepts these keys with these meanings (C-STYLE-VOCAB). Nothing here names a plugin.

/// Style `bearer`: `Authorization: Bearer <credential>`.
pub const BEARER: &str = "bearer";
/// Style `api-key`: `<settings.header>: <credential>`.
pub const API_KEY: &str = "api-key";
/// Style `sigv4`: a request signature (`settings.service`, `settings.region`).
pub const SIGV4: &str = "sigv4";
/// Style `oauth-token-exchange`: RFC 8693 (`settings.token_url`, `resource`, `subject_token_type`).
pub const TOKEN_EXCHANGE: &str = "oauth-token-exchange";
/// Style `oauth-connection`: the verified caller's own grant (the seven `connection` keys).
pub const CONNECTION: &str = "oauth-connection";

/// The class of a D_DIALECT_AUTH row, the key of [`CORE_DIALECT_STYLES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowClass {
    /// `Header` with no `key_header`.
    HeaderBearer,
    /// `Header` with a `key_header`.
    HeaderKey,
    /// `Sign`.
    Sign,
}

/// The one fixed table from a row's class to its style word.
pub const CORE_DIALECT_STYLES: [(RowClass, &str); 3] = [
    (RowClass::HeaderBearer, BEARER),
    (RowClass::HeaderKey, API_KEY),
    (RowClass::Sign, SIGV4),
];

/// The class of an `upstreams.<name>.auth` core-vocabulary form, the key of [`CORE_UPSTREAM_STYLES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamForm {
    Bearer,
    ApiKey,
    TokenExchange,
    Connection,
}

/// The one fixed table from an upstream form to its style word (round 21).
pub const CORE_UPSTREAM_STYLES: [(UpstreamForm, &str); 4] = [
    (UpstreamForm::Bearer, BEARER),
    (UpstreamForm::ApiKey, API_KEY),
    (UpstreamForm::TokenExchange, TOKEN_EXCHANGE),
    (UpstreamForm::Connection, CONNECTION),
];

fn table<K: PartialEq + Copy, const N: usize>(
    rows: &[(K, &'static str); N],
    key: K,
) -> &'static str {
    rows.iter()
        .find(|(k, _)| *k == key)
        .map_or("", |(_, word)| word)
}

/// The style word of a row class.
#[must_use]
pub fn dialect_style(class: RowClass) -> &'static str {
    table(&CORE_DIALECT_STYLES, class)
}

/// The style word of an upstream form.
#[must_use]
pub fn upstream_style(form: UpstreamForm) -> &'static str {
    table(&CORE_UPSTREAM_STYLES, form)
}

/// One D_DIALECT_AUTH row as core reads it (borrowed from the registry's owned copy; same fields).
pub enum Row<'a> {
    Header {
        key_header: Option<&'a str>,
        own_header: Option<&'a str>,
        passthrough_header: Option<&'a str>,
        /// (prefix, header ("" = bearer), trim_start).
        families: &'a [(Box<str>, Box<str>, bool)],
    },
    Sign {
        service: &'a str,
        region_after: &'a [Box<str>],
        region_default: &'a str,
    },
}

impl Row<'_> {
    /// The row's class.
    #[must_use]
    pub fn class(&self) -> RowClass {
        match self {
            Row::Header {
                key_header: None, ..
            } => RowClass::HeaderBearer,
            Row::Header { .. } => RowClass::HeaderKey,
            Row::Sign { .. } => RowClass::Sign,
        }
    }
}

/// One `families` item core writes: `prefix`, `header` (None = "" = bearer, omitted), `trim_start` (written only
/// when true).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Family {
    pub prefix: Box<str>,
    pub header: Option<Box<str>>,
    pub trim_start: bool,
}

/// The settings core writes for a binding, in core vocabulary. Key order is the document order of
/// [`Settings::entries`]. No `Debug`: some forms carry URLs (credential typecheck `printable-url`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Settings {
    /// `bearer` / `api-key` from a `Header` row: `header` (api-key only), `own`, `passthrough`, `families`,
    /// `protocol`.
    Header {
        header: Option<Box<str>>,
        own: Option<Box<str>>,
        passthrough: Option<Box<str>>,
        families: Vec<Family>,
        protocol: Box<str>,
    },
    /// `sigv4` from a `Sign` row: `service`, `region`, and core's `region_unread` text when the default was used.
    Sign {
        service: Box<str>,
        region: Box<str>,
        region_unread: Option<Box<str>>,
    },
    /// A catalog style word's binding: the forwarded keys of the resolved provider entry (§8.6 item 2).
    Forwarded {
        token_url: Option<Box<str>>,
        scope: Option<Box<str>>,
        subject: Option<Box<str>>,
    },
    /// `upstreams.<n>.auth: {bearer: ..}`: no settings.
    Empty,
    /// `upstreams.<n>.auth: {api_key: {header, ..}}`.
    ApiKey { header: Box<str> },
    /// `upstreams.<n>.auth: {token_exchange: ..}` (the subject token is the credential).
    TokenExchange {
        token_url: Box<str>,
        resource: Box<str>,
        subject_token_type: Option<Box<str>>,
    },
    /// `upstreams.<n>.auth: {connection: ..}`: the seven keys verbatim.
    Connection {
        issuer: Box<str>,
        resource: Box<str>,
        client_id: Box<str>,
        redirect_uri: Box<str>,
        authorization_endpoint: Box<str>,
        token_endpoint: Box<str>,
        scopes: Option<Vec<Box<str>>>,
    },
}

/// A JSON string literal (RFC 8259 escaping).
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn object(entries: &[(&str, String)]) -> String {
    let body: Vec<String> = entries
        .iter()
        .map(|(k, v)| format!("{}:{v}", quote(k)))
        .collect();
    format!("{{{}}}", body.join(","))
}

fn opt(out: &mut Vec<(&'static str, String)>, key: &'static str, value: &Option<Box<str>>) {
    if let Some(v) = value {
        out.push((key, quote(v)));
    }
}

fn header_object(header: Option<&str>) -> String {
    match header {
        Some(h) => object(&[("header", quote(h))]),
        None => object(&[]),
    }
}

impl Settings {
    /// Every key core writes, in document order, each with its canonical JSON value text. The explicit-binding
    /// fill adds the ones a binding's own settings do not hold (§12.18).
    #[must_use]
    pub fn entries(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        match self {
            Settings::Header {
                header,
                own,
                passthrough,
                families,
                protocol,
            } => {
                opt(&mut out, "header", header);
                out.push(("own", header_object(own.as_deref())));
                out.push(("passthrough", header_object(passthrough.as_deref())));
                let items: Vec<String> = families
                    .iter()
                    .map(|f| {
                        let mut e = vec![("prefix", quote(&f.prefix))];
                        if let Some(h) = &f.header {
                            e.push(("header", quote(h)));
                        }
                        if f.trim_start {
                            e.push(("trim_start", "true".to_owned()));
                        }
                        object(&e)
                    })
                    .collect();
                out.push(("families", format!("[{}]", items.join(","))));
                out.push(("protocol", quote(protocol)));
            }
            Settings::Sign {
                service,
                region,
                region_unread,
            } => {
                out.push(("service", quote(service)));
                out.push(("region", quote(region)));
                opt(&mut out, "region_unread", region_unread);
            }
            Settings::Forwarded {
                token_url,
                scope,
                subject,
            } => {
                opt(&mut out, "token_url", token_url);
                opt(&mut out, "scope", scope);
                opt(&mut out, "subject", subject);
            }
            Settings::Empty => {}
            Settings::ApiKey { header } => out.push(("header", quote(header))),
            Settings::TokenExchange {
                token_url,
                resource,
                subject_token_type,
            } => {
                out.push(("token_url", quote(token_url)));
                out.push(("resource", quote(resource)));
                opt(&mut out, "subject_token_type", subject_token_type);
            }
            Settings::Connection {
                issuer,
                resource,
                client_id,
                redirect_uri,
                authorization_endpoint,
                token_endpoint,
                scopes,
            } => {
                out.push(("issuer", quote(issuer)));
                out.push(("resource", quote(resource)));
                out.push(("client_id", quote(client_id)));
                out.push(("redirect_uri", quote(redirect_uri)));
                out.push(("authorization_endpoint", quote(authorization_endpoint)));
                out.push(("token_endpoint", quote(token_endpoint)));
                if let Some(scopes) = scopes {
                    let items: Vec<String> = scopes.iter().map(|s| quote(s)).collect();
                    out.push(("scopes", format!("[{}]", items.join(","))));
                }
            }
        }
        out
    }

    /// The settings object as canonical JSON text (keys in [`Settings::entries`] order).
    #[must_use]
    pub fn to_json(&self) -> String {
        object(&self.entries())
    }
}

/// Core's text when the signing region could not be derived from the provider host (auth-sigv4 logs it per
/// signature; the wording is core's).
#[must_use]
pub fn region_unread_text(host: &str, default: &str, labels: &[Box<str>]) -> String {
    format!(
        "could not derive the signing region from the provider host '{host}'; signing with the default region \
         '{default}' (use a host whose label after one of {} is the region)",
        labels.join(", ")
    )
}

/// The region of a `Sign` row for a provider host: the DNS label after the first label equal to one of
/// `region_after`, else `region_default` (with core's unread text).
#[must_use]
pub fn derive_region(
    host: &str,
    region_after: &[Box<str>],
    region_default: &str,
) -> (Box<str>, Option<Box<str>>) {
    let labels: Vec<&str> = host.split('.').collect();
    let found = labels
        .iter()
        .position(|l| region_after.iter().any(|a| a.as_ref() == *l))
        .and_then(|i| labels.get(i + 1))
        .filter(|l| !l.is_empty());
    match found {
        Some(region) => ((*region).into(), None),
        None => (
            region_default.into(),
            Some(region_unread_text(host, region_default, region_after).into()),
        ),
    }
}

/// `CORE_DIALECT_STYLES` applied to one row: the binding's style word and settings. `protocol` = the resolved
/// dialect (core's word); `base_url` = the provider's resolved `base_url` (read only by a `Sign` row).
#[must_use]
pub fn dialect_binding(
    row: &Row<'_>,
    protocol: &str,
    base_url: Option<&str>,
) -> (&'static str, Settings) {
    let style = dialect_style(row.class());
    let settings = match row {
        Row::Header {
            key_header,
            own_header,
            passthrough_header,
            families,
        } => Settings::Header {
            header: key_header.map(Box::from),
            own: own_header.map(Box::from),
            passthrough: passthrough_header.map(Box::from),
            families: families
                .iter()
                .map(|(prefix, header, trim_start)| Family {
                    prefix: prefix.clone(),
                    header: (!header.is_empty()).then(|| header.clone()),
                    trim_start: *trim_start,
                })
                .collect(),
            protocol: protocol.into(),
        },
        Row::Sign {
            service,
            region_after,
            region_default,
        } => {
            let host = base_url.and_then(crate::net::url_host).unwrap_or_default();
            let (region, region_unread) = derive_region(&host, region_after, region_default);
            Settings::Sign {
                service: (*service).into(),
                region,
                region_unread,
            }
        }
    };
    (style, settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fam(prefix: &str, header: &str, trim: bool) -> (Box<str>, Box<str>, bool) {
        (prefix.into(), header.into(), trim)
    }

    /// Guards the anthropic row's settings bytes (C-DIALECT-AUTH (d)): a renamed or reordered core key breaks
    /// every auth plugin that reads it.
    #[test]
    fn a_key_header_row_writes_api_key_with_core_keys_only() {
        let families = [
            fam("sk-ant-api", "x-api-key", true),
            fam("sk-ant-oat", "", false),
        ];
        let row = Row::Header {
            key_header: Some("x-api-key"),
            own_header: Some("x-api-key"),
            passthrough_header: None,
            families: &families,
        };
        let (style, settings) = dialect_binding(&row, "anthropic", None);
        assert_eq!(style, API_KEY);
        assert_eq!(
            settings.to_json(),
            r#"{"header":"x-api-key","own":{"header":"x-api-key"},"passthrough":{},"families":[{"prefix":"sk-ant-api","header":"x-api-key","trim_start":true},{"prefix":"sk-ant-oat"}],"protocol":"anthropic"}"#
        );
    }

    /// Guards the bearer mapping (openai, responses, cohere, jev): no `header` key is written.
    #[test]
    fn a_header_row_without_key_header_is_bearer() {
        let row = Row::Header {
            key_header: None,
            own_header: None,
            passthrough_header: None,
            families: &[],
        };
        let (style, settings) = dialect_binding(&row, "openai", None);
        assert_eq!(style, BEARER);
        assert_eq!(
            settings.to_json(),
            r#"{"own":{},"passthrough":{},"families":[],"protocol":"openai"}"#
        );
    }

    /// Guards region derivation from the host and core's unread text on the default.
    #[test]
    fn a_sign_row_derives_the_region_after_its_label_else_the_default_with_core_text() {
        let after: Vec<Box<str>> = [
            "bedrock-runtime",
            "bedrock-runtime-fips",
            "bedrock",
            "bedrock-fips",
        ]
        .into_iter()
        .map(Box::from)
        .collect();
        let row = Row::Sign {
            service: "bedrock",
            region_after: &after,
            region_default: "us-east-1",
        };
        let (style, settings) = dialect_binding(
            &row,
            "bedrock",
            Some("https://bedrock-runtime.eu-west-1.amazonaws.com/model"),
        );
        assert_eq!(style, SIGV4);
        assert_eq!(
            settings.to_json(),
            r#"{"service":"bedrock","region":"eu-west-1"}"#
        );

        let (_, settings) = dialect_binding(&row, "bedrock", Some("https://proxy.example.com"));
        let Settings::Sign {
            region,
            region_unread,
            ..
        } = settings
        else {
            panic!("a sign row writes sign settings");
        };
        assert_eq!(&*region, "us-east-1");
        assert_eq!(
            region_unread.as_deref(),
            Some(
                "could not derive the signing region from the provider host 'proxy.example.com'; signing with \
                 the default region 'us-east-1' (use a host whose label after one of bedrock-runtime, \
                 bedrock-runtime-fips, bedrock, bedrock-fips is the region)"
            )
        );
    }

    /// Guards the upstream form table (C-STYLE-VOCAB's two auth-oauth styles included).
    #[test]
    fn every_upstream_form_maps_to_its_core_style_word() {
        assert_eq!(upstream_style(UpstreamForm::Bearer), BEARER);
        assert_eq!(upstream_style(UpstreamForm::ApiKey), API_KEY);
        assert_eq!(upstream_style(UpstreamForm::TokenExchange), TOKEN_EXCHANGE);
        assert_eq!(upstream_style(UpstreamForm::Connection), CONNECTION);
    }

    /// Guards escaping of core-written text (a header name or label can never break the settings document).
    #[test]
    fn written_text_is_escaped_as_json() {
        let s = Settings::ApiKey {
            header: "a\"b\\c\n".into(),
        };
        assert_eq!(s.to_json(), r#"{"header":"a\"b\\c\n"}"#);
    }
}
