// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JUDGE for the OAuth 2.1 issuer's move out of `busbar-core` and into the CONTROL surface
//! `busbar-control-oauth2`: every route's answer, recorded on the base binary before the move and
//! required to be the SAME BYTES after it.
//!
//! ## Why this file exists at all
//!
//! There are no 1.5.5 golden cells for `oauth_as:` — the plane is 1.6.0 surface, so there is nothing
//! upstream to diff against. A move that is claimed to be behaviour-preserving and has no witness is
//! a move nobody can review: the interesting failures are a header that stopped being emitted, a
//! `Set-Cookie` whose `Path` narrowed or widened, a discovery document that lost a member, and an
//! error body whose `error` code changed — none of which a compile catches and none of which a test
//! that only asserts `200` catches either. So the witness is built here, first, against the binary
//! as it stands, and the move is judged against it.
//!
//! ## What "identical" means, precisely
//!
//! For every cell: the STATUS, then every response HEADER (name-sorted, `date` dropped), then the
//! BODY, verbatim. Three classes of value are normalised, and each normalisation is a value this
//! deployment MINTS FRESH per request rather than a property of the surface under test:
//!
//! | normalised | to | why it cannot be pinned |
//! |---|---|---|
//! | a 64-hex run | `<HEX64>` | the consent session id is 256 bits from the platform RNG |
//! | `client_id` / `client_secret` / `registration_access_token` / `access_token` / `refresh_token` / `code` JSON string members | `<OPAQUE>` | minted per registration / per grant |
//! | `client_id_issued_at` / `client_secret_expires_at` / `iat` / `exp` / `nbf` numeric members | `<TIME>` | the wall clock |
//!
//! Everything else — the member ORDER of the discovery document, the exact `error` codes, the
//! `WWW-Authenticate` challenge, `Cache-Control`, both `Set-Cookie` lines and their `Path`,
//! `HttpOnly`, `SameSite` and `Max-Age` attributes, the two HTML refusal pages and the consent page
//! itself — is compared byte for byte.
//!
//! ## Recording
//!
//! `BUSBAR_OAUTH2_GOLDEN_RECORD=1 cargo test -p busbar --test oauth2_control_byte_identity`
//! rewrites `tests/oauth2_golden/routes.txt`. Without it the test COMPARES, and a difference is the
//! finding. The recording was taken on the base commit named in `docs/design/control-oauth2.md`.
//!
//! ## The signing key is FIXED, and it is a throwaway
//!
//! `tests/oauth2_golden/signing-key.b64` is a P-256 PKCS#8 key generated for this file and used
//! nowhere else, so the JWKS document — which is a pure function of the key — is a stable cell. It
//! is a fixture, not a credential: nothing this repository ships ever loads it.
//!
//! ## The ports
//!
//! 46201 (data) and 46202 (admin), fixed rather than asked of the OS, because the ISSUER is part of
//! every answer under test: it is the `iss` of the discovery document, the base of every advertised
//! endpoint, and the origin of the `jwks_uri`. A port the OS chose would make every one of those
//! cells a different string on every run, which would defeat the file.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The data listener, and therefore the ISSUER. See the module note on why it is not a free port.
const DATA_PORT: u16 = 46201;
/// The admin listener. Unused by the cells (the consent route is on the DATA listener) but a
/// deployment needs one, and pinning it keeps the fixture reproducible.
const ADMIN_PORT: u16 = 46202;
/// The operator admin token the consent cells present. A fixture value; the consent screen's bar is
/// what is under test, not the token.
const ADMIN_TOKEN: &str = "oauth2-judge-admin-token";

/// The recorded surface. One cell per request, in declaration order.
const GOLDEN: &str = "tests/oauth2_golden/routes.txt";

/// THE FIXED SIGNING KEY (see the module note). `include_str!` rather than a literal so the bytes
/// live in a file that reads as a fixture rather than as a secret pasted into source.
const SIGNING_KEY_B64: &str = include_str!("oauth2_golden/signing-key.b64");

/// One request to make, and the name it is recorded under.
struct Cell {
    name: &'static str,
    method: &'static str,
    /// Path + query, exactly as it goes on the wire.
    target: &'static str,
    /// `(content-type, body)`, or `None` for a request with no body.
    body: Option<(&'static str, &'static str)>,
    /// Present ⇒ the request carries `Authorization: Bearer <admin token>`.
    admin: bool,
    /// Present ⇒ the request carries this `Cookie` header verbatim.
    cookie: Option<&'static str>,
}

/// EVERY ROUTE THE ISSUER MOUNTS, and for each one the answers that are worth pinning: the success,
/// the refusals, and the wrong-method. Ordered by route so a diff reads as "this route changed".
const CELLS: &[Cell] = &[
    // ── discovery ────────────────────────────────────────────────────────────────────────────
    Cell {
        name: "metadata",
        method: "GET",
        target: "/.well-known/oauth-authorization-server",
        body: None,
        admin: false,
        cookie: None,
    },
    Cell {
        name: "metadata.wrong-method",
        method: "POST",
        target: "/.well-known/oauth-authorization-server",
        body: Some(("application/json", "{}")),
        admin: false,
        cookie: None,
    },
    // ── jwks ─────────────────────────────────────────────────────────────────────────────────
    Cell {
        name: "jwks",
        method: "GET",
        target: "/jwks",
        body: None,
        admin: false,
        cookie: None,
    },
    Cell {
        name: "jwks.wrong-method",
        method: "POST",
        target: "/jwks",
        body: Some(("application/json", "{}")),
        admin: false,
        cookie: None,
    },
    // ── authorize ────────────────────────────────────────────────────────────────────────────
    Cell {
        name: "authorize.no-params",
        method: "GET",
        target: "/authorize",
        body: None,
        admin: false,
        cookie: None,
    },
    Cell {
        name: "authorize.unknown-client",
        method: "GET",
        // A non-URL `client_id` on purpose: a `client_id` that parses as an HTTPS URL is a Client ID
        // Metadata Document, and resolving one is a NETWORK FETCH. A cell whose answer depends on
        // DNS is not a cell.
        target: "/authorize?response_type=code&client_id=no-such-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=mcp%3Aread&state=judge",
        body: None,
        admin: false,
        cookie: None,
    },
    Cell {
        name: "authorize.no-response-type",
        method: "GET",
        target: "/authorize?client_id=no-such-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcb",
        body: None,
        admin: false,
        cookie: None,
    },
    Cell {
        name: "authorize.wrong-method",
        method: "POST",
        target: "/authorize",
        body: Some(("application/x-www-form-urlencoded", "")),
        admin: false,
        cookie: None,
    },
    // ── token ────────────────────────────────────────────────────────────────────────────────
    Cell {
        name: "token.empty-body",
        method: "POST",
        target: "/token",
        body: Some(("application/x-www-form-urlencoded", "")),
        admin: false,
        cookie: None,
    },
    Cell {
        name: "token.unknown-code",
        method: "POST",
        target: "/token",
        body: Some((
            "application/x-www-form-urlencoded",
            "grant_type=authorization_code&code=no-such-code&client_id=no-such-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_verifier=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )),
        admin: false,
        cookie: None,
    },
    Cell {
        name: "token.unsupported-grant",
        method: "POST",
        target: "/token",
        body: Some((
            "application/x-www-form-urlencoded",
            "grant_type=password&username=a&password=b",
        )),
        admin: false,
        cookie: None,
    },
    Cell {
        name: "token.wrong-method",
        method: "GET",
        target: "/token",
        body: None,
        admin: false,
        cookie: None,
    },
    // ── register (RFC 7591, mounted UNCONDITIONALLY) ──────────────────────────────────────────
    Cell {
        name: "register.ok",
        method: "POST",
        target: "/register",
        body: Some((
            "application/json",
            r#"{"redirect_uris":["https://client.example/cb"],"client_name":"judge client","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}"#,
        )),
        admin: false,
        cookie: None,
    },
    Cell {
        name: "register.scope-above-the-ceiling",
        method: "POST",
        target: "/register",
        body: Some((
            "application/json",
            r#"{"redirect_uris":["https://client.example/cb"],"scope":"admin:everything"}"#,
        )),
        admin: false,
        cookie: None,
    },
    Cell {
        name: "register.no-redirect-uri",
        method: "POST",
        target: "/register",
        body: Some(("application/json", r#"{"client_name":"no redirect"}"#)),
        admin: false,
        cookie: None,
    },
    Cell {
        name: "register.not-json",
        method: "POST",
        target: "/register",
        body: Some(("application/json", "not json at all")),
        admin: false,
        cookie: None,
    },
    Cell {
        name: "register.wrong-method",
        method: "GET",
        target: "/register",
        body: None,
        admin: false,
        cookie: None,
    },
    // ── consent: the ONE route this deployment authenticates itself, through the admin chain ──
    Cell {
        name: "consent.get.no-credential",
        method: "GET",
        target: "/consent?return=%2Fauthorize%3Fclient_id%3Dc%26scope%3Dmcp%3Aread",
        body: None,
        admin: false,
        cookie: None,
    },
    Cell {
        name: "consent.get.admin.no-return",
        method: "GET",
        target: "/consent",
        body: None,
        admin: true,
        cookie: None,
    },
    Cell {
        name: "consent.get.admin.offsite-return",
        method: "GET",
        target: "/consent?return=https%3A%2F%2Fevil.example%2F",
        body: None,
        admin: true,
        cookie: None,
    },
    Cell {
        name: "consent.get.admin.scheme-relative-return",
        method: "GET",
        target: "/consent?return=%2F%2Fevil.example%2F",
        body: None,
        admin: true,
        cookie: None,
    },
    Cell {
        name: "consent.get.admin.ok",
        method: "GET",
        target: "/consent?return=%2Fauthorize%3Fclient_id%3Dc%26scope%3Dmcp%3Aread%26redirect_uri%3Dhttps%253A%252F%252Fclient.example%252Fcb",
        body: None,
        admin: true,
        cookie: None,
    },
    Cell {
        name: "consent.get.admin.escaping",
        // The consent page interpolates the `client_id`, the scope and the redirect HOST. This cell
        // hands all three something that changes the meaning of surrounding markup, so the golden
        // carries the ESCAPED rendering and a move that dropped `escape()` is a diff.
        method: "GET",
        target: "/consent?return=%2Fauthorize%3Fclient_id%3D%253Cscript%253E%26scope%3D%2522x%2522%26redirect_uri%3Dhttps%253A%252F%252Fclient.example%2540evil.example%252Fcb",
        body: None,
        admin: true,
        cookie: None,
    },
    Cell {
        name: "consent.post.no-credential",
        method: "POST",
        target: "/consent",
        body: Some(("application/x-www-form-urlencoded", "return=%2Fauthorize")),
        admin: false,
        cookie: None,
    },
    Cell {
        name: "consent.post.admin.no-session-cookie",
        method: "POST",
        target: "/consent",
        body: Some((
            "application/x-www-form-urlencoded",
            "return=%2Fauthorize%3Fclient_id%3Dc%26scope%3Dmcp%3Aread",
        )),
        admin: true,
        cookie: None,
    },
    Cell {
        name: "consent.post.admin.offsite-return",
        method: "POST",
        target: "/consent",
        body: Some((
            "application/x-www-form-urlencoded",
            "return=https%3A%2F%2Fevil.example%2F",
        )),
        admin: true,
        cookie: Some("busbar_as_session=0000000000000000000000000000000000000000000000000000000000000000"),
    },
    Cell {
        name: "consent.post.admin.with-session",
        method: "POST",
        target: "/consent",
        body: Some((
            "application/x-www-form-urlencoded",
            "return=%2Fauthorize%3Fclient_id%3Dc%26scope%3Dmcp%3Aread",
        )),
        admin: true,
        cookie: Some("busbar_as_session=0000000000000000000000000000000000000000000000000000000000000000"),
    },
    Cell {
        name: "consent.wrong-method",
        method: "DELETE",
        target: "/consent",
        body: None,
        admin: true,
        cookie: None,
    },
    // ── the negative control: a path the issuer does NOT mount ────────────────────────────────
    // Present so a recording that captured a router which serves EVERYTHING cannot pass. This cell
    // is the data plane's own answer, and it must stay the data plane's answer after the move.
    Cell {
        name: "not-an-issuer-path",
        method: "GET",
        target: "/introspect",
        body: None,
        admin: false,
        cookie: None,
    },
];

#[test]
fn every_oauth2_route_answers_the_same_bytes_after_the_move() {
    let dir = fixture_dir();
    let cfg = write_config(&dir);
    let mut child = spawn(&cfg);
    let addr = format!("127.0.0.1:{DATA_PORT}");

    if !wait_for(Duration::from_secs(120), || {
        std::net::TcpStream::connect(&addr).is_ok()
    }) {
        let seen = drain(&mut child);
        let _ = child.kill();
        let _ = child.wait();
        panic!("busbar never listened on {addr}. Output:\n{seen}");
    }

    let mut recorded = String::new();
    for cell in CELLS {
        recorded.push_str(&record(&addr, cell));
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    let golden_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    if std::env::var_os("BUSBAR_OAUTH2_GOLDEN_RECORD").is_some() {
        std::fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        std::fs::write(&golden_path, &recorded).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&golden_path).unwrap_or_else(|e| {
        panic!(
            "the recorded surface is missing ({}: {e}). Record it against the BASE binary with \
             `BUSBAR_OAUTH2_GOLDEN_RECORD=1 cargo test -p busbar --test \
             oauth2_control_byte_identity` — never against the moved one, or the judge is judging \
             its own defendant.",
            golden_path.display()
        )
    });

    if expected != recorded {
        panic!("{}", first_difference(&expected, &recorded));
    }
}

/// The recorded form of ONE cell: a header line, the status, the headers, then the body.
fn record(addr: &str, cell: &Cell) -> String {
    let (status, headers, body) = http(addr, cell);
    let mut out = format!("=== {} {} {}\n", cell.name, cell.method, cell.target);
    out.push_str(&format!("status: {status}\n"));
    for (name, value) in headers {
        out.push_str(&format!("header: {name}: {}\n", normalise(&value)));
    }
    out.push_str("body:\n");
    out.push_str(&normalise(&body));
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out
}

/// The three classes of freshly-minted value, replaced by their placeholder. See the module note.
fn normalise(s: &str) -> String {
    let s = replace_hex_runs(s);
    let s = replace_json_strings(
        &s,
        &[
            "client_id",
            "client_secret",
            "registration_access_token",
            "access_token",
            "refresh_token",
            "code",
        ],
    );
    replace_json_numbers(
        &s,
        &[
            "client_id_issued_at",
            "client_secret_expires_at",
            "iat",
            "exp",
            "nbf",
        ],
    )
}

/// Every maximal run of 32 or more hex digits becomes `<HEX64>`. Hand-written rather than a regex
/// dependency: the shape is one character class and a length bound.
fn replace_hex_runs(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let run = i - start;
        if run >= 32 {
            out.push_str("<HEX64>");
        } else if run > 0 {
            out.push_str(&s[start..i]);
        } else {
            // Not a hex digit: copy the whole character, so a multi-byte one is not split.
            let ch = s[i..].chars().next().expect("a char at a char boundary");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// `"name":"value"` ⇒ `"name":"<OPAQUE>"`, for each name in `names`. Tolerates whitespace after the
/// colon; does not attempt to be a JSON parser, because what is wanted is a TEXTUAL substitution
/// that leaves every other byte of the document — including member order — exactly as it arrived.
fn replace_json_strings(s: &str, names: &[&str]) -> String {
    let mut out = s.to_string();
    for name in names {
        out = replace_member(&out, name, |rest| {
            let rest = rest.trim_start();
            if !rest.starts_with('"') {
                return None;
            }
            let mut end = 1;
            let b = rest.as_bytes();
            while end < b.len() && b[end] != b'"' {
                end += if b[end] == b'\\' { 2 } else { 1 };
            }
            (end < b.len()).then(|| (end + 1, "\"<OPAQUE>\""))
        });
    }
    out
}

/// `"name":1234` ⇒ `"name":<TIME>`.
fn replace_json_numbers(s: &str, names: &[&str]) -> String {
    let mut out = s.to_string();
    for name in names {
        out = replace_member(&out, name, |rest| {
            let lead = rest.len() - rest.trim_start().len();
            let digits = rest[lead..].bytes().take_while(u8::is_ascii_digit).count();
            (digits > 0).then_some((lead + digits, "<TIME>"))
        });
    }
    out
}

/// Find every `"name":` and hand the text AFTER the colon to `take`, which answers how many bytes
/// the value occupies and what to write instead.
fn replace_member(
    s: &str,
    name: &str,
    take: impl Fn(&str) -> Option<(usize, &'static str)>,
) -> String {
    let needle = format!("\"{name}\":");
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find(&needle) {
        let after = at + needle.len();
        match take(&rest[after..]) {
            Some((len, replacement)) => {
                out.push_str(&rest[..after]);
                out.push_str(replacement);
                rest = &rest[after + len..];
            }
            None => {
                out.push_str(&rest[..after]);
                rest = &rest[after..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// One request. Returns `(status, headers sorted by name with `date` dropped, body text)`.
fn http(addr: &str, cell: &Cell) -> (u16, Vec<(String, String)>, String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            // NO REDIRECT FOLLOWING. The consent submission answers `302` with a `Location`, and
            // that pair IS the cell; a client that followed it would record the page at the other
            // end instead.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");
        let url = format!("http://{addr}{}", cell.target);
        let mut req = match cell.method {
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "DELETE" => client.delete(url),
            _ => client.get(url),
        };
        if cell.admin {
            req = req.bearer_auth(ADMIN_TOKEN);
        }
        if let Some(cookie) = cell.cookie {
            req = req.header("cookie", cookie);
        }
        if let Some((content_type, body)) = cell.body {
            req = req.header("content-type", content_type).body(body);
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        let mut headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            // `date` is the wall clock on every response and is the one header no move can hold
            // still. Everything else — including `content-length` — is part of the claim.
            .filter(|(n, _)| n.as_str() != "date")
            .map(|(n, v)| {
                (
                    n.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        // Sorted by (name, value) so two `Set-Cookie` lines have a stable order without either of
        // them being dropped — which is the whole point of there being two of them.
        headers.sort();
        (status, headers, resp.text().await.unwrap_or_default())
    })
}

/// The smallest config that makes this deployment an authorization server, plus the `mcp:` block
/// that gives it a protected resource to mint for (the RFC 8707 `allowed_resources` list and the
/// `aud` of every access token are derived from it, so a fixture without one records a DIFFERENT
/// discovery document).
fn write_config(dir: &Path) -> PathBuf {
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        format!(
            r#"listen: "127.0.0.1:{DATA_PORT}"
admin_listen: "127.0.0.1:{ADMIN_PORT}"
providers: {{}}
models: {{}}
pools: {{}}
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: {{ env: BUSBAR_SIGNING_KEY }}
mcp:
  canonical_uri: "http://127.0.0.1:{DATA_PORT}/mcp"
  authorization_servers:
    - "http://127.0.0.1:{DATA_PORT}"
oauth_as:
  issuer: "http://127.0.0.1:{DATA_PORT}"
  signing_key: {{ env: BUSBAR_OAUTH_SIGNING_KEY }}
  key_id: "judge-key-1"
  default_grant: ["mcp:read"]
  access_token_ttl_secs: 600
"#
        ),
    )
    .unwrap();
    path
}

fn spawn(cfg: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", cfg)
        .env(
            "BUSBAR_PROVIDERS",
            cfg.parent().unwrap().join("providers.yaml"),
        )
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env(
            "BUSBAR_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .env("BUSBAR_OAUTH_SIGNING_KEY", SIGNING_KEY_B64.trim())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn busbar")
}

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("busbar-oauth2-judge-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn drain(child: &mut Child) -> String {
    let mut seen = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut seen);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut seen);
    }
    seen
}

fn wait_for(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

/// The FIRST differing line, with its cell heading — because a whole-file diff of a 700-line
/// recording is not a finding anybody reads.
fn first_difference(expected: &str, got: &str) -> String {
    let mut cell = "(before the first cell)";
    for (n, (e, g)) in expected.lines().zip(got.lines()).enumerate() {
        if e.starts_with("=== ") {
            cell = e;
        }
        if e != g {
            return format!(
                "the OAuth 2.1 control surface answered DIFFERENT BYTES after the move.\n\
                 cell:      {cell}\n\
                 line:      {}\n\
                 recorded:  {e}\n\
                 now:       {g}\n\
                 \n\
                 This file is the whole witness for the move: there are no 1.5.5 golden cells for \
                 `oauth_as:`. A difference here is a behaviour change, not a fixture that needs \
                 re-recording — re-record only when the CHANGE ITSELF is the intent and is named in \
                 the commit.",
                n + 1
            );
        }
    }
    let (e, g) = (expected.lines().count(), got.lines().count());
    format!(
        "the OAuth 2.1 control surface answered a DIFFERENT NUMBER OF LINES after the move: the \
         recording has {e}, this run produced {g}. The last cell in common was {cell}."
    )
}
