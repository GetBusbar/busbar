# Outbound destination guard and TLS trust store: one place for each

Status: DESIGN for adversarial review and owner sign-off. Nothing past the design is built.
Date: 2026-11-12. Base: core `fix/corefix-integration` @ e207f2aea4. Plugin repos: each repo's `dev`.
Branches already pushed for reference (not merged): core `feat/single-destination-policy` (14304112c3),
core `feat/single-destination-policy-retire-allow-private` (c61a57d82e, gated), README-only branches
`feat/single-destination-policy` in busbar-export-otlp, busbar-export-webhook, busbar-auth-oidc.

Owner decisions this design implements:

* 2026-11-12, destination guard: busbar 1.6.0 has ONE location for outbound private-address policy,
  core's destination guard (`advanced.block_private_addresses`, default true, plus
  `advanced.allow_destinations`: hosts, `*.domain` wildcards, IPs, CIDRs; cloud metadata always
  refused). No feature- or plugin-specific switches. The guard lives at the outbound transport seam,
  in core (`busbar-core-connector`), exactly once.
* 2026-11-12, trust store: ONE core TLS trust store next to the guard. System roots plus listed
  CAs, or listed only, with optional per-destination CAs. No skip-verify option, ever. Certificate
  and hostname verification are always on. CAs are validated at boot (they parse, they are CA
  certificates, they have not expired), and their fingerprints are logged and audited. The same
  mechanism applies to every outbound TLS connection, through core's connector. Plugins with their
  own `ca_cert_pem` switch to it, and `--migrate-config` migrates `ca_cert_pem`.

---

## 1. Problem

### 1.1 Destination policy

Core already has one guard on the dial path (`crates/busbar-core-connector/src/guard.rs`). It
resolves the name once, judges the name and every address it answers, admits exactly those
addresses for the op's ticket (`hostio::Admission::Dial`), and the carrier can `io.open` only an
admitted literal (`hostio.rs:512-515`). Four things sit beside it:

1. **Per-registration widening.** `tools.<server>.allow_private` (plane-mcp) and
   `agents.<agent>.allow_private` (plane-a2a) feed the plane trust role `TRUST_PRIVATE_REACH`
   (`abi/plane/mod.rs:1217`). It reaches `Guard::judge_*_with(.., reach = true)`, which admits any
   non-metadata private address for that registration without consulting `allow_destinations`.
   That is a second policy, decided per plugin.
2. **A copy of the guard in a plugin.** busbar-hook-webrequest `src/net_guard/mod.rs`
   (`host_is_blocked`, `ip_is_internal`) judges the URL's literal host at configure time. It is
   stricter than core in one way: it refused IPv6 site-local `fec0::/10`, which core's
   `busbar_contract::net::ipv6_is_internal` did not (fixed on `feat/single-destination-policy`).
   It also contradicts the one policy: it refuses an allowlisted private literal.
3. **Plaintext rules in seven places.** The connector's class rule (`lib.rs:212-225`,
   `process.rs:104-149`). Plugin rules keyed on `allow_private`: a2a `card_trust.rs:215`, mcp
   `tools_config.rs:1282`. Plugin and core rules keyed on "the host is private or loopback":
   auth-oidc `fetch.rs:183`, auth-oauth `style.rs:447`, auth-github `guard.rs:57`, core
   `config_validate/destinations.rs:124` (provider `base_url`), `config_validate/mod.rs:1584,2090`,
   `preflight.rs:1116`. Result: an in-cluster `http://otel-collector:4318` on 10.x is refused even
   when allowlisted (BUSBAR-7140, traces off until reload), while an a2a agent at `http://` on a
   public host was admitted under `allow_private: true`.
4. **Config-time pre-judgements beside the dial-time guard.** These are core
   `busbar-core-connector/src/endpoint.rs` (a metadata-name subset),
   `busbar-kernel-egress/src/trust/net.rs` `ssrf_blocked_host` / `judge_against_lists` (provider
   URLs at validation), and the BUSBAR-3025 provider advisory. Each is built from the shared
   predicates, not from `Guard`, so each can drift from it.

### 1.2 TLS trust

Core has one client TLS builder (`busbar-core-connector/src/tls/client.rs`): bundled Mozilla roots
(`webpki_roots`) plus `EgressTrust::extra_anchors`, with `PinnedKeyVerifier` layered over WebPKI
verification. The problems:

1. **Each plugin brings its own CA.** auth-ldap, auth-github, auth-oidc and secret-vault each
   declare a setting `ca_cert_pem` as a need's `trust_from` path. plane-mcp has
   `tools.<s>.tls.ca_cert_pem` (`TLS_FROM = settings.*.tls`). Core parses whatever PEM the path
   holds (`operator_ca_anchors`) and adds it beside the bundled roots for that need only. The
   validation is "it parses and rustls accepts it". There is no CA check, no expiry check, no
   fingerprint, and no audit. Five grammars state the same thing.
2. **A skip-verify path exists.** `tls::client::unverified_client_config()` (`AcceptsAnyCertificate`)
   is reachable through the connector ABI flag `UPGRADE_VERIFY_OFF`
   (`abi/host/conn/connector.rs:339`) and the SDK's `upgrade_secure_unverified`. Today it is
   honoured only for the `operator-infrastructure` class. Users: store-postgres `sslmode=prefer`
   (`pgwire.rs:1116-1128`) and store-valkey's `#insecure` URL fragment (`lib.rs:80-83,192-197,366`).
3. **"System roots" means the bundled Mozilla set**, not the OS store. An enterprise CA installed
   in the OS is ignored, and auth-oidc's README says so.

---

## 2. Options

### 2.1 Where the destination policy lives

| option | description | pros | cons |
|---|---|---|---|
| D-a, status quo | Core guard plus per-plugin switches and copies | No work | Multiple policies; per-plugin bypass; drift (fec0) |
| D-b, core guard plus per-registration reach | Keep `TRUST_PRIVATE_REACH`, drop the plugin copies | Small change | Still a per-plugin switch; the owner rejected it |
| **D-c, one core guard at the connector seam; plugins never dial or judge** | All policy in `advanced.*`; plugins declare needs only; `dest.judge` for content-named hosts | One place; transports already comply (no dial-path ABI change); least privilege by exact entries | Retire one plane ABI role; migration for `allow_private` |
| D-d, enterprise egress-policy table | Ordered rules `{match, action, schemes, ports, tls}` (Istio ServiceEntry / Envoy RBAC style) | Most expressive (ports, schemes per destination) | Large grammar; ordering semantics; overkill for 1.6.0 |

**Chosen: D-c**, with one structured extension borrowed from D-d. An `allow_destinations` entry may
be an object carrying per-destination attributes (`plaintext`, see D1). That keeps one table with
one matcher, without rule ordering.

### 2.2 Plaintext (D1, owner decides)

| option | rule | pros | cons |
|---|---|---|---|
| P-a | Loopback only, everywhere outside `open-web`; everything else TLS | Simplest; strictest | In-cluster collectors and sidecars without TLS cannot be reached |
| P-b | Loopback, plus any destination `allow_destinations` names | No new grammar | Listing a host so it can be reached privately would also, silently, admit cleartext to it (an implicit widening) |
| **P-c (recommended)** | Loopback, plus a destination whose `allow_destinations` entry says `plaintext: true` | Explicit, per destination, least privilege, auditable | Small grammar addition (object entry) |

Under every option: `open-web` stays TLS-only, every plugin scheme gate goes, and the provider
`base_url` rule moves into the same core check.

### 2.3 Trust store

| option | description | pros | cons |
|---|---|---|---|
| T-a, status quo | Per-plugin `ca_cert_pem` via `trust_from` | No work | Five grammars; no CA/expiry checks; no audit |
| T-b, one global list | `advanced.tls.trust_anchors` trusted for every destination | Simple | A CA for one internal service becomes trusted for all of them (widening); enterprise reviews reject this |
| **T-c, global roots plus per-destination anchors, one matcher** | `advanced.tls.roots` (base set) + `trust_anchors` (global) + `destinations` (per-match anchors), applied by the connector at dial time by server name | Least privilege by default (migration writes per-destination); global for a real corporate root; one validation, audit and fingerprint path | Dial-time config selection (cache per (need, matched entry)) |
| T-d, OS verifier (`rustls-platform-verifier`) | Delegate verification to the OS | Matches enterprise desktop expectation; honours OS revocation | Behaviour differs per host image; a new dependency (deny/vet); containers often ship no store |

**Chosen: T-c.** `roots: system` is offered as an opt-in base set (T-d's store, read once at
boot), never as the default.

---

## 3. Chosen design

### 3.1 Config surface

```yaml
advanced:
  block_private_addresses: true             # unchanged, default true
  allow_destinations:                       # unchanged short form: a host, *.domain, IP or CIDR
    - ollama.internal
    - 10.20.30.0/24
    - host: otel-collector.observability.svc.cluster.local   # object form (new)
      plaintext: true                       # D1 / P-c: this destination may be dialled without TLS
  tls:                                      # new: THE trust store, boot-time
    roots: bundled                          # bundled (default, today's Mozilla set) | system (OS store, read at boot) | none
    trust_anchors:                          # trusted for every destination, on top of `roots`
      - { file: /etc/busbar/ca/corp-root.pem }
    destinations:                           # trusted only for a destination the entry matches
      - match: ldap.corp.internal           # same matcher as allow_destinations: host, *.domain, IP, CIDR
        trust_anchors:
          - { file: /etc/busbar/ca/ldap-ca.pem }
```

* Anchor sources are `{file:}`, `{env:}`, a `kind: secret` reference, or inline PEM (a CA
  certificate is public; inline is accepted).
* `roots: none` with an empty `trust_anchors` and no matching `destinations` entry means every TLS
  dial fails closed with a named refusal.
* There is no key that disables verification or hostname checking. None is reserved for one.
* Matching for `tls.destinations` uses the TLS server name the dial verifies (SNI host), or the IP
  for an IP target, through the same `Entry` matcher as the guard (`guard.rs`). A dial matching
  several entries trusts the union of their anchors.
* Pins (`cert_spki`, `pinned_pubkey`) stay layered OVER chain and name verification
  (`PinnedKeyVerifier`). A pinned self-signed server therefore needs its certificate or CA listed in
  the store. That is intended: the pin narrows, it never replaces verification.

### 3.2 Behaviour

* The connector builds the base `RootCertStore` once at boot (`roots` + `trust_anchors`). At dial
  time it adds the anchors of every matching `tls.destinations` entry and builds (and caches, per
  (need, matched-entry set)) the client config. `build_client_config` remains the only rustls
  client builder in the product.
* `trust_from` stops carrying CA roots (see §5). It keeps carrying a member's client identity
  (`{cert, key}`) and pin.
* Boot validation runs for every anchor (global and per destination):
  * PEM parses, and holds only certificates.
  * Each certificate is X.509 v3 with `basicConstraints CA:TRUE`. If `keyUsage` is present it
    includes `keyCertSign`.
  * `notBefore <= now < notAfter`. An expired or not-yet-valid anchor is fatal.
  * An anchor within 30 days of `notAfter` gets an Actionable warning.
  * rustls accepts it as a trust anchor.
  * Each failure is a typed Config code naming the key, the index and the reason, never the PEM.
  * Parsing uses `x509-parser`, already in `Cargo.lock`. Confirm cargo-deny/vet coverage for
    core's direct use.
* Every accepted anchor gets one log line (a Config code): SHA-256 fingerprint of the DER, subject,
  issuer, `notAfter`, and where it applies (`global` or the match). It also gets one audit record
  (kind `config.tls_trust_anchor`, in the kernel audit chain) at boot and whenever the committed
  set changes.
* Skip-verify is gone. `unverified_client_config`, `AcceptsAnyCertificate`, the host honouring of
  `UPGRADE_VERIFY_OFF` and the SDK's `upgrade_secure_unverified` are removed (§5).

### 3.3 Destination policy behaviour (already designed and partly built)

* `fec0::/10` is internal in the shared predicate (built: 14304112c3).
* `allow_private` is retired. The kernel trust-section reader refuses it with BUSBAR-3027 and no
  registration holds a private reach (built, gated: c61a57d82e).
* The plaintext decision moves into the connector class rule only (D1). Per-plugin scheme gates
  are deleted.
* The config-time pre-judgements (§1.1 item 4) call `Guard::judge_name` instead of the raw
  predicates, so boot advisories and dial-time refusals can never disagree.

---

## 4. Migration (`busbar --migrate-config`)

| input | rewrite | report |
|---|---|---|
| `tools.<s>.allow_private: true`, `agents.<a>.allow_private: true` | Remove the key. Add an exact `allow_destinations` entry for each host the registration dials (`url`, `token_exchange.token_url`, `oauth.token_endpoint`). Never a wildcard or network, never a metadata host. If the URL is `http://` and P-c is chosen, write the object form `{host, plaintext: true}` | One change line per host; a warning on plaintext; built at c61a57d82e (object form pending D1) |
| `allow_private: false` | Remove | Change line |
| A plugin `settings.ca_cert_pem` (auth-ldap `url`; auth-github API base; auth-oidc `issuer`; secret-vault `addr`), `tools.<s>.tls.ca_cert_pem` (`url`) | Remove the key. Add `advanced.tls.destinations: [{match: <exact host of that registration's target>, trust_anchors: [<the same value, reference kept as written>]}]`. Merge into an existing entry with the same match | Change line naming the registration, the host and the anchor's fingerprint (computed at migrate time when readable; a reference is listed by name only) |
| auth-oidc: discovered `jwks_uri` / `token_endpoint` on another host | Cannot be known offline | TODO naming the issuer: add `tls.destinations` entries for the discovered hosts, or move the CA to `trust_anchors` if it is a corporate root |
| store-valkey URL `#insecure` | Remove the fragment | TODO: list the server's CA under `tls.destinations` (the connection is now verified) |
| store-postgres `sslmode=prefer` / `allow` | Keep the value; its meaning becomes "TLS verified when the server offers it, else plaintext" | Warning: an offered certificate that does not verify now fails the connection instead of being accepted |

After 1.6.0, leftover keys are refused with typed codes (one registry, `catalog.toml`):

| code | refusal |
|---|---|
| BUSBAR-3027 | `allow_private` (built) |
| BUSBAR-3028 (proposed) | A need whose `trust_from` resolves to a CA bundle: a plugin still reading `ca_cert_pem`. Refused at need declaration, naming the plugin and the path, pointing to `advanced.tls.destinations` |
| BUSBAR-3029 (proposed) | A TLS anchor that fails boot validation (parse, not a CA, expired, not yet valid) |
| BUSBAR-3030 (proposed) | Anchor accepted (Actionable/info line carrying the fingerprint; audited) |
| BUSBAR-3031 (proposed) | Anchor expires within 30 days |

---

## 5. ABI implications (owner review; nothing implemented)

The dial path needs **no** ABI change. Carriers already dial only host-admitted literals, and
framers own no socket.

| ABI item | change | layout impact | who moves |
|---|---|---|---|
| `abi::plane::TRUST_PRIVATE_REACH` (=4) | Retired: the number stays reserved; a Statement declaring it is refused at load (`check_trust_keys`); `TrustAnchors::private_reach`, `PollConns::seal_reach` and the guard's `reach` parameter are deleted | None (a role value); plane ABI minor bump for the semantic change | plane-mcp, plane-a2a (drop the key) |
| `abi::host::conn::connector::UPGRADE_VERIFY_OFF` (bit 1) | Retired: reserved; the host answers Refused when set; SDK `upgrade_secure_unverified` removed | None (a flag bit); connector ABI minor bump | store-postgres (`prefer` becomes verified-if-offered), store-valkey (`#insecure` removed) |
| `Need::trust_from` | Semantics narrowed: a member's client identity and pin only, never CA roots. A path that resolves to a CA bundle is refused (BUSBAR-3028) | None | auth-ldap, auth-github, auth-oidc, secret-vault (drop the anchored needs), plane-mcp (`tls.ca_cert_pem` goes; `client_identity` stays) |
| `abi::host::service::DEST_REFUSE_PRIVATE` (dest.judge flag) | Owner choice: keep (a plugin may only ask STRICTER than the deployment; plane-mcp uses it for tool-argument hosts) or retire (then `block_private_addresses: false` also opens tool-argument hosts). Recommend keep | None | none if kept |
| `EgressTrust` (contract `transport/trust.rs`) | Gains no field: `extra_anchors` is filled by the connector from the store, never from a plugin | None | none |

No new ABI names, and no protocol nouns.

---

## 6. Duplication audit (every overlapping mechanism, core and all plugin repos)

Scan scope: non-test code of core and every `/Users/matthew/Developer/GetBusbar/busbar-*` repo.
Patterns covered: guard predicates, `allow_private`, scheme rules, `ca_cert_pem` / root loading,
rustls builders, `reqwest` / `hyper` / `ureq` / sockets. Test-only uses are excluded and listed at
the end.

### 6.1 Destination policy

| # | mechanism | where | design action | pros | cons |
|---|---|---|---|---|---|
| G1 | The guard | core `busbar-core-connector/src/guard.rs` | KEEP, the one | Already on the dial path; checks after resolution; pins the checked address | none |
| G2 | Shared predicates | core `busbar-contract/src/net.rs` | KEEP as the guard's library; `fec0::/10` added (built) | One predicate set | Public: a plugin can build a copy from it. Add a source rule refusing `ip_is_internal`/`METADATA_HOSTS` use outside core |
| G3 | Pre-dial metadata-name check | core `busbar-core-connector/src/endpoint.rs` (`compose.rs:389`) | REPLACE with `Guard::judge_name` | Removes a subset copy | Touches compose's early-refusal message |
| G4 | Provider URL metadata judgement at validation | core `busbar-kernel-egress/src/trust/net.rs:216-250` | REPLACE with `Guard::judge_name` | Boot and dial verdicts cannot drift | Needs the guard built before validation |
| G5 | Provider private-host advisory BUSBAR-3025 | core `config_validate/mod.rs:1555-1575`, `preflight.rs:1116` | REPLACE the predicate with `Guard::judge_name` | Same | none |
| G6 | Migration classification | core `busbar-migrations/src/config/migrate_plugins.rs:986` `allow_if_private` | KEEP (migration only, never on a dial path) | Offline; reports | A second reading of the predicates, accepted for a one-shot tool |
| G7 | Per-registration reach | plane-mcp `statement.rs:261`, `tools_config.rs:528`; plane-a2a `statement.rs:289,303`; core `trust/section.rs`, connector `reach` | REMOVE (BUSBAR-3027 + ABI retire) and MIGRATE to exact `allow_destinations` | One policy | `allow_private` also gated plaintext (D1) |
| G8 | Literal-host guard copy | hook-webrequest `src/net_guard/mod.rs` | REMOVE the address checks once webrequest CI's pinned core carries `fec0::/10`; KEEP URL-grammar validation (userinfo, ambiguity) | Count of guards becomes 1 | Configure-time refusal moves to the dial (or call `dest.judge` at configure for an early, same-policy answer: recommended) |
| G9 | Tool-argument SSRF walk | plane-mcp `argguard.rs` (asks `dest.judge`) | KEEP (it judges content, not a dial, through core) | Not a copy | Depends on the `DEST_REFUSE_PRIVATE` decision |
| G10 | Card fetch verdict text | plane-a2a `card_trust.rs` `refused_name`/`refused_address` (maps `dest.judge` verdicts) | KEEP; reword to name `allow_destinations` | Not a copy | Text only |
| S1 | Connector class scheme rule | core `lib.rs:212-225`, `process.rs:104-149` | KEEP as the only plaintext rule; extend per D1 | One place | none |
| S2 | Plaintext keyed on `allow_private` | plane-a2a `card_trust.rs:215`; plane-mcp `tools_config.rs:1282` | REMOVE | | Needs D1 first |
| S3 | Plaintext keyed on a private host | auth-oidc `fetch.rs:183`; auth-oauth `style.rs:447-457`; auth-github `guard.rs:57`; core `config_validate/destinations.rs:124` (provider `base_url`) | REMOVE; S1 decides | One rule | Errors move from validation to the dial, unless validation asks S1 (recommended: a pure `scheme_admitted(class, url, entries)` used by both) |
| S4 | Per-plugin plaintext opt-in | auth-ldap `allow_insecure_transport` (`lib.rs:176,410`) | REPLACE with the D1 per-destination `plaintext: true`; MIGRATE | One mechanism | LDAP bind over plaintext stays possible, but only explicitly per host |
| S5 | `public_url` scheme rule | core `busbar-core-admin/src/config.rs:33` | OUT OF SCOPE (busbar's own advertised URL, not an outbound dial) | | |

### 6.2 TLS trust and clients

| # | mechanism | where | design action | pros | cons |
|---|---|---|---|---|---|
| T1 | The client builder | core `tls/client.rs` `build_client_config`, `wants_client_cert`, `webpki_roots_store` | KEEP, the one; base set from `advanced.tls.roots` | One builder | none |
| T2 | Pin verifier | core `tls/client.rs` `PinnedKeyVerifier` | KEEP (layered over verification) | Correct already | none |
| T3 | Plugin CA via `trust_from` | core `tls/client.rs` `operator_ca_anchors`/`operator_ca_config`, `lib.rs:2514`, `door_steps.rs:1905,4392,4485` | REPLACE with the store; share one `validate_anchor` (CA, expiry, fingerprint) | One validation, audit and fingerprint path | Transition: plugins must stop declaring before core refuses (BUSBAR-3028) |
| T4 | Skip-verify | core `tls/client.rs:112-160` `unverified_client_config`, `AcceptsAnyCertificate`; `lib.rs:2572-2582`; contract `UPGRADE_VERIFY_OFF`, SDK `store/wire.rs:59,288,1432` | REMOVE (ABI retire) | No skip-verify anywhere | postgres `prefer` and valkey `#insecure` behaviour change (migration warnings) |
| T5 | auth-ldap `ca_cert_pem` | `auth-ldap/src/lib.rs:164`, `door.rs:61-90` (anchored need) | REMOVE; MIGRATE to `tls.destinations` (match the `url` host) | | |
| T6 | auth-github `ca_cert_pem` | `auth-github/src/lib.rs:112`, `door.rs:61-83` | REMOVE; MIGRATE | | GitHub Enterprise Server hosts need an entry |
| T7 | auth-oidc `ca_cert_pem` | `auth-oidc/src/fetch.rs:58,95,395`, `lib.rs`, `open.rs` (anchored need set) | REMOVE; MIGRATE (issuer host + TODO for discovered hosts) | Halves the needs (anchored and public sets collapse) | Discovered hosts cannot be migrated offline |
| T8 | secret-vault `ca_cert_pem` | `secret-vault/src/lib.rs:101,148,161`, `door.rs:49-83` | REMOVE; MIGRATE (match the `addr` host) | | |
| T9 | plane-mcp `tools.<s>.tls.ca_cert_pem` | `plane-mcp/src/statement.rs:73-75,129,149`, `tools_config.rs:107-138,994` | REMOVE the CA; KEEP `client_identity` on `trust_from`; MIGRATE | | Schema change in a plane grammar |
| T10 | a2a / mcp `client_identity` | plane-a2a `settings.schema.json:109,265`; plane-mcp `ClientIdentityCfg` | KEEP (client identity, not trust) | | |
| T11 | postgres `sslrootcert` | `store-postgres/src/pgwire.rs:299-305` (already refused: "verified against busbar's trust anchors") | KEEP the refusal; point its text at `advanced.tls.destinations` | Already aligned | |
| T12 | postgres `sslmode=prefer` unverified | `store-postgres/src/pgwire.rs:28-41,1116-1128` | REPLACE with verified-if-offered | No skip-verify | Behaviour change |
| T13 | valkey `#insecure` | `store-valkey/src/lib.rs:80-83,192-197,366-367` | REMOVE; MIGRATE (TODO to list the CA) | | Behaviour change |
| T14 | mysql `ssl-mode` | `store-mysql/src/credentials/mod.rs:71-80` (`required` and up are verified through the host) | KEEP | Already verified | |
| T15 | Inbound listener `client_ca` | core `tls/mod.rs:115-133` (`RootCertStore` for inbound mTLS) | OUT OF SCOPE (inbound). Reuse `validate_anchor` for the same checks | Same CA hygiene inbound | |
| T16 | HTTP clients in shipped plugin code | none. `transport-http` `door/engine.rs` and `transport-grpc` `transport.rs` run `hyper::client::conn` sans-IO over bytes the host already secured; `reqwest` is dev-only (auth-oidc, secret-vault, hook-webrequest, transport-http); mysql `open_tcp` is `#[cfg(test)]` | KEEP; add a CI source rule refusing `reqwest`/`ureq`/`std::net::TcpStream`/`rustls::ClientConfig` in non-test plugin code | Keeps the count at one | |
| T17 | Clients of busbar (not busbar's outbound) | busbar-admin `src/client.rs` (`reqwest`, `insecure`, `ca_cert_pem`); terraform/pulumi providers; SDKs (busbar-go/js/python); busbar-release tooling | OUT OF SCOPE (they call busbar's admin API). Separate owner decision on busbar-admin `--insecure` | | |

Test-only uses (unchanged): core `test_support.rs` RootCertStore, `tls/tests.rs` AcceptAnyServerCert,
plugin `tests/support/*` networking (`net_ban.rs`, `tls_front.rs`, `ldap_tls.rs`, …).

### 6.3 Counts

| | before | after this design |
|---|---|---|
| Address-guard implementations on a dial path | 2 (G1, G8) + per-registration bypass (G7) | 1 (G1) |
| Config-time address pre-judgements built from raw predicates | 3 (G3, G4, G5) | 0 (they call G1) |
| Plaintext rules | 7 sites (S1-S4) | 1 (S1) |
| Rustls client builders | 1 (T1) + skip-verify (T4) | 1 |
| CA grammars | 5 plugin settings (T5-T9) | 1 (`advanced.tls`) |

---

## 7. Test plan (red first: each test is written and seen failing on the current base before its fix)

Destination guard:
1. `guard_tests::every_feature_plugin_class_is_governed_by_the_one_allowlist`: provider,
   loopback-allowed, open-web and default classes; private (including `fec0::7`) refused by
   default, admitted by host/IP/CIDR entries, metadata refused even when covered. RED on e207f2aea4
   for `fec0::7` (built, green at 14304112c3).
2. Contract `ipv6_site_local_is_internal_and_its_neighbours_keep_their_reading` (built).
3. Kernel `a_registration_writing_the_retired_private_reach_is_refused_whatever_its_value` (BUSBAR-3027; built, gated).
4. Migration `allow_private_becomes_exactly_the_registrations_hosts_in_the_one_allowlist` and `allow_private_never_lists_a_metadata_host` (built, gated).
5. Plugin-level, per feature plugin, through the host connector fixture (not the plugin's own code):
   a dial to a private address is refused by default; admitted when `allow_destinations` lists the
   host; metadata refused when listed. Cover export-otlp, export-webhook, hook-webrequest,
   auth-oidc, plane-mcp, plane-a2a. RED for plane-mcp and plane-a2a under `allow_private`
   semantics.
6. hook-webrequest: with `net_guard` removed, `fec0::1` and `169.254.169.254` are still refused at
   the dial (RED if the core pin lacks the fec0 fix), and an allowlisted `10.x` literal is admitted.
7. D1, once decided: `http://` to an allowlisted non-loopback host refused, and admitted with
   `plaintext: true` (P-c). `open-web` never admits plaintext. One table test over the class rule
   replaces the per-plugin scheme tests.
8. Config-time pre-judgements (G3-G5) agree with the guard: a property test over a host corpus
   (names, literals, alternate encodings, IDN) asserts `boot verdict == dial verdict`.
9. Source rule: no non-test plugin code uses `ip_is_internal` / `METADATA_HOSTS` / sockets / HTTP
   clients / rustls `ClientConfig`.

Trust store:
10. Boot validation table: not PEM, a leaf (`CA:FALSE`), `keyUsage` without `keyCertSign`, expired,
    not-yet-valid, a valid CA. The bad ones are refused with BUSBAR-3029 naming key and index; the
    valid one is accepted, and its log line carries the SHA-256 fingerprint (BUSBAR-3030). RED:
    today an expired CA in `ca_cert_pem` is accepted.
11. Expiry window: an anchor 10 days from `notAfter` warns (BUSBAR-3031).
12. Audit: one `config.tls_trust_anchor` record per accepted anchor at boot, and a new record when
    the committed set changes.
13. Connector: a TLS dial to a server whose chain ends in a listed `tls.destinations` CA succeeds
    only for the matching host; the same CA presented by another host fails (least privilege).
    `trust_anchors` admits it everywhere. `roots: none` plus no anchor fails closed with a named
    refusal.
14. Hostname verification: a valid chain with a wrong SAN fails, whatever the anchors and pins.
15. No skip-verify: `UPGRADE_VERIFY_OFF` set gets Refused (RED: today honoured for
    operator-infrastructure); postgres `sslmode=prefer` against a self-signed server fails unless
    its CA is listed; valkey `#insecure` is refused at parse.
16. Migration: each plugin's `ca_cert_pem` moves to an exact-host `tls.destinations` entry (a
    reference kept as a reference); `#insecure` removed with a TODO; an auth-oidc discovered-host
    TODO; idempotent on a second run.
17. Leftover refusal: a plugin still declaring a CA `trust_from` is refused at need declaration
    with BUSBAR-3028.

Locally: fmt, clippy and these targeted tests only; CI runs the suites.

---

## 8. Sequencing

1. Owner sign-off on D1 (P-c recommended), T-c, `roots` default (`bundled`), the ABI retirements
   (§5) and the `DEST_REFUSE_PRIVATE` choice.
2. Core: the guard (merge `feat/single-destination-policy`); D1 class rule; G3-G5 call the guard;
   `advanced.tls` grammar, validation, audit and connector application; ABI retirements behind the
   minor bumps; BUSBAR-3027..3031; migration; docs.
3. Plugin CI pins move to that core revision.
4. Plugins:
   * webrequest drops `net_guard`;
   * mcp and a2a drop `allow_private` and the scheme gates;
   * oidc, oauth and github drop the scheme rules;
   * ldap, github, oidc and vault drop `ca_cert_pem` and their anchored needs;
   * ldap drops `allow_insecure_transport`;
   * postgres `prefer` becomes verified, and valkey drops `#insecure`;
   * mcp drops `tls.ca_cert_pem`.
5. Merge the gated core branch (BUSBAR-3027 refusal) last, once no plugin pin declares the role.

## 9. Oracle cells needing owner sign-off

* `a2a|fence|egress-message-send` and `mcp|fence|egress-tools-call` (`testing/shadow-oracle/cells.json`):
  their configs set `allow_private: true`.
* The rationale at `testing/shadow-oracle/accepted-differences.json:3109` mentions `allow_private`.
* Trust-store cells: any cell whose capture fixture relies on a plugin `ca_cert_pem` or
  `#insecure` or `sslmode=prefer` (to be enumerated when step 2 starts).

The golden is not edited.
