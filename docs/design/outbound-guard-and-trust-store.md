# Outbound destination guard and TLS trust store: one place for each

> **HISTORICAL DESIGN RECORD (2026-11-12). This is not the shipped contract.** It is kept as the
> record of how the outbound destination guard and the TLS trust store were designed. Where it
> differs from busbar 1.6.0, 1.6.0 wins: the shipped configuration surface and error codes are in
> [the configuration reference](../config-at-a-glance.md) and [the diagnostics catalog](../diagnostics.md).
> In particular: the `plaintext: true` destination row is deleted (transport security is
> `insecure_transport`); there is no `busbar --migrate-config` (the first-boot migration is described
> in [the migration guide](../migration-1.6.md)); `advanced.allow_destinations` is being replaced by a
> per-registration `allow_private`; the "Sunday 2026-11-15" slices below have shipped or been dropped;
> and the diagnostic-code table in R2.5 is corrected to the shipped catalog. Plugin and repository
> names below are those of the design's time.


Status when written: DESIGN, Revision 2 (after the adversarial review, verdict REWORK targeted). Revision 2 (the next section) supersedes Revision 1
wherever they differ; Revision 1 is kept below it unchanged, for history.
Date: 2026-11-12. Revision 1 base: core `fix/corefix-integration` @ e207f2aea4. Revision 2 code read
at: core `origin/feat/single-destination-policy` @ 43fda1da12, `origin/feat/single-destination-policy-retire-allow-private`
@ c61a57d82e, `origin/feat/operator-error-codes` (registry rules), `origin/dev`; plugin repos at
`origin/dev`; `testing/shadow-oracle` at 43fda1da12.

---

## Revision 2

### R2.0 Summary and the Sunday verdict

The review's direction stands and every blocker and major is adopted (R2.1). One correction comes
from the code: **two of the three ABI retirements (`UPGRADE_VERIFY_OFF`, CA via `trust_from`)
cannot be retired before the 1.6.0 GA tag (Sunday 2026-11-15) without first shipping the trust
store.** The trust store is the largest piece of this design. Without it:

* Retiring `UPGRADE_VERIFY_OFF` leaves a store user whose server chains to a private CA (Amazon RDS,
  Cloud SQL, any in-house PKI) with no verified path. `sslrootcert` is already refused
  (`store-postgres pgwire.rs:299-305`), valkey has no CA setting, and the only remaining choice is
  `sslmode=disable` or `redis://`. That pushes these users to plaintext, which is worse than today.
* Retiring CA via `trust_from` removes private-CA support from auth-ldap, auth-github, auth-oidc,
  secret-vault and plane-mcp at GA, with nothing to replace it.

**Plain verdict:** the full pre-GA slice the review asked for (three retirements, two-phase, plus the
egress-class rule) is **too risky for Sunday**. The **safe pre-GA slice** (R2.3) is:

1. Retire `TRUST_PRIVATE_REACH` fully. Its replacement, `advanced.allow_destinations`, already exists.
2. Close the parts of the egress-class hole that are ABI values: refuse `operator-infrastructure` on a
   plugin's `dest.judge`, and refuse a framed (`http`/`grpc`) operator-infrastructure need that has
   no declared target.
3. Freeze `UpgradeIn::offered_name`: it is never a trust selector, and it must equal the dial host
   unless the dial is an IP literal.
4. Remove the metadata carve-out in `allow_destinations`. It is new in 1.6, so it is frozen config at
   GA.
5. Ship `UPGRADE_VERIFY_OFF`, CA via `trust_from`, and operator-infrastructure carriers without a
   declared target as **reserved-but-accepted, deprecated** values. The GA ABI docs state the sunset
   (refused from 1.7.0). Operator-actionable cases get a coded warning and an audit record.
6. Optional, and only if the owner signs the five 1.5.5 golden cells in R2.8 by Friday: retire the
   1.5.5 metadata keys at GA. Otherwise they ship deprecated and are retired in 1.7.0.

This slice changes **two plugins in lock-step: plane-mcp and plane-a2a.** It takes about 3 core
dev-days plus 1 plugin dev-day. The risk to Sunday is **medium**: the work is small and local, and the
risk sits in rebasing onto `feat/operator-error-codes` and in re-tagging two plugins against the
1.6.0 test kit. Everything else is post-GA (R2.4).

### R2.1 Disposition table (review finding → change)

| Finding | Disposition | Change (where specified) | Slice |
|---|---|---|---|
| B1 metadata carve-outs | ADOPT | Metadata is always refused, with no exceptions (R2.2.1). The `pins` carve-out and the name-arm lift are removed. An `allow_destinations` entry naming metadata is refused at boot (3134). `security.allow_all_metadata`, `security.allow_metadata_hosts` and `providers.<p>.allow_metadata_hosts` are retired (3136, migration 3411). There is no carve-out for credential plugins: workload-identity federation only, and any future instance credentials come from a core-owned source in a separate design | Carve-out 1: PRE-GA. Keys 2-4: PRE-GA if the owner signs R2.8 item 4, else deprecated at GA and retired in 1.7.0 |
| B2 plaintext for carriers; `prefer` downgrade | ADOPT | One rule, P-c, for framed **and** carrier needs: plaintext intent only to loopback or to an exact-host `{host, plaintext: true}` entry. There is no opportunistic mode. Postgres `prefer`/`allow` are refused (migrated to `require`). The intent is declared from the operator's URL and judged at need declaration (R2.2.2) | POST-GA. At GA, `prefer` stays opportunistic and deprecated (3138 warning). Owner signs the known gap (R2.9 D-5) |
| B3 egress class self-selection | ADOPT, split | (a) `dest.judge` refuses `EGRESS_OPERATOR_INFRASTRUCTURE` from a plugin (6014). (b) A framed operator-infrastructure need without `target_from` is refused at declaration (6013). (c) A carrier operator-infrastructure need without `target_from` (postgres, valkey, mysql, ldap) is a deprecated shape at GA and refused from 1.7.0. The four carriers move to a declared target post-GA. (d) The a2a card fetch judges in the registration's own class (`provider`), not open-web | (a), (b), (d): PRE-GA. (c): doc at GA, code POST-GA |
| B4 trust chosen by `offered_name` | ADOPT, refined | Trust is selected only by the guard-judged dial target, never by `offered_name`. `offered_name` must equal the dial host when the dial target is a name. A dial to an IP literal may offer a name, because libpq `hostaddr` + `host` needs it (`store-postgres pgwire.rs:401-440`), but anchors are still selected by the dialled target | PRE-GA (constraint + ABI doc); store selection POST-GA |
| M1 proxies | ADOPT | R2.2.6 | POST-GA (default behaviour unchanged at GA) |
| M2 runtime expiry | ADOPT | Boot load, plus a periodic sweep registered in the unified `Refresher` of `secret-refresh-resilience.md` (D1), not a new thread. Runtime expiry withdraws the anchor (5048). The 30-day warning repeats daily. `notBefore` has a 5-minute tolerance. Fatal-at-boot stays for operator anchors, and its text names the scoped destination and the runbook | POST-GA |
| M3 `roots: system` rules | ADOPT | R2.2.4. Base-set rules differ from anchor rules: expired or non-CA roots are dropped with one coded warning carrying the count. An empty system set is a boot refusal. `SSL_CERT_FILE`/`SSL_CERT_DIR` are logged and audited. New release dependencies `rustls-native-certs` and `x509-parser` get vet audits, not exemptions | POST-GA |
| M4 `roots: none` + pin panics | ADOPT | An empty effective store is a coded refusal at config build (3140). `PinnedKeyVerifier::new` returns `Result`. `wants_client_cert` surfaces every failed `add` | POST-GA (`roots` does not exist at GA, and bundled is never empty) |
| M5 exclusive anchors; no secret refs | ADOPT | A matching `tls.destinations` entry's anchors **replace** the base set. `include_roots: true` opts back in. Sources are `{file}`, `{env}` and inline only. A secret-ref `ca_cert_pem` migrates to a TODO | POST-GA |
| M6 reload semantics | ADOPT | Boot-time, restart to apply (consistent with the guard). The periodic sweep also compares each file anchor's on-disk SHA-256 with the loaded one and warns on change (5049). No hot reload | POST-GA |
| M7 every refusal audited | ADOPT | Every dial refusal (5046) and every TLS verification failure (5047) gets a coded, rate-limited line plus an audit record. `FACTS` gains an appended reason field (append-only, minor) | POST-GA |
| M8 client identity on plugin needs | ADOPT | A settings-path `trust_from` may hold `{cert, key}` (key as a sealed secret ref, never in plugin memory) and a pin, for any outbound need. This serves CyberArk CCP, Oracle wallets and MongoDB X.509. Today the connector reads a settings-path `trust_from` only as CA PEM (`lib.rs:2511-2522`); the identity shape is reserved in the GA ABI doc | Doc PRE-GA, code POST-GA |
| M9 sequencing; "minor bump" | ADOPT, refined | No minor-bump semantics. Two phases, **plugins first**: phase 1 = first-party plugins stop using the value (works against today's core); phase 2 = core refuses with a code naming the plugin and the value. Core CI never goes red. `-dev`-built drop-ins are unsupported. Values core cannot retire by Sunday ship reserved-but-accepted with a documented 1.7.0 sunset (R2.3 item 5). BUSBAR-6013 also refuses by schema shape (a CA-string setting feeding `trust_from`) once the sunset arrives | PRE-GA for role 4; sunset POST-GA |
| M10 code allocation | ADOPT | R2.5. 3133 is taken by `login-attempt-limiter.md`, so refusals start at **3134**, migration at **3410**, plugin-ABI refusals at **6013**, runtime egress at **5046**. 3027 is renumbered to 3135 | PRE-GA for the codes the pre-GA slice emits |
| M11 migration rows | ADOPT | Secret-held URLs get a TODO and a coded plugin parse refusal. `CA:FALSE` self-signed anchors: a RED test pins today's behaviour, then migration reports the concrete fix (3418). auth-oidc discovered hosts: the open-time failure carries the host to add (5047 fields) | POST-GA |
| M12 credentials over plaintext | ADOPT | A credential's `require_secure` is never lifted toward a non-loopback host, `plaintext: true` included. `auth-ldap allow_insecure_transport` migrates to a refusal plus a TODO (3146/3417). There is no `credentials_in_clear` attribute | POST-GA |
| m1 wildcards, plaintext entry shape | ADOPT | Wildcards over a public suffix or a single label are refused (3145). `plaintext: true` is accepted only on an exact host or exact IP (3144). `tls.destinations` IP/CIDR entries match only IP-literal dials | POST-GA. The public-suffix refusal is a 1.6-only key, so it is PRE-GA-eligible, but it needs a PSL dependency, so it is deferred and documented as a limit at GA |
| m2 NAT64 NSP | ADOPT (doc) | Document the limit at GA. `advanced.nat64_prefixes` post-GA | Doc PRE-GA |
| m3 revocation | ADOPT (doc) | "No CRL/OCSP in 1.6.x" is stated. Optional per-anchor `crls: [{file}]` post-GA | Doc |
| m4 test 8 | ADOPT | The boot == dial property is restricted to literals, metadata names and alternate encodings. G4 text stays byte-identical (BOOT-025, BOOT-033) | POST-GA |
| m5 red for the right reason | ADOPT | Tests are driven YAML → validate → designed code | Both |
| m6 DTLS | ADOPT | Out of scope, listed in §6.2 as T18. The ICE call site's `reach` argument is touched only when `reach` is deleted (post-GA) | Doc |
| m7 server-advertised redirects | ADOPT | Content-named, judged in default class with `DEST_REFUSE_PRIVATE`, never operator-infrastructure. SRV targets are each judged | Doc (rule), code with each store |
| m8 base | ADOPT | Build rebases onto `origin/dev` and `feat/operator-error-codes` | PRE-GA |
| m9 docs `configuration.md:1944` | ADOPT | Rewritten with R2.2.1 | PRE-GA |
| m10 MSSQL TDS | ADOPT (doc) | Any future framed TLS builds through `build_client_config` and the store | Doc |
| Review "recommended decisions": busbar-admin `--insecure` | ADOPT | Remove `--insecure`. Keep `--ca-cert` and add `--pin sha256/…` (SPKI). busbar-admin is versioned on its own (0.2.x), so this is not GA-frozen. Ship in busbar-admin 0.3.0. Terraform/pulumi `insecure` follow the same rule | POST-GA (independent) |
| Review: valkey `#insecure` | ADOPT | Refused at parse with a plugin-declared code (3143). Migration removes it from literal URLs and writes a TODO for ref-held URLs | POST-GA (deprecated, 6015 warning at GA) |
| secret-refresh-resilience §9 (finding 6, T-G1/T-G2) | ADOPT | Both holes (address-arm `pins`, name-arm lift) closed in R2.3 item 4. Tests T-G1 and T-G2 are adopted verbatim | PRE-GA |

### R2.2 Revised rules (normative; replace §3 where they differ)

#### R2.2.1 Metadata (new §3.4)

* A cloud-metadata destination (`METADATA_HOSTS`, `ip_is_cloud_metadata`, link-local v4, `fe80::/10`,
  and operator `security.blocked_metadata_hosts`) is refused in **every** class, for every plugin and
  every core caller. No configuration admits it.
* `guard.rs` changes:
  * In `judge_address`, `allowlisted` never applies to a denied address. The `self.allow.iter().any(|e| e.pins(addr))` branch (`guard.rs:505-507`) is removed, and `Entry::pins` goes with it.
  * In `judge_name_with`, `allowed` no longer lifts the `METADATA_HOSTS`/`blocked` refusal (`guard.rs:430-436`).
  * `Metadata::lifts`/`carves_address` and the provider carve-out class are deleted when keys 2-4 retire.
* Boot: `strict()` (`guard.rs:225`) refuses an `advanced.allow_destinations` entry that is a metadata
  host name, a metadata literal, or a /32 or /128 equal to a metadata address. The code is
  **BUSBAR-3134**, and the message names the index. A wider CIDR that merely covers metadata is
  accepted (it never admits metadata). The docs say so.
* Instance credentials: no plugin need and no `allow_destinations` entry ever reaches IMDS. The
  supported route is workload-identity federation (IRSA, AKS WI, GKE WIF) through projected token
  files, which `secret-refresh-resilience.md` (b) re-reads on rotation. ECS task roles, EKS Pod
  Identity or plain EC2/GCE instance credentials, if demanded, become a **core-owned credential
  source** in their own design: core dials IMDSv2 on fixed paths, audited, and hands sealed
  credentials to custody. Enterprise designs cite this paragraph.
* 1.5.5 keys `security.allow_all_metadata`, `security.allow_metadata_hosts` and
  `providers.<p>.allow_metadata_hosts` are refused (**BUSBAR-3136**). `--migrate-config` removes
  them (**BUSBAR-3411**, warning naming each removed entry). BUSBAR-5045
  (`METADATA_PROTECTION_DISABLED`) becomes `retired = true`. BUSBAR-3132's `action` text loses its
  `allow_metadata_hosts` advice. **Owner-gated** (R2.8 item 4).

#### R2.2.2 Plaintext: one rule, P-c, every transport

* A need has a **security intent** for each target:
  * `tls` (secure from the first byte);
  * `upgrade` (secured mid-stream before any application byte or lent credential);
  * `plaintext`.
* Framed needs take it from the scheme. A carrier states it in an appended `Need` detail derived
  from the operator's URL (append-only, so a minor change post-GA): postgres `sslmode`, valkey
  `redis://`/`rediss://`, mysql `ssl-mode`, ldap `ldap://`/StartTLS/`ldaps://`.
* `plaintext` is admitted only:
  * to loopback, or
  * to a destination whose `allow_destinations` entry is `{host: <exact host or IP>, plaintext: true}`.

  This is judged at need declaration (early, coded **BUSBAR-3141**) and again at the dial.
* `upgrade` is enforced by the host. It refuses to lend any credential, and refuses reads and writes
  past the negotiation window, until `upgrade_secure` succeeds. **There is no opportunistic intent.**
* `open-web` never admits plaintext.
* A credential's `require_secure` is never lifted toward a non-loopback host (M12).
* Plane registrations (`tools.<s>.url`, `agents.<a>.url`, `token_exchange.token_url`) are
  config-declared targets and follow P-c in their need's own class.
* Every plugin scheme gate (S2, S3, S4 and S6-S9 in R2.6) is deleted when this lands.
  * **Interim at GA:** plane-mcp and plane-a2a gate `http://` to **loopback only**. Revision 1 keyed
    the gate on `allow_private`, which is retired. Widening this to P-c later is compatible;
    tightening a wider rule later would not be.

#### R2.2.3 Egress class (new rule in §3.3)

* `EGRESS_OPERATOR_INFRASTRUCTURE` is a property of a **config-declared target**, never a
  plugin's choice.
  * `dest.judge` from a plugin refuses class 2 (`host_services.rs:2737`) with **BUSBAR-6014**.
    Content-named hosts are judged in default or open-web with `DEST_REFUSE_PRIVATE`.
  * An operator-infrastructure need whose transport is framed (`http`, `grpc`) and that declares
    no `target_from` is refused at `declare` (`lib.rs:2486`) with **BUSBAR-6013**. No first-party
    plugin declares one: secret-vault has `target_from`, and plane-mcp's stdio need has the member
    program.
  * A carrier (`tcp`, `unix`) operator-infrastructure need without `target_from` is the
    **deprecated** shape at GA. Today that is postgres, valkey, mysql and ldap: they name the target
    per connection because of multi-host lists, `hostaddr`, unix sockets and LDAP URL lists.
    * Post-GA, these carriers declare `target_from` on their URL setting, and the connector derives
      the admitted host set from that URL/DSN (libpq URL and key-value forms, multi-host,
      `hostaddr`, `socket=`, `rediss://`, LDAP URL lists). An open is admitted only to a member of
      that set.
    * From 1.7.0 the deprecated shape is refused with BUSBAR-6013.
    * No operator warning at GA: the operator cannot act on a plugin's shape. The conformance kit
      flags it to plugin authors.
* `judged_class` (`guard.rs:59`) is unchanged: a configured default-class need still lifts to
  operator-infrastructure.

#### R2.2.4 Trust store (T-c revised; replaces §3.1-3.2 where they differ)

```yaml
advanced:
  tls:
    roots: bundled                  # bundled (default; 1.5.5 parity: webpki-roots) | system | none
    trust_anchors:                  # trusted for every destination, on top of roots
      - { file: /etc/busbar/ca/corp-root.pem }
    destinations:
      - match: ldap.corp.internal   # exact host, *.domain (not over a public suffix), IP or CIDR
        trust_anchors: [ { file: /etc/busbar/ca/ldap-ca.pem } ]
        include_roots: false        # default: these anchors REPLACE roots + trust_anchors for this match
```

* **Selection.** Selection is by the guard-judged dial target (`line.target()`), never by
  `offered_name` and never by a proxy hop. Name entries match a name dial. IP and CIDR entries match
  only IP-literal dials. A dial matching several entries trusts the union of their anchors (plus the
  roots and `trust_anchors` if any matching entry sets `include_roots`).
* **Sources.** Anchors come from `{file}`, `{env}` or inline PEM. Secret refs are refused (boot
  cycle: Vault's own CA).
* **Operator-anchor validation** (global and per destination):
  * the PEM parses and holds only certificates;
  * v3 with `CA:TRUE` and, if present, `keyCertSign`;
  * `notBefore - 5 min <= now < notAfter`;
  * rustls accepts it.

  A failure is fatal at boot with **BUSBAR-3137**, naming the key, the index, the scoped destination
  and the rotation runbook. An anchor expiring within 30 days warns with **BUSBAR-3139**, daily.
  Every accepted anchor gets one **BUSBAR-3138** line (SHA-256 of the DER, subject, issuer,
  `notAfter`, scope) and one `config.tls_trust_anchor` audit record.
* **Base-set rules (`bundled`, `system`):** expired or non-CA roots are dropped with one
  **BUSBAR-3140** warning carrying the count. Each `rustls-native-certs` error is reported, never
  dropped. An empty system set is a boot refusal (3140, Fatal). The log carries a count and a SHA-256
  of the sorted set, never 150 lines. The `SSL_CERT_FILE`/`SSL_CERT_DIR` source is logged and
  audited.
* **`roots: none`** with no matching anchor: the config build refuses with 3140. It never panics
  (`PinnedKeyVerifier::new` returns `Result`).
* **Runtime.** A periodic sweep (hourly, in the unified `Refresher`) withdraws expired anchors from
  new client configs (5048, audited). A dial whose matched entry has no anchor left is refused
  (5047). File anchors whose on-disk digest changed get **BUSBAR-5049** ("restart to apply").
* **Revocation:** none in 1.6.x (stated).
* **Pins** stay layered over verification.

#### R2.2.5 `offered_name` (ABI doc, frozen at GA)

`UpgradeIn::offered_name` is the SNI and the name verified, and **never selects trust anchors**. When
the dial target is a host name, `offered_name` must equal it (case-insensitive, after IDNA). If it does
not, the call is Refused with **BUSBAR-6014**. When the dial target is an IP literal, any DNS name may
be offered (libpq `hostaddr`), and the anchors are those of the IP target.
store-postgres passes `endpoint.name`, store-valkey passes `t.host`, and auth-ldap passes `None`, so
every first-party caller already complies.

#### R2.2.6 Proxies (new §3.5)

(a) The name arm always applies. The address arm applies when the name resolves locally (1.5.5
reqwest parity).
(b) One boot line (**BUSBAR-3149**) plus an audit record names the redacted proxy endpoint and
`NO_PROXY`, and states that the address check is delegated for names that do not resolve locally.
(c) `NO_PROXY` is parsed through the guard's `judged_host`, giving one matcher (`proxy_route.rs:102-190`
is replaced).
(d) Owner option `advanced.proxy_resolution: local` sends `CONNECT <judged literal>:port`.
(e) The trust store selects by target, not by proxy hop.

The proxy hop's own judgement (`reach = true` today, `lib.rs:1777-1781, 2000-2004`) becomes a
config-declared operator-infrastructure target when `reach` is deleted.

### R2.3 PRE-GA slice (must land before the 1.6.0 tag, Sunday 2026-11-15)

Rule for this slice: change only what is ABI-frozen or config-frozen at GA, choose the strict form
now (it can be widened later compatibly), and change no plugin except where it must move in
lock-step.

**Order (plugins first, so core CI never goes red):** P1/P2 merged and tagged against the 1.6.0 test
kit, then C3 (refusal of role 4). Everything else is independent of the plugins.

Core (one branch, rebased onto `origin/dev` + `feat/operator-error-codes`):

| # | Change | Where | Codes | Effort |
|---|---|---|---|---|
| C1 | Metadata: remove the `pins` carve-out and the name-arm lift. Boot refusal of a metadata `allow_destinations` entry. Fix `configuration.md:1940-1947`. Tests T-G1, T-G2, and a boot refusal for each entry form | `busbar-core-connector/src/guard.rs`, `guard_tests.rs` (flip `a_name_entry_never_admits_a_metadata_answer`, `an_exact_metadata_allow_entry_is_the_documented_carve_out`) | 3134 | 0.5 d |
| C2 | Merge c61a57d82e (the kernel refuses `allow_private`; migration writes exact hosts). Renumber 3027 → **3135**. Refuse the `allow_private` key **by name** in every `tools.*`/`agents.*` registration, so the coded refusal survives the plugins dropping role 4. Give the migration's lines code **3410**. A `http://` non-loopback registration's migration warning says "refused at GA; use https (P-c `plaintext: true` arrives post-GA)" | `busbar-kernel/src/trust/section.rs`, `catalog.toml`, `busbar-migrations/src/config/migrate_1_6.rs` | 3135, 3410 | 0.5 d |
| C3 | Retire `TRUST_PRIVATE_REACH` (=4) as a reserved value: `check_trust_keys` refuses role 4 (fault `trust_key.role_retired`), and the loader refuses the plugin naming it and the role. The internal `reach` plumbing is left dead and deleted post-GA (the proxy hop still uses it) | `busbar-contract/src/abi/plane/check.rs:1651`, `abi/plane/mod.rs:1217` (doc: RESERVED), `plugin-loader/src/dispatch/kinds/plane.rs:611` | 6013 | 0.5 d |
| C4 | `dest.judge` refuses `EGRESS_OPERATOR_INFRASTRUCTURE` from a plugin | `busbar-kernel/src/host_services.rs:2737`, `abi/host/service.rs` doc | 6014 | 0.25 d |
| C5 | A framed operator-infrastructure need without `target_from` is refused at `declare`. The carrier shape is documented as deprecated (refused from 1.7.0) | `busbar-core-connector/src/lib.rs:2486`, `abi/host/conn/connector.rs:19` doc | 6013 | 0.5 d |
| C6 | `offered_name` constraint (R2.2.5) and ABI doc | `busbar-core-connector/src/lib.rs:2558-2605`, `abi/host/conn/connector.rs:328` | 6014 | 0.25 d |
| C7 | Reserved-but-accepted, deprecated: `UPGRADE_VERIFY_OFF` is still honoured only for operator-infrastructure (as today). Its untyped WARN becomes **BUSBAR-6015** once per instance, plus an audit record. CA via `trust_from` is still accepted: an info line with the SHA-256 of each anchor, and no operator warning (the operator cannot act until the store exists). ABI docs on `UPGRADE_VERIFY_OFF`, `UpgradeIn::flags`, `Need::trust_from` (identity `{cert, key}` + pin reserved; CA PEM deprecated) and `EGRESS_OPERATOR_INFRASTRUCTURE` state "deprecated; refused from 1.7.0" | `lib.rs:2572-2582`, `connector.rs:331-339`, `tls/client.rs` `operator_ca_anchors`, `abi/sdk/store/wire.rs:283` (doc only: no `#[deprecated]` attribute, which would fail plugins' `-D warnings` clippy at a pin bump) | 6015 | 0.5 d |
| C8 (owner-gated) | Retire the 1.5.5 metadata keys (R2.2.1). Retire 5045 | `busbar-kernel` config schema and validation, `guard.rs` `Metadata`, `busbar-migrations`, `catalog.toml`, docs | 3136, 3411 | 0.75 d |

Plugins (lock-step; each merged to `dev` and tagged against the 1.6.0 test kit before C3):

| # | Plugin | Change | Effort |
|---|---|---|---|
| P1 | **busbar-plane-mcp** | Drop the `allow_private` trust key (`statement.rs:262`) and the field. `dest_verdict` (`plane_door_impl.rs:1476`) always passes `DEST_REFUSE_PRIVATE` for tool-argument hosts. The `token_exchange.token_url` scheme gate (`tools_config.rs:1281-1289`) becomes https, or http to a loopback host only | 0.5 d |
| P2 | **busbar-plane-a2a** | Drop the `allow_private` trust key (`statement.rs:289`). Card fetch (`plane_door.rs:3977-3981`) judges a **registered agent's** card in `EGRESS_PROVIDER` (its need's class) with `DEST_EXPLAIN`, so `allow_destinations` governs it; never operator-infrastructure. Push and content hosts stay open-web with `DEST_REFUSE_PRIVATE`. `card_trust.rs` `scheme_refusal` becomes https, or http to loopback only, and its refusal text names `allow_destinations` (G10) | 0.5 d |

No other plugin changes for GA. store-postgres, store-valkey, store-mysql, auth-ldap, auth-github,
auth-oidc, secret-vault and webrequest keep working unchanged against the GA core.

**Totals and risk.**
* Core: C1-C7 about 3.0 dev-days, plus about 0.75 for C8.
* Plugins: about 1.0 dev-day, plus two re-tags.
* Tests: as listed in R2.7 (targeted locally; CI runs the suites).
* **Risk to Sunday: MEDIUM.** The changes are small and local. The main risks are:
  * (1) the rebase onto `feat/operator-error-codes` (the codes need its `text` machinery; if that
    branch does not land before GA, the same numbers are added without `text` and gain it when it
    lands);
  * (2) two plugin re-tags against the 1.6.0 test kit (`release/plugin-pins.tsv` is still empty);
  * (3) the a2a and mcp fence cells, which need an owner signature (R2.8).
* **Fallback if P1 or P2 cannot be re-tagged by Sunday:** skip C3. C2 already refuses the config key
  by name, so role 4 can never carry `true`; the role is inert. Ship role 4 as reserved-but-accepted
  (6015 at load, refused from 1.7.0). C1, C4-C7 do not depend on the plugins.
* **Not recommended for Sunday (Option B, rejected):** shipping a minimal `advanced.tls` before GA so
  that `UPGRADE_VERIFY_OFF` and CA via `trust_from` could retire now. It brings `x509-parser` (and
  likely `rustls-native-certs`) as new release dependencies needing vet audits, a new config grammar,
  validation, audit and migration. That is 4-6 dev-days plus five plugin re-tags. **High** risk.

**What the deprecated values cost.** They ship at GA and are refused at 1.7.0 without an ABI_MAJOR
bump. That breaks the append-only reading of `ABI_MINOR` (`abi/mod.rs:240`). The owner signs it as a
documented deprecation exception (R2.9 D-2), or else they stay honoured until ABI 2.

### R2.4 POST-GA slice

| # | Work | Plugins affected | Effort | Risk | Oracle cells |
|---|---|---|---|---|---|
| Q1 | Trust store (R2.2.4): grammar, validation, base-set rules, audit, connector selection by target, exclusive anchors, sweep in the unified `Refresher` (1.6.1 per `secret-refresh-resilience.md` D1), file-change warning; `x509-parser` + `rustls-native-certs` vet | none (core) | 6-8 d | Medium (new deps, connector config cache per matched set) | none with `roots: bundled`; `wire.tls|client-hello|*` unchanged (rustls sends no CA list) |
| Q2 | Retire CA via `trust_from` (sunset 1.7.0): migration of `ca_cert_pem` → `tls.destinations` (exact host; ref → TODO; `CA:FALSE` detection 3418); 6013 by schema shape | auth-ldap, auth-github, auth-oidc, secret-vault, plane-mcp (`tools.<s>.tls.ca_cert_pem`) | core 2 d, plugins 0.5 d each | Medium | none known (no cell sets `ca_cert_pem`) |
| Q3 | Retire `UPGRADE_VERIFY_OFF` (sunset 1.7.0): host Refused + 6013/6014; delete `unverified_client_config`, `AcceptsAnyCertificate`, SDK `upgrade_secure_unverified`. Postgres `prefer`/`allow` refused (3142), migration `prefer` → `require` (3412); valkey `#insecure` refused (3143), migration (3413, TODO for refs) | store-postgres, store-valkey | core 1 d, plugins 1 d | Medium (operator behaviour change; needs Q1 first) | none (no cell uses `prefer` or `#insecure`) |
| Q4 | P-c for every transport (R2.2.2): intent detail on `Need` (append-only), declaration-time judgement, upgrade enforcement, object entries, delete every plugin scheme gate; ldap `allow_insecure_transport` → refusal + TODO | store-postgres, store-valkey, store-mysql, auth-ldap, secret-vault, auth-oidc, auth-oauth, auth-github, plane-mcp, plane-a2a, hook-webrequest | core 4 d, plugins 3 d | High (largest operator-visible change) | `store.boot|postgres|private-validate`, `store.boot|valkey|private-validate` (R2.8 item 6); BOOT-023/031 text kept byte-identical |
| Q5 | Carriers declare `target_from` (R2.2.3), connector derives host sets; 6013 for the old shape from 1.7.0 | store-postgres, store-valkey, store-mysql, auth-ldap | core 2-3 d, plugins 1 d | Medium (multi-host and `hostaddr` corners; `store.boot|postgres|multi-host`/`key-value` must stay green) | none expected |
| Q6 | Proxies (R2.2.6) | none | 2 d | Medium | none with defaults |
| Q7 | Audit of every dial refusal and TLS failure (5046/5047), `FACTS` reason (appended) | none | 1.5 d | Low | none |
| Q8 | Client identity on any outbound need (M8) | enabling only; enterprise stores later | 2 d | Medium | none |
| Q9 | Remove the dead `reach` plumbing; G3-G5 call `Guard::judge_name`; webrequest drops `net_guard` (calls `dest.judge` at configure) | hook-webrequest | 1.5 d | Low | none (texts byte-identical) |
| Q10 | Wildcard public-suffix refusal, `plaintext` entry shape, `nat64_prefixes`, optional CRLs | none | 1.5 d | Low | none |
| Q11 | busbar-admin: remove `--insecure`, add `--pin`; terraform/pulumi `insecure` | busbar-admin (0.3.0), providers | 0.5 d + 1 d | Low | none (not in the oracle) |
| Q12 | If C8 was not signed: retire the 1.5.5 metadata keys in 1.7.0 (deprecated + 3136 warning at GA) | none | 0.75 d | Low | R2.8 item 4 |

Post-GA total: about 25-30 dev-days. Q1 must precede Q2 and Q3, Q4 must precede the deletion of the
plugin scheme gates, and Q5 must precede the 1.7.0 refusal of the carrier shape.

### R2.5 Diagnostic codes (registry rules of `feat/operator-error-codes`)

Checked against that branch's `catalog.toml` and `docs/errors/LEDGER.tsv`, every `origin/*` branch,
and the sibling designs. 3133 is claimed by `login-attempt-limiter.md`, and 8026-8028 by
`secret-refresh-resilience.md`. Re-check at merge. Each operator-facing entry carries `text`,
`example` and `example_detail`.

Shipped catalog (`crates/busbar-kernel/src/diagnostics/mod.rs`; each entry below is checked against it).
The table of codes this design proposed was wrong in several places and is replaced by what shipped:

| Code | Slug | Notes |
|---|---|---|
| 3134 | config-destination-names-metadata | Fatal |
| 3135 | config-private-reach-retired | Fatal |
| 3136 | config-metadata-carve-out-retired | Fatal |
| 3137 | config-tls-anchor-invalid | Fatal |
| 3138 | config-tls-anchor-accepted | Info-level (BenignRecurring); not a `prefer` deprecation |
| 3139 | config-tls-anchor-expiring | Actionable |
| 3140 | config-tls-trust-empty | Fatal (this design called it `config-tls-base-set`) |
| 3144 | config-plaintext-entry-not-exact | Fatal |
| 3145 | config-wildcard-over-public-suffix | Fatal |
| 3147 | config-tls-base-roots-dropped | Actionable |
| 3148 | config-tls-destination-invalid | Fatal |
| 3149 | config-proxy-delegates-address-check | BenignRecurring |
| 3410 | migrate-private-reach-to-allowlist | Actionable |
| 3411 | migrate-metadata-carve-out-removed | Actionable |
| 5047 | egress-tls-verification-failed | Actionable |
| 5048 | egress-tls-anchor-expired-withdrawn | Actionable |
| 5049 | egress-tls-anchor-file-changed | Actionable |
| 5051 | egress-dial-refused | BenignRecurring (5046 shipped as `plane-usage-unread`) |
| 6014 | plugin-call-refused-abi-rule | Actionable |
| 6015 | plugin-uses-deprecated-abi-value | Actionable |
| 6017 | plugin-declares-retired-abi-value | Fatal (6013 shipped as `plugin-text-cut`) |

Proposed here and **not in the shipped catalog**: 3141 (`config-plaintext-not-admitted`, though the
catalog text for 5051 still names it), 3142 and 3143 (plugin-declared store refusals), 3146, and
3412 to 3418. The migration guide's 3417 has no emitter. See issue #301 (error-catalog codes emitted
with no catalog row). 3160 and 3161 appear only as literal strings in `crates/plugin-loader/src/instance.rs`.

Revision 1's 3028-3031 were withdrawn.

### R2.6 Duplication audit additions (§6)

| # | Mechanism | Where | Action |
|---|---|---|---|
| G11 | Plugin-chosen egress class | `dest.judge` class argument (`process.rs:80-90`, `host_services.rs:2737`); operator-infrastructure needs without `target_from` (`lib.rs:2497-2503`) | REPLACE with core-derived class (R2.2.3) |
| S6 | Postgres plaintext and opportunistic modes | `store-postgres pgwire.rs:28-41,222,244-256` | REPLACE with intent + P-c (Q3, Q4) |
| S7 | Valkey `redis://` versus `rediss://` | `store-valkey lib.rs:191` | REPLACE with intent + P-c |
| S8 | MySQL `ssl-mode` disabled/preferred | `store-mysql credentials/mod.rs:71-80` | REPLACE with intent + P-c |
| S9 | LDAP `ldap://` without StartTLS; operator-infrastructure `http://` settings URLs (vault `addr`) | auth-ldap, secret-vault | REPLACE with intent + P-c; credentials never in clear (M12) |
| T18 | DTLS (`dimpl`), ICE candidates | core-connector `datagram.rs` (h3) | OUT OF SCOPE: fingerprint-authenticated by signalling |
| T19 | Future framed TLS (MSSQL TDS PRELOGIN) | none yet | Must build through `build_client_config` and the store |

Counts after Revision 2:
* plaintext rules: 1 (the core intent rule), from 11 sites (S1-S4, S6-S9);
* address guards: 1;
* class selectors: core only;
* rustls client builders: 1, with no skip-verify after Q3. At GA there is still 1 plus a deprecated
  skip-verify path.

### R2.7 Tests added (red first; YAML → validate → designed code where config is involved)

PRE-GA:
* T-G1: flip `a_name_entry_never_admits_a_metadata_answer`.
* T-G2: a metadata-name entry is refused in every class.
* Boot refusal 3134 for an IP, a /32, a /128 and a name entry.
* Flip `an_exact_metadata_allow_entry_is_the_documented_carve_out` to a refusal in the default,
  provider and operator-infrastructure classes.
* 3135 for `allow_private` written in a registration whose plugin declares no role 4.
* Role 4 in a Statement → 6013 naming the plugin.
* `dest.judge` with class 2 → 6014.
* A framed operator-infrastructure need without `target_from` → 6013. A carrier need is still
  admitted.
* `offered_name` ≠ dial host on a name dial → Refused with 6014. An IP-literal dial offering a name is
  admitted.
* `UPGRADE_VERIFY_OFF` → 6015 once per instance plus one audit record.
* plane-a2a: an `http://127.0.0.1` registered agent with `127.0.0.1` allowlisted is fetched, and
  `http://` to a public host is refused.
* plane-mcp: a tool-argument private host is refused whatever is configured.

POST-GA: the review's additional-tests list, in full, attached to Q1-Q10.

### R2.8 Oracle cells needing the owner's explicit signature

PRE-GA (the slice in R2.3):
1. `a2a|fence|egress-message-send` (`cells.json` config at l.121 sets `allow_private: true`). The
   config line is removed. The card is then judged in `provider` and admitted through the oracle pin
   `advanced.allow_destinations: ["127.0.0.1"]`. `http://` to loopback stays admitted. Status and body
   are expected unchanged, but the **cell config edit** needs a signature.
2. `mcp|fence|egress-tools-call` (`cells.json` l.26128, `allow_private: true`): same edit, same
   expectation.
3. `accepted-differences.json:3109` rationale: re-sign the wording. It says "an A2A registration's own
   `allow_private`" and "cloud metadata is refused … unless an IP or CIDR allowlist entry names it",
   and both statements become false. No cell moves.
4. **Only if C8 (retire the 1.5.5 metadata keys at GA) is chosen.** 1.5.5 golden, exit status
   unchanged (1), stderr text changes:
   * `boot.refusal__BOOT-002__validate` (`security.allow_metadata_hosts` CIDR text → 3136 retired-key text);
   * `boot.refusal__BOOT-003__validate` (`providers.gemini.allow_metadata_hosts` → 3136);
   * `boot.refusal__BOOT-025__validate` (the base_url metadata refusal's "to override add … allow_metadata_hosts … allow_all_metadata" advice is removed);
   * `boot.refusal__BOOT-033__validate` (same advice in the token_url refusal);
   * `neutrality__NEUT-U-providers__validate` (the unknown-field list loses `allow_metadata_hosts`).

   The related records also change: the `why` texts at `cells.json` l.12990 and l.13007, and
   `accepted-differences.json` l.272, l.1322 and l.1364. If C8 is deferred, BOOT-002 and BOOT-003
   still gain one 3136 deprecation-warning line at 1.7.0, so the owner signs either now or then.
   `cli|--print-metadata-blocklist` is unchanged: it prints the block list, which stays.

POST-GA:
5. BOOT-023 and BOOT-031 (provider `base_url` / `token_url` plaintext text). Planned **unchanged**:
   Q4 keeps these strings byte-identical. A signature is needed only if Q4 cannot.
6. `store.boot|postgres|private-validate` (`postgres://…@192.0.2.1:5432/busbar`, no sslmode) and
   `store.boot|valkey|private-validate` (`redis://192.0.2.1:6379/0`). 1.5.5 accepts both under
   `--validate`. Under P-c for carriers (Q4), plaintext intent to a non-loopback host without
   `{host, plaintext: true}` is refused at declaration, so both would exit 1. Either the owner signs
   the refusal, or the cell configs gain the entry (also a signed edit). Recommended: sign the
   refusal, because a 1.5.5 operator with a private plaintext database gets a migration-written
   entry (3414) when the URL is literal, and a coded refusal when it is ref-held.
7. Behaviour difference with no cell: a private non-loopback `http://` provider (for example vLLM at
   `http://192.0.2.5:8000`) needs `plaintext: true` in addition to its 2026-10-02 allowlist entry.
8. `admin.ops__GetHooksNameSchema__ok_hooks-webrequest`: unchanged unless the schema description is
   edited for P-c. The plan keeps it.
9. No change: `store.boot|postgres|sslmode-disable`, `sslmode-require`, `multi-host`, `key-value`,
   `url-options`, `loopback*` (all loopback); `wire.tls|client-hello|*`; provider TLS roots (default
   `bundled`); proxy defaults.

### R2.9 Owner decisions requested

| # | Decision | Recommendation |
|---|---|---|
| D-1 | Pre-GA slice = R2.3 C1-C7 + P1/P2, with full retirement of `UPGRADE_VERIFY_OFF` and CA via `trust_from` deferred | Approve |
| D-2 | Deprecated ABI values refused at 1.7.0 without an ABI_MAJOR bump (a documented deprecation exception to append-only) | Approve. The alternative is honouring them until ABI 2 |
| D-3 | C8: retire the 1.5.5 metadata keys at GA (sign R2.8 item 4 by Friday) or deprecate them and retire in 1.7.0 | Retire at GA if signed. It is the cleaner boundary |
| D-4 | Interim plaintext for plane-mcp and plane-a2a at GA: loopback only | Approve (strict now, P-c widens compatibly) |
| D-5 | Known gap at GA: postgres `sslmode=prefer` and valkey `#insecure` stay opportunistic or unverified (deprecated, 6015) until Q1 + Q3 | Accept. The alternative pushes private-CA users to plaintext |
| D-6 | `DEST_REFUSE_PRIVATE` | Keep (unchanged from Revision 1) |
| D-7 | Roots default `bundled`, `system` opt-in | Approve (1.5.5 parity) |
| D-8 | Info-severity anchor lines in the 31xx band (3138, 3149) | Approve |
| D-9 | busbar-admin `--insecure` removed in 0.3.0 | Approve |

---

## Revision 1 (2026-11-12, kept for history; superseded by Revision 2 where they differ)

Original status: DESIGN for adversarial review and owner sign-off. Base: core `fix/corefix-integration`
@ e207f2aea4. Plugin repos: each repo's `dev`.
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
    - 192.0.2.0/24
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
