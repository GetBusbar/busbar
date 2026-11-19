---
title: "Error codes"
description: "Every Busbar 1.6 error and warning code: what it means and how to fix it."
slug: docs/1.6/errors
---

Every operator-facing error and warning Busbar prints carries a permanent `BUSBAR-NNNN` code: config refusals at `--validate` and startup (the one-time upgrade included), CLI errors, admin API error responses (the `code` field) and warn/error log lines (the `diag` field). A message reads `BUSBAR-NNNN: <what is wrong>. See <link>`; the link is the code's page below. Codes are never reused: a retired code keeps its page.

The thousands digit is the area.

## 1xxx: Durability & write-through

| Code | What it reports | Since |
|---|---|---|
| [BUSBAR-1001](/docs/1.6/errors/BUSBAR-1001/) | Durable audit write-through skipped (seq at or below the recovered floor) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-1002](/docs/1.6/errors/BUSBAR-1002/) | Durable audit log has another writer — this node detached its durable sink — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-1003](/docs/1.6/errors/BUSBAR-1003/) | Durable audit write-through held — ring not yet reconciled with the durable tail — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-1004](/docs/1.6/errors/BUSBAR-1004/) | Durable audit write-through failed (entry retained in the in-memory ring) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-1005](/docs/1.6/errors/BUSBAR-1005/) | Durable audit chain has an unrepairable gap (a seq was pruned before it persisted) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-1006](/docs/1.6/errors/BUSBAR-1006/) | Admin store operation failed (generic 500; store detail logged server-side) | 1.6.0 |
| [BUSBAR-1007](/docs/1.6/errors/BUSBAR-1007/) | Admin store blocking task failed to join (cancelled or panicked) | 1.6.0 |
| [BUSBAR-1008](/docs/1.6/errors/BUSBAR-1008/) | Group delete could not read keys to check bindings (admin 500) | 1.6.0 |
| [BUSBAR-1009](/docs/1.6/errors/BUSBAR-1009/) | Admin /usage blocking task failed to join (cancelled or panicked) | 1.6.0 |
| [BUSBAR-1010](/docs/1.6/errors/BUSBAR-1010/) | Store in-flight queue exhausted: new store writes are refused until slots free up | 1.6.0 |
| [BUSBAR-1011](/docs/1.6/errors/BUSBAR-1011/) | A store commit whose earlier send may have applied was fenced on retry | 1.6.0 |
| [BUSBAR-1012](/docs/1.6/errors/BUSBAR-1012/) | A live store commit was answered STALE: the slot queue invariant was broken | 1.6.0 |
| [BUSBAR-1013](/docs/1.6/errors/BUSBAR-1013/) | A self-fenced store commit's readback could not decide whether it applied | 1.6.0 |
| [BUSBAR-1014](/docs/1.6/errors/BUSBAR-1014/) | The store answered an inconsistent time-guard failure | 1.6.0 |

## 2xxx: Audit chain

| Code | What it reports | Since |
|---|---|---|
| [BUSBAR-2001](/docs/1.6/errors/BUSBAR-2001/) | Durable audit chain failed hash-chain verification at boot (tamper evidence) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-2041](/docs/1.6/errors/BUSBAR-2041/) | Per-task provenance chain failed hash-chain verification on restore (tamper) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-2042](/docs/1.6/errors/BUSBAR-2042/) | Plane per-call records failed hash-chain verification on restore (tamper evidence) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-2043](/docs/1.6/errors/BUSBAR-2043/) | Admin audit records failed hash-chain verification on restore (tamper evidence) | 1.6.0 |
| [BUSBAR-2044](/docs/1.6/errors/BUSBAR-2044/) | Admin audit record could not be written through the durable journal seam (evidence lost) | 1.6.0 |
| [BUSBAR-2045](/docs/1.6/errors/BUSBAR-2045/) | Persisted plane per-call record could not be decoded on restore (skipped, not dropped) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-2046](/docs/1.6/errors/BUSBAR-2046/) | Persisted journal record could not be reframed on restore (skipped, not dropped) | 1.6.0 |
| [BUSBAR-2047](/docs/1.6/errors/BUSBAR-2047/) | Persisted admin audit record could not be decoded on restore (skipped, not dropped) | 1.6.0 |
| [BUSBAR-2048](/docs/1.6/errors/BUSBAR-2048/) | A plane journal scope failed hash-chain verification on resume (tamper evidence) | 1.6.0 |
| [BUSBAR-2049](/docs/1.6/errors/BUSBAR-2049/) | The audit notary could not stamp a page (lines stay durable and linked) | 1.6.0 |
| [BUSBAR-2050](/docs/1.6/errors/BUSBAR-2050/) | Audit lines have gone unstamped for too long | 1.6.0 |
| [BUSBAR-2051](/docs/1.6/errors/BUSBAR-2051/) | A request terminal audit original could not be staged | 1.6.0 |
| [BUSBAR-2052](/docs/1.6/errors/BUSBAR-2052/) | An exporter first observed lost delivery or failed evidence | 1.6.0 |
| [BUSBAR-2053](/docs/1.6/errors/BUSBAR-2053/) | Exporter loss evidence remains unconfirmed or a producer reported after quiescence | 1.6.0 |
| [BUSBAR-2054](/docs/1.6/errors/BUSBAR-2054/) | An unstamped audit tail was sealed after a restart | 1.6.0 |
| [BUSBAR-2055](/docs/1.6/errors/BUSBAR-2055/) | An audit chain is broken after its last valid stamp; the tail is recorded, never sealed | 1.6.0 |
| [BUSBAR-2056](/docs/1.6/errors/BUSBAR-2056/) | A crashed predecessor on this host was not sealed | 1.6.0 |
| [BUSBAR-2057](/docs/1.6/errors/BUSBAR-2057/) | Sealing a crashed predecessor is failing and is retried | 1.6.0 |
| [BUSBAR-2059](/docs/1.6/errors/BUSBAR-2059/) | An amendment record names a class this build does not know | 1.6.0 |

## 3xxx: Config

| Code | What it reports | Since |
|---|---|---|
| [BUSBAR-3003](/docs/1.6/errors/BUSBAR-3003/) | Config overlay unreadable/corrupt on apply (refusing to overwrite) | 1.6.0 |
| [BUSBAR-3004](/docs/1.6/errors/BUSBAR-3004/) | Config overlay written by a newer busbar on apply (refusing to overwrite) | 1.6.0 |
| [BUSBAR-3005](/docs/1.6/errors/BUSBAR-3005/) | Config overlay corrupt at boot (starting on base config.yaml alone) | 1.6.0 |
| [BUSBAR-3006](/docs/1.6/errors/BUSBAR-3006/) | Config overlay written by a newer busbar (boot refuses to start) | 1.6.0 |
| [BUSBAR-3007](/docs/1.6/errors/BUSBAR-3007/) | Config overlay patch does not parse (entry not applied) | 1.6.0 |
| [BUSBAR-3008](/docs/1.6/errors/BUSBAR-3008/) | plugins.min_versions floor is not valid semver (anti-downgrade disarmed) | 1.6.0 |
| [BUSBAR-3009](/docs/1.6/errors/BUSBAR-3009/) | plugins.first_party_floors floor is not valid semver (plugin refused unconditionally) | 1.6.0 |
| [BUSBAR-3010](/docs/1.6/errors/BUSBAR-3010/) | Heterogeneous pool (cross-protocol failover may not preserve all features) | 1.6.0 |
| [BUSBAR-3011](/docs/1.6/errors/BUSBAR-3011/) | auth.chain entry grants max_admin_scope: full | 1.6.0 |
| [BUSBAR-3012](/docs/1.6/errors/BUSBAR-3012/) | auth.chain names `keys` with an empty admin_auth (refused: no admin credential can mint a key) | 1.6.0 |
| [BUSBAR-3013](/docs/1.6/errors/BUSBAR-3013/) | passthrough provider has a non-empty api_key that is never forwarded (inert config) | 1.6.0 |
| [BUSBAR-3014](/docs/1.6/errors/BUSBAR-3014/) | --print-metadata-blocklist printed the built-in denylist only (config unreadable) | 1.6.0 |
| [BUSBAR-3015](/docs/1.6/errors/BUSBAR-3015/) | --validate rejected the config (load, resolve, semantic, or secret-resolution failure) | 1.6.0 |
| [BUSBAR-3016](/docs/1.6/errors/BUSBAR-3016/) | --list-plugins refused a config that exists but is not readable | 1.6.0 |
| [BUSBAR-3017](/docs/1.6/errors/BUSBAR-3017/) | Config-settings read found the overlay unreadable/corrupt (reported no root overrides) | 1.6.0 |
| [BUSBAR-3018](/docs/1.6/errors/BUSBAR-3018/) | Config-settings read found a newer-busbar overlay (reported no root overrides) | 1.6.0 |
| [BUSBAR-3019](/docs/1.6/errors/BUSBAR-3019/) | Config-settings overlay read task failed to join (500 rather than a fabricated 200) | 1.6.0 |
| [BUSBAR-3020](/docs/1.6/errors/BUSBAR-3020/) | rate_card entry prices a model at ALL ZERO (metered as free, uncapped) | 1.6.0 |
| [BUSBAR-3021](/docs/1.6/errors/BUSBAR-3021/) | A deprecated environment variable is set and still honored — RETIRED *(retired)* | 1.5.0 |
| [BUSBAR-3023](/docs/1.6/errors/BUSBAR-3023/) | Config overlay rejected at read (the reason, naming the key and the file) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-3024](/docs/1.6/errors/BUSBAR-3024/) | A metadata host-list entry names no host (it matches nothing and is dropped) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-3025](/docs/1.6/errors/BUSBAR-3025/) | A provider URL names a private or loopback host the destination guard refuses *(retired)* | 1.6.0 |
| [BUSBAR-3026](/docs/1.6/errors/BUSBAR-3026/) | Declared billable classes have no configured rate | 1.6.0 |
| [BUSBAR-3027](/docs/1.6/errors/BUSBAR-3027/) | A 1.5.5 file overlay held settings this Store had not imported — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-3028](/docs/1.6/errors/BUSBAR-3028/) | A 1.5.5 overlay input was not read — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-3029](/docs/1.6/errors/BUSBAR-3029/) | A retired launch environment variable is set (converted or ignored) | 1.6.0 |
| [BUSBAR-3030](/docs/1.6/errors/BUSBAR-3030/) | An auth plugin states the operator credential but is not first-party (ignored) | 1.6.0 |
| [BUSBAR-3101](/docs/1.6/errors/BUSBAR-3101/) | A registration is named with a reserved word | 1.6.0 |
| [BUSBAR-3102](/docs/1.6/errors/BUSBAR-3102/) | A model definition is invalid | 1.6.0 |
| [BUSBAR-3103](/docs/1.6/errors/BUSBAR-3103/) | A model, pool or provider is named after a reserved route prefix | 1.6.0 |
| [BUSBAR-3104](/docs/1.6/errors/BUSBAR-3104/) | A pool shares its name with a provider or a model | 1.6.0 |
| [BUSBAR-3105](/docs/1.6/errors/BUSBAR-3105/) | A pool's member list is invalid | 1.6.0 |
| [BUSBAR-3106](/docs/1.6/errors/BUSBAR-3106/) | A pool's failover block is invalid | 1.6.0 |
| [BUSBAR-3107](/docs/1.6/errors/BUSBAR-3107/) | A pool's on_exhausted block is invalid | 1.6.0 |
| [BUSBAR-3108](/docs/1.6/errors/BUSBAR-3108/) | A pool's affinity header name is invalid | 1.6.0 |
| [BUSBAR-3109](/docs/1.6/errors/BUSBAR-3109/) | Pools' on_exhausted fallbacks form a cycle | 1.6.0 |
| [BUSBAR-3110](/docs/1.6/errors/BUSBAR-3110/) | A pool's circuit-breaker settings are invalid | 1.6.0 |
| [BUSBAR-3111](/docs/1.6/errors/BUSBAR-3111/) | A pool's hook list is invalid | 1.6.0 |
| [BUSBAR-3112](/docs/1.6/errors/BUSBAR-3112/) | A hook definition is invalid | 1.6.0 |
| [BUSBAR-3113](/docs/1.6/errors/BUSBAR-3113/) | An auth policy or key lifetime setting is invalid | 1.6.0 |
| [BUSBAR-3114](/docs/1.6/errors/BUSBAR-3114/) | A role binding is invalid | 1.6.0 |
| [BUSBAR-3115](/docs/1.6/errors/BUSBAR-3115/) | The auth chain cannot authenticate as configured | 1.6.0 |
| [BUSBAR-3116](/docs/1.6/errors/BUSBAR-3116/) | A plane is configured while the data-plane auth chain is empty | 1.6.0 |
| [BUSBAR-3117](/docs/1.6/errors/BUSBAR-3117/) | A global limit or timing setting is out of range | 1.6.0 |
| [BUSBAR-3118](/docs/1.6/errors/BUSBAR-3118/) | A rate card or fee is invalid | 1.6.0 |
| [BUSBAR-3119](/docs/1.6/errors/BUSBAR-3119/) | A group's limits are invalid | 1.6.0 |
| [BUSBAR-3120](/docs/1.6/errors/BUSBAR-3120/) | The store block is missing or names no module | 1.6.0 |
| [BUSBAR-3121](/docs/1.6/errors/BUSBAR-3121/) | A secret reference or secret module setting is invalid | 1.6.0 |
| [BUSBAR-3122](/docs/1.6/errors/BUSBAR-3122/) | A metadata host list entry can never match | 1.6.0 |
| [BUSBAR-3123](/docs/1.6/errors/BUSBAR-3123/) | A provider definition is invalid | 1.6.0 |
| [BUSBAR-3124](/docs/1.6/errors/BUSBAR-3124/) | A provider URL targets a blocked cloud-metadata host | 1.6.0 |
| [BUSBAR-3125](/docs/1.6/errors/BUSBAR-3125/) | A provider's credential cannot be used as configured | 1.6.0 |
| [BUSBAR-3126](/docs/1.6/errors/BUSBAR-3126/) | A provider names a protocol this build does not speak | 1.6.0 |
| [BUSBAR-3127](/docs/1.6/errors/BUSBAR-3127/) | A plane section's failover pool is invalid | 1.6.0 |
| [BUSBAR-3128](/docs/1.6/errors/BUSBAR-3128/) | A reference names a provider that is not defined or speaks the wrong protocol | 1.6.0 |
| [BUSBAR-3129](/docs/1.6/errors/BUSBAR-3129/) | A configuration section is not valid for this build | 1.6.0 |
| [BUSBAR-3130](/docs/1.6/errors/BUSBAR-3130/) | The admin listener is network-exposed without mTLS | 1.6.0 |
| [BUSBAR-3131](/docs/1.6/errors/BUSBAR-3131/) | An export sink definition is invalid | 1.6.0 |
| [BUSBAR-3132](/docs/1.6/errors/BUSBAR-3132/) | An outbound destination is refused by the egress policy | 1.6.0 |
| [BUSBAR-3133](/docs/1.6/errors/BUSBAR-3133/) | A login attempt limit setting is invalid | 1.6.0 |
| [BUSBAR-3134](/docs/1.6/errors/BUSBAR-3134/) | An allowlist entry names a cloud-metadata destination *(retired)* | 1.6.0 |
| [BUSBAR-3135](/docs/1.6/errors/BUSBAR-3135/) | A registration still carries the retired per-registration private-address switch *(retired)* | 1.6.0 |
| [BUSBAR-3136](/docs/1.6/errors/BUSBAR-3136/) | A retired cloud-metadata carve-out key is set | 1.6.0 |
| [BUSBAR-3137](/docs/1.6/errors/BUSBAR-3137/) | An outbound.tls trust anchor is not a usable CA | 1.6.0 |
| [BUSBAR-3138](/docs/1.6/errors/BUSBAR-3138/) | An outbound.tls trust anchor was accepted | 1.6.0 |
| [BUSBAR-3139](/docs/1.6/errors/BUSBAR-3139/) | An outbound.tls trust anchor expires within 30 days | 1.6.0 |
| [BUSBAR-3140](/docs/1.6/errors/BUSBAR-3140/) | No trust anchor applies to a TLS destination | 1.6.0 |
| [BUSBAR-3141](/docs/1.6/errors/BUSBAR-3141/) | Plaintext is not admitted to this destination | 1.6.0 |
| [BUSBAR-3144](/docs/1.6/errors/BUSBAR-3144/) | A plaintext destination entry is not an exact host or IP | 1.6.0 |
| [BUSBAR-3145](/docs/1.6/errors/BUSBAR-3145/) | A destination wildcard is too wide | 1.6.0 |
| [BUSBAR-3147](/docs/1.6/errors/BUSBAR-3147/) | System CA bundle entries were not used | 1.6.0 |
| [BUSBAR-3148](/docs/1.6/errors/BUSBAR-3148/) | An outbound.tls destination entry is invalid | 1.6.0 |
| [BUSBAR-3149](/docs/1.6/errors/BUSBAR-3149/) | Outbound connections go through a proxy | 1.6.0 |
| [BUSBAR-3160](/docs/1.6/errors/BUSBAR-3160/) | A plugin instance would connect without TLS | 1.6.0 |
| [BUSBAR-3162](/docs/1.6/errors/BUSBAR-3162/) | A plugin instance runs with insecure_transport accepted | 1.6.0 |
| [BUSBAR-3163](/docs/1.6/errors/BUSBAR-3163/) | An insecure_transport acceptance is invalid | 1.6.0 |
| [BUSBAR-3170](/docs/1.6/errors/BUSBAR-3170/) | A configuration word, section or style changed its owner after it was read | 1.6.0 |
| [BUSBAR-3171](/docs/1.6/errors/BUSBAR-3171/) | A reserved configuration key was written | 1.6.0 |
| [BUSBAR-3172](/docs/1.6/errors/BUSBAR-3172/) | A listener would serve plaintext without an acceptance | 1.6.0 |
| [BUSBAR-3401](/docs/1.6/errors/BUSBAR-3401/) | The retired migration command was given no file to migrate — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-3402](/docs/1.6/errors/BUSBAR-3402/) | The retired migration command could not read the file it was given — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-3403](/docs/1.6/errors/BUSBAR-3403/) | The retired migration command could not resolve its working directory — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-3404](/docs/1.6/errors/BUSBAR-3404/) | The retired migration command refused the file — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-3405](/docs/1.6/errors/BUSBAR-3405/) | Migration carried refresh_ttl over to verify_ttl, whose meaning differs | 1.6.0 |
| [BUSBAR-3406](/docs/1.6/errors/BUSBAR-3406/) | Migration widened a retired delegated admin scope to full | 1.6.0 |
| [BUSBAR-3407](/docs/1.6/errors/BUSBAR-3407/) | An empty allowed_pools list now means no pools | 1.6.0 |
| [BUSBAR-3408](/docs/1.6/errors/BUSBAR-3408/) | Migration added a binding that keeps 1.5.5's ungoverned access | 1.6.0 |
| [BUSBAR-3409](/docs/1.6/errors/BUSBAR-3409/) | BUSBAR_WORKER_THREADS was not a positive integer and was not captured — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-3410](/docs/1.6/errors/BUSBAR-3410/) | A registration's allow_private was replaced by exact advanced.allow_destinations entries *(retired)* | 1.6.0 |
| [BUSBAR-3411](/docs/1.6/errors/BUSBAR-3411/) | A retired cloud-metadata carve-out key was removed | 1.6.0 |

## 4xxx: Auth & identity

| Code | What it reports | Since |
|---|---|---|
| [BUSBAR-4001](/docs/1.6/errors/BUSBAR-4001/) | Token-exchange could not mint a self-serve key | 1.6.0 |
| [BUSBAR-4002](/docs/1.6/errors/BUSBAR-4002/) | Login plugin offload saturated (permit not acquired; login rejected fail-closed) | 1.6.0 |
| [BUSBAR-4003](/docs/1.6/errors/BUSBAR-4003/) | Login plugin call panicked (login rejected fail-closed) | 1.6.0 |
| [BUSBAR-4004](/docs/1.6/errors/BUSBAR-4004/) | auth.chain is empty (open relay) | 1.6.0 |
| [BUSBAR-4005](/docs/1.6/errors/BUSBAR-4005/) | Auth chain offload saturated (permit not acquired; request denied fail-closed) | 1.6.0 |
| [BUSBAR-4006](/docs/1.6/errors/BUSBAR-4006/) | Auth chain panicked (request denied fail-closed) | 1.6.0 |
| [BUSBAR-4007](/docs/1.6/errors/BUSBAR-4007/) | admin_auth names a module with no resolved plugin | 1.6.0 |
| [BUSBAR-4008](/docs/1.6/errors/BUSBAR-4008/) | Admin auth offload saturated (permit not acquired; request denied fail-closed) | 1.6.0 |
| [BUSBAR-4009](/docs/1.6/errors/BUSBAR-4009/) | Admin auth chain did not complete in time (request denied fail-closed) | 1.6.0 |
| [BUSBAR-4010](/docs/1.6/errors/BUSBAR-4010/) | Admin request forbidden (audit record suppressed this window) | 1.6.0 |
| [BUSBAR-4011](/docs/1.6/errors/BUSBAR-4011/) | auth.chain names `keys` alongside upstream_credentials: passthrough | 1.6.0 |
| [BUSBAR-4012](/docs/1.6/errors/BUSBAR-4012/) | Token-exchange refused an unsafe self-serve subject | 1.6.0 |
| [BUSBAR-4013](/docs/1.6/errors/BUSBAR-4013/) | Egress API key contains invalid header bytes (auth header omitted) | 1.6.0 |
| [BUSBAR-4014](/docs/1.6/errors/BUSBAR-4014/) | Minted OAuth token contains invalid header bytes (auth header omitted) | 1.6.0 |
| [BUSBAR-4015](/docs/1.6/errors/BUSBAR-4015/) | OAuth token endpoint returned a 200 with an empty access_token | 1.6.0 |
| [BUSBAR-4016](/docs/1.6/errors/BUSBAR-4016/) | OAuth token mint (refresh) failed; retrying | 1.6.0 |
| [BUSBAR-4017](/docs/1.6/errors/BUSBAR-4017/) | Scheduled trust sweep could not be attempted (registration not contacted) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-4018](/docs/1.6/errors/BUSBAR-4018/) | Scheduled trust sweep could not authenticate the upstream (failed contact recorded) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-4019](/docs/1.6/errors/BUSBAR-4019/) | Upstream drifted from the approved pin (registration demoted) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-4020](/docs/1.6/errors/BUSBAR-4020/) | Clean trust observation held (recovery backoff not yet elapsed) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-4021](/docs/1.6/errors/BUSBAR-4021/) | Anomaly breaker suspended a trust registration — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-4022](/docs/1.6/errors/BUSBAR-4022/) | Scheduled trust sweep panicked (job continues) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-4023](/docs/1.6/errors/BUSBAR-4023/) | oauth_as expired-record sweep failed (retrying next tick) | 1.6.0 |
| [BUSBAR-4024](/docs/1.6/errors/BUSBAR-4024/) | Request-signing HMAC-SHA256 init failed — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-4025](/docs/1.6/errors/BUSBAR-4025/) | oauth_as generated an ephemeral ES256 signing key (tokens die on restart) | 1.6.0 |
| [BUSBAR-4026](/docs/1.6/errors/BUSBAR-4026/) | admin_auth chain is EMPTY (it identifies no one; 1.6.0 has no open admin posture) | 1.6.0 |
| [BUSBAR-4027](/docs/1.6/errors/BUSBAR-4027/) | create_key request body failed to parse (client 400) | 1.6.0 |
| [BUSBAR-4028](/docs/1.6/errors/BUSBAR-4028/) | create_key allowed_pools names an unconfigured pool (key still created) | 1.6.0 |
| [BUSBAR-4029](/docs/1.6/errors/BUSBAR-4029/) | update_key request body failed to parse (client 400) | 1.6.0 |
| [BUSBAR-4032](/docs/1.6/errors/BUSBAR-4032/) | Sender-constrained (DPoP) credential refused | 1.6.0 |
| [BUSBAR-4033](/docs/1.6/errors/BUSBAR-4033/) | Credential sign-in throttled: the client's source spent its budget | 1.6.0 |
| [BUSBAR-4034](/docs/1.6/errors/BUSBAR-4034/) | Credential sign-in failures passed the global alarm threshold | 1.6.0 |
| [BUSBAR-4035](/docs/1.6/errors/BUSBAR-4035/) | Login attempt limiter cannot reach the core store (sign-ins refused) | 1.6.0 |
| [BUSBAR-4036](/docs/1.6/errors/BUSBAR-4036/) | Client address unknown: per-source login limits skipped | 1.6.0 |
| [BUSBAR-4037](/docs/1.6/errors/BUSBAR-4037/) | A login attempt limiter is disabled | 1.6.0 |
| [BUSBAR-4038](/docs/1.6/errors/BUSBAR-4038/) | Admin door: a source's refused-credential budget is spent | 1.6.0 |
| [BUSBAR-4039](/docs/1.6/errors/BUSBAR-4039/) | Credential sign-in refused: no signing key to key the login limiter | 1.6.0 |
| [BUSBAR-4040](/docs/1.6/errors/BUSBAR-4040/) | Credential method held open after repeated provider outages | 1.6.0 |
| [BUSBAR-4041](/docs/1.6/errors/BUSBAR-4041/) | An account has been throttled for more than four consecutive windows | 1.6.0 |
| [BUSBAR-4042](/docs/1.6/errors/BUSBAR-4042/) | Operator token is shorter than 32 bytes | 1.6.0 |
| [BUSBAR-4043](/docs/1.6/errors/BUSBAR-4043/) | Self-serve sign-in or refresh refused: the subject's key is on hold | 1.6.0 |
| [BUSBAR-4044](/docs/1.6/errors/BUSBAR-4044/) | Admin request to re-enable a revoked key refused (revoked is terminal) | 1.6.0 |
| [BUSBAR-4045](/docs/1.6/errors/BUSBAR-4045/) | Credential sign-in throttled: the account's failure ceiling is reached | 1.6.0 |

## 5xxx: Proxy & routing

| Code | What it reports | Since |
|---|---|---|
| [BUSBAR-5005](/docs/1.6/errors/BUSBAR-5005/) | Routing policy failed; on_error fallback applied | 1.6.0 |
| [BUSBAR-5006](/docs/1.6/errors/BUSBAR-5006/) | Routing policy deadline exceeded; on_error fallback applied | 1.6.0 |
| [BUSBAR-5007](/docs/1.6/errors/BUSBAR-5007/) | on_error fallback hook answered for the failed gate | 1.6.0 |
| [BUSBAR-5008](/docs/1.6/errors/BUSBAR-5008/) | on_error fallback hook failed; continuing down the chain | 1.6.0 |
| [BUSBAR-5009](/docs/1.6/errors/BUSBAR-5009/) | on_error fallback hook deadline exceeded; continuing down the chain | 1.6.0 |
| [BUSBAR-5019](/docs/1.6/errors/BUSBAR-5019/) | Decision gate rejected the request | 1.6.0 |
| [BUSBAR-5020](/docs/1.6/errors/BUSBAR-5020/) | Decision gate restrict left no eligible lane; on_empty: weighted escape | 1.6.0 |
| [BUSBAR-5021](/docs/1.6/errors/BUSBAR-5021/) | Decision gate restrict left no eligible lane (on_empty: reject) | 1.6.0 |
| [BUSBAR-5022](/docs/1.6/errors/BUSBAR-5022/) | Routing policy rejected the request | 1.6.0 |
| [BUSBAR-5023](/docs/1.6/errors/BUSBAR-5023/) | Routing policy restrict left no eligible lane; on_empty: weighted escape | 1.6.0 |
| [BUSBAR-5024](/docs/1.6/errors/BUSBAR-5024/) | Routing policy restrict left no eligible lane (on_empty: reject) | 1.6.0 |
| [BUSBAR-5026](/docs/1.6/errors/BUSBAR-5026/) | Lane hard-down (breaker trip) | 1.6.0 |
| [BUSBAR-5029](/docs/1.6/errors/BUSBAR-5029/) | Usage tap: read_response failed to decode a same-protocol 2xx body | 1.6.0 |
| [BUSBAR-5032](/docs/1.6/errors/BUSBAR-5032/) | Metrics recorder install failed; /metrics will be empty | 1.6.0 |
| [BUSBAR-5033](/docs/1.6/errors/BUSBAR-5033/) | Could not spawn the metrics maintenance thread (observations drain on scrape only) | 1.6.0 |
| [BUSBAR-5034](/docs/1.6/errors/BUSBAR-5034/) | Metrics scrape: failed to list virtual keys (per-key gauges skipped) | 1.6.0 |
| [BUSBAR-5035](/docs/1.6/errors/BUSBAR-5035/) | Metrics scrape: virtual-key count exceeds the per-key gauge limit (truncating) | 1.6.0 |
| [BUSBAR-5036](/docs/1.6/errors/BUSBAR-5036/) | Metrics scrape: usage read failed; skipping key | 1.6.0 |
| [BUSBAR-5037](/docs/1.6/errors/BUSBAR-5037/) | Metrics scrape: group ledger read failed; skipping bucket | 1.6.0 |
| [BUSBAR-5038](/docs/1.6/errors/BUSBAR-5038/) | Plane breaker tripped (upstream target failing; dispatches fast-fail) | 1.6.0 |
| [BUSBAR-5039](/docs/1.6/errors/BUSBAR-5039/) | Plane breaker tripped hard-down (definitive auth/billing failure; sticky cooldown) | 1.6.0 |
| [BUSBAR-5040](/docs/1.6/errors/BUSBAR-5040/) | Lane hard-down across all cells (sticky cooldown; recovers via half-open probe) | 1.6.0 |
| [BUSBAR-5041](/docs/1.6/errors/BUSBAR-5041/) | Unexpected breaker state on classify (fail-safe: deny admission) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-5042](/docs/1.6/errors/BUSBAR-5042/) | Unexpected breaker state on probe acquisition (fail-safe: refuse) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-5043](/docs/1.6/errors/BUSBAR-5043/) | Unexpected breaker state on state read (reporting Closed) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-5044](/docs/1.6/errors/BUSBAR-5044/) | Unexpected breaker state in record_failure (no-op) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-5045](/docs/1.6/errors/BUSBAR-5045/) | Cloud-metadata SSRF protection DISABLED (allow_all_metadata is set) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-5046](/docs/1.6/errors/BUSBAR-5046/) | Provider usage not read (a unit settled without billing its final stated usage) | 1.6.0 |
| [BUSBAR-5047](/docs/1.6/errors/BUSBAR-5047/) | An outbound TLS connection failed verification | 1.6.0 |
| [BUSBAR-5048](/docs/1.6/errors/BUSBAR-5048/) | An expired trust anchor was withdrawn | 1.6.0 |
| [BUSBAR-5049](/docs/1.6/errors/BUSBAR-5049/) | A trust anchor file changed; restart to apply | 1.6.0 |
| [BUSBAR-5050](/docs/1.6/errors/BUSBAR-5050/) | Routing policy made no choice and no member has a known routing cost | 1.6.0 |
| [BUSBAR-5051](/docs/1.6/errors/BUSBAR-5051/) | An outbound dial was refused | 1.6.0 |
| [BUSBAR-5052](/docs/1.6/errors/BUSBAR-5052/) | The local egress framer failed | 1.6.0 |

## 6xxx: Plugins

| Code | What it reports | Since |
|---|---|---|
| [BUSBAR-6001](/docs/1.6/errors/BUSBAR-6001/) | plugins.fetch missed on reload (keeping the current artifact) | 1.6.0 |
| [BUSBAR-6002](/docs/1.6/errors/BUSBAR-6002/) | Plugin present but NOT loaded (skipped by trust policy) | 1.6.0 |
| [BUSBAR-6003](/docs/1.6/errors/BUSBAR-6003/) | Plugin loaded UNVERIFIED (permitted by an explicit plugins.trust opt-in) | 1.6.0 |
| [BUSBAR-6004](/docs/1.6/errors/BUSBAR-6004/) | Cannot fingerprint the plugins dir (bypassing the catalog cache) | 1.6.0 |
| [BUSBAR-6005](/docs/1.6/errors/BUSBAR-6005/) | Plugin catalog scan gate not acquired within the wait bound (retryable 503) | 1.6.0 |
| [BUSBAR-6006](/docs/1.6/errors/BUSBAR-6006/) | Plugin catalog blocking task failed to join (fail-soft to the compiled-in row) | 1.6.0 |
| [BUSBAR-6007](/docs/1.6/errors/BUSBAR-6007/) | Plugin rollback could not persist the version pin (nothing swapped, fail-closed) | 1.6.0 |
| [BUSBAR-6008](/docs/1.6/errors/BUSBAR-6008/) | Plugin rollback rebuild failed AND reverting the version pin failed (disk out of sync) | 1.6.0 |
| [BUSBAR-6009](/docs/1.6/errors/BUSBAR-6009/) | --validate plugin pre-flight failed (structure, trust, conflict, or store resolution) | 1.6.0 |
| [BUSBAR-6010](/docs/1.6/errors/BUSBAR-6010/) | --list-plugins could not build a trust policy (plugins.trust is invalid) | 1.6.0 |
| [BUSBAR-6011](/docs/1.6/errors/BUSBAR-6011/) | First-party anti-downgrade floor unreadable (booting with NO first-party floor) | 1.6.0 |
| [BUSBAR-6012](/docs/1.6/errors/BUSBAR-6012/) | First-party anti-downgrade floor could not be persisted (it will not survive a restart) | 1.6.0 |
| [BUSBAR-6013](/docs/1.6/errors/BUSBAR-6013/) | Plugin-supplied text exceeded its cap and was cut | 1.6.0 |
| [BUSBAR-6014](/docs/1.6/errors/BUSBAR-6014/) | A plugin call was refused by an ABI rule | 1.6.0 |
| [BUSBAR-6015](/docs/1.6/errors/BUSBAR-6015/) | A plugin requested the retired UPGRADE_VERIFY_OFF flag (refused) | 1.6.0 |
| [BUSBAR-6017](/docs/1.6/errors/BUSBAR-6017/) | A plugin declares a retired ABI value | 1.6.0 |
| [BUSBAR-6018](/docs/1.6/errors/BUSBAR-6018/) | A plugin's error-number declaration was refused; it runs without error codes — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-6019](/docs/1.6/errors/BUSBAR-6019/) | A plugin reported an error number it did not declare | 1.6.0 |

## 7xxx: Plane protocols

| Code | What it reports | Since |
|---|---|---|
| [BUSBAR-7030](/docs/1.6/errors/BUSBAR-7030/) | Stateful plane on the in-memory store — plane task state is lost on restart | 1.6.0 |
| [BUSBAR-7087](/docs/1.6/errors/BUSBAR-7087/) | Egress credential has invalid header bytes (auth header omitted) | 1.6.0 |
| [BUSBAR-7089](/docs/1.6/errors/BUSBAR-7089/) | Persisted plane task row could not be read back (not resumable) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-7090](/docs/1.6/errors/BUSBAR-7090/) | SSRF-refused push callback reached the task store (dropped) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-7091](/docs/1.6/errors/BUSBAR-7091/) | Spent-approval ledger unreachable — redemption refused — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-7092](/docs/1.6/errors/BUSBAR-7092/) | Durable plane call log enumerates a principal with NO records — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-7093](/docs/1.6/errors/BUSBAR-7093/) | Durable plane per-call record could not be written (evidence lost) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-7094](/docs/1.6/errors/BUSBAR-7094/) | Durable plane demotion record could not be written | 1.6.0 |
| [BUSBAR-7095](/docs/1.6/errors/BUSBAR-7095/) | Durable plane demotion record could not be cleared | 1.6.0 |
| [BUSBAR-7096](/docs/1.6/errors/BUSBAR-7096/) | Durable plane demotion records could not be read at boot | 1.6.0 |
| [BUSBAR-7097](/docs/1.6/errors/BUSBAR-7097/) | Verify-on-call refused a call because the upstream's advertised surface drifted — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-7098](/docs/1.6/errors/BUSBAR-7098/) | Verify-on-call could not reach an upstream to re-verify, and refused fail-closed — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-7099](/docs/1.6/errors/BUSBAR-7099/) | Abandoned plane task could not be transitioned to canceled (durable store write failed) — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-7106](/docs/1.6/errors/BUSBAR-7106/) | A plane declares a record kind the kernel keeps its own records under (the plane is refused) | 1.6.0 |
| [BUSBAR-7107](/docs/1.6/errors/BUSBAR-7107/) | An admin plane record write named a kernel record kind (the write is refused) | 1.6.0 |
| [BUSBAR-7108](/docs/1.6/errors/BUSBAR-7108/) | A plane's destination judge is not installed (every JUDGE answers internal) | 1.6.0 |
| [BUSBAR-7110](/docs/1.6/errors/BUSBAR-7110/) | A plane reported usage for a class it never declared (the usage is dropped) | 1.6.0 |
| [BUSBAR-7111](/docs/1.6/errors/BUSBAR-7111/) | A plane reported usage with a scale past micro-units (the quantity is rounded) | 1.6.0 |

## 8xxx: Governance & cost

| Code | What it reports | Since |
|---|---|---|
| [BUSBAR-8001](/docs/1.6/errors/BUSBAR-8001/) | Revocation denylist re-sync still outstanding from an earlier window | 1.6.0 |
| [BUSBAR-8002](/docs/1.6/errors/BUSBAR-8002/) | Revocation denylist re-sync failed (keeping the previously-known revocations) | 1.6.0 |
| [BUSBAR-8003](/docs/1.6/errors/BUSBAR-8003/) | Refused to synthesize a governance key (principal id collides with a reserved namespace) | 1.6.0 |
| [BUSBAR-8004](/docs/1.6/errors/BUSBAR-8004/) | Unrecognized limit window (enforcing as all-time 'total') | 1.6.0 |
| [BUSBAR-8005](/docs/1.6/errors/BUSBAR-8005/) | Self-serve refresh left an inconsistent binding (tombstone AND rollback both failed) | 1.6.0 |
| [BUSBAR-8006](/docs/1.6/errors/BUSBAR-8006/) | Self-serve refresh: cache reconcile failed after tombstoning the prior binding | 1.6.0 |
| [BUSBAR-8007](/docs/1.6/errors/BUSBAR-8007/) | Group missing at accrual (tokens ledgered to the key bucket only) | 1.6.0 |
| [BUSBAR-8008](/docs/1.6/errors/BUSBAR-8008/) | Metering flush: some keys failed to persist this tick (retained for retry) | 1.6.0 |
| [BUSBAR-8009](/docs/1.6/errors/BUSBAR-8009/) | delete_key: tombstone committed and key evicted, but cache reconcile failed | 1.6.0 |
| [BUSBAR-8010](/docs/1.6/errors/BUSBAR-8010/) | rotate_key: new generation committed, but cache reconcile failed (new secret not returned) | 1.6.0 |
| [BUSBAR-8011](/docs/1.6/errors/BUSBAR-8011/) | Budget flush: some buckets failed to persist this tick (re-marked dirty for retry) | 1.6.0 |
| [BUSBAR-8012](/docs/1.6/errors/BUSBAR-8012/) | IGNORE OVERLAY: config overlay not merged (running on base config alone) | 1.6.0 |
| [BUSBAR-8013](/docs/1.6/errors/BUSBAR-8013/) | Provider api_key did not resolve (degraded to an empty key) — RETIRED, see BUSBAR-8020 *(retired)* | 1.6.0 |
| [BUSBAR-8014](/docs/1.6/errors/BUSBAR-8014/) | auth.chain is empty — OPEN RELAY (every request admitted unauthenticated) | 1.6.0 |
| [BUSBAR-8015](/docs/1.6/errors/BUSBAR-8015/) | Store settings hold a secret reference that does not resolve here | 1.6.0 |
| [BUSBAR-8016](/docs/1.6/errors/BUSBAR-8016/) | Governance store is in-memory (ephemeral) — state resets on restart | 1.6.0 |
| [BUSBAR-8017](/docs/1.6/errors/BUSBAR-8017/) | Durable keys are inert (keys exist but `keys` is not in the running auth chain) | 1.6.0 |
| [BUSBAR-8018](/docs/1.6/errors/BUSBAR-8018/) | Group usage read failed (could not derive a bucket's usage from the governance store) | 1.6.0 |
| [BUSBAR-8019](/docs/1.6/errors/BUSBAR-8019/) | Metering accumulator at cap: a cell was coalesced into an overflow sentinel | 1.6.0 |
| [BUSBAR-8020](/docs/1.6/errors/BUSBAR-8020/) | Provider api_key did not resolve (boot refuses) | 1.6.0 |
| [BUSBAR-8021](/docs/1.6/errors/BUSBAR-8021/) | An entitlement check named a scope kind its plane did not declare | 1.6.0 |
| [BUSBAR-8022](/docs/1.6/errors/BUSBAR-8022/) | A unit reported a usage class its plane never declared (the line is refused, not billed) | 1.6.0 |
| [BUSBAR-8023](/docs/1.6/errors/BUSBAR-8023/) | A stored recoverable credential opens under neither at-rest key (it does not authenticate) | 1.6.0 |
| [BUSBAR-8024](/docs/1.6/errors/BUSBAR-8024/) | Recoverable credentials are not yet re-sealed under the current at-rest key | 1.6.0 |
| [BUSBAR-8025](/docs/1.6/errors/BUSBAR-8025/) | A recoverable credential written before 1.6.0 is stored in the clear | 1.6.0 |
| [BUSBAR-8026](/docs/1.6/errors/BUSBAR-8026/) | A plane member's upstream credential could not be refreshed | 1.6.0 |
| [BUSBAR-8027](/docs/1.6/errors/BUSBAR-8027/) | A plane member's upstream credential lapsed or was revoked at its source | 1.6.0 |
| [BUSBAR-8028](/docs/1.6/errors/BUSBAR-8028/) | A plugin's rotated credential could not be applied | 1.6.0 |
| [BUSBAR-8029](/docs/1.6/errors/BUSBAR-8029/) | A plugin instance's scheduled tick failed | 1.6.0 |
| [BUSBAR-8030](/docs/1.6/errors/BUSBAR-8030/) | Governed admission paused (draining, or finished requests await settlement) | 1.6.0 |
| [BUSBAR-8031](/docs/1.6/errors/BUSBAR-8031/) | A unit checkpoint flush batch was refused whole; smaller batches were used | 1.6.0 |
| [BUSBAR-8101](/docs/1.6/errors/BUSBAR-8101/) | The admin resource named in the request does not exist | 1.6.0 |
| [BUSBAR-8102](/docs/1.6/errors/BUSBAR-8102/) | The admin request carries no valid admin credential | 1.6.0 |
| [BUSBAR-8103](/docs/1.6/errors/BUSBAR-8103/) | The admin path does not take this HTTP method | 1.6.0 |
| [BUSBAR-8104](/docs/1.6/errors/BUSBAR-8104/) | The admin credential's scope does not cover this call | 1.6.0 |
| [BUSBAR-8105](/docs/1.6/errors/BUSBAR-8105/) | The admin request is malformed or fails validation | 1.6.0 |
| [BUSBAR-8106](/docs/1.6/errors/BUSBAR-8106/) | The If-Match version is stale | 1.6.0 |
| [BUSBAR-8107](/docs/1.6/errors/BUSBAR-8107/) | The admin request contradicts the server's state | 1.6.0 |
| [BUSBAR-8108](/docs/1.6/errors/BUSBAR-8108/) | The admin mutation rate limit is exhausted | 1.6.0 |
| [BUSBAR-8109](/docs/1.6/errors/BUSBAR-8109/) | The admin call failed inside busbar | 1.6.0 |
| [BUSBAR-8110](/docs/1.6/errors/BUSBAR-8110/) | The admin call could not complete within its bound | 1.6.0 |
| [BUSBAR-8111](/docs/1.6/errors/BUSBAR-8111/) | A usage read names a class the rate card does not price | 1.6.0 |
| [BUSBAR-8112](/docs/1.6/errors/BUSBAR-8112/) | The admin request body exceeds the configured limit | 1.6.0 |
| [BUSBAR-8199](/docs/1.6/errors/BUSBAR-8199/) | The admin request was refused | 1.6.0 |

## 9xxx: Boot & lifecycle

| Code | What it reports | Since |
|---|---|---|
| [BUSBAR-9001](/docs/1.6/errors/BUSBAR-9001/) | Durable audit log could not be read at boot (starting with an empty ring) | 1.6.0 |
| [BUSBAR-9002](/docs/1.6/errors/BUSBAR-9002/) | TLS accept loop failing persistently (backing off) | 1.6.0 |
| [BUSBAR-9003](/docs/1.6/errors/BUSBAR-9003/) | Telemetry slot table full (further label sets fall back to the metrics macros) | 1.6.0 |
| [BUSBAR-9007](/docs/1.6/errors/BUSBAR-9007/) | Boot refused (fatal misconfiguration or startup error; process exits non-zero) | 1.6.0 |
| [BUSBAR-9008](/docs/1.6/errors/BUSBAR-9008/) | Configured worker-thread count is invalid — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-9009](/docs/1.6/errors/BUSBAR-9009/) | Shutdown-signal handler not installed (that signal won't trigger graceful drain) | 1.6.0 |
| [BUSBAR-9010](/docs/1.6/errors/BUSBAR-9010/) | jemalloc idle-purge fallback unavailable (idle RSS may not return to the OS) | 1.6.0 |
| [BUSBAR-9011](/docs/1.6/errors/BUSBAR-9011/) | --generate-signing-key could not mint a key (OS entropy source unavailable) | 1.6.0 |
| [BUSBAR-9012](/docs/1.6/errors/BUSBAR-9012/) | Legacy audit table could not be migrated into the durable journal seam at boot | 1.6.0 |
| [BUSBAR-9013](/docs/1.6/errors/BUSBAR-9013/) | Waiting on another writer's first start of this dataset (no listener bound yet) | 1.6.0 |
| [BUSBAR-9014](/docs/1.6/errors/BUSBAR-9014/) | Took over a stalled first start (the previous owner is retired) | 1.6.0 |
| [BUSBAR-9015](/docs/1.6/errors/BUSBAR-9015/) | First-start takeover not confirmed (outcome unknown or refused) | 1.6.0 |
| [BUSBAR-9016](/docs/1.6/errors/BUSBAR-9016/) | First start step slower than its budget (waiters may take over) | 1.6.0 |
| [BUSBAR-9017](/docs/1.6/errors/BUSBAR-9017/) | First start handed over on exit (writer retired) | 1.6.0 |
| [BUSBAR-9018](/docs/1.6/errors/BUSBAR-9018/) | First start not handed over on exit (the next start waits) | 1.6.0 |
| [BUSBAR-9019](/docs/1.6/errors/BUSBAR-9019/) | Shutdown drain incomplete (the writer was not retired; exit 75 or 70) | 1.6.0 |
| [BUSBAR-9020](/docs/1.6/errors/BUSBAR-9020/) | Completed spend not in durable custody at exit (exit 70) | 1.6.0 |
| [BUSBAR-9021](/docs/1.6/errors/BUSBAR-9021/) | A closed writer's shutdown.drain_incomplete record could not be queued (retried) | 1.6.0 |
| [BUSBAR-9022](/docs/1.6/errors/BUSBAR-9022/) | A writer lease or host assignment row does not decode (never closed) | 1.6.0 |
| [BUSBAR-9023](/docs/1.6/errors/BUSBAR-9023/) | An expired writer was not closed (the next start retries) | 1.6.0 |
| [BUSBAR-9024](/docs/1.6/errors/BUSBAR-9024/) | More expired writers remain than one start closes (the next start continues) | 1.6.0 |
| [BUSBAR-9025](/docs/1.6/errors/BUSBAR-9025/) | Waiting on another owner's record-format conversion of this dataset (no listener bound yet) | 1.6.0 |
| [BUSBAR-9026](/docs/1.6/errors/BUSBAR-9026/) | This node is in restore quarantine: the Store was restored and is not yet declared — RETIRED *(retired)* | 1.6.0 |
| [BUSBAR-9101](/docs/1.6/errors/BUSBAR-9101/) | The command line names an argument busbar does not know | 1.6.0 |
| [BUSBAR-9102](/docs/1.6/errors/BUSBAR-9102/) | A command's arguments do not fit together | 1.6.0 |
| [BUSBAR-9103](/docs/1.6/errors/BUSBAR-9103/) | A command-line flag is missing its value | 1.6.0 |
| [BUSBAR-9201](/docs/1.6/errors/BUSBAR-9201/) | A plane needs a transport protocol that no installed transport provides | 1.6.0 |

This page is generated from the Busbar source; do not edit it by hand.
