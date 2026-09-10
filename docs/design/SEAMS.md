# SEAMS — every boundary through which something outside the kernel loop reaches core, or core reaches out

Design inventory. Documentation only; no code changed. Read against
`origin/integration/oracle-phase0` at `588b07261`.

The question this answers: *how are core's inputs and outputs designed — twenty seams, a config
seam, a store seam?* The honest headline is that there is **no single number that is twenty**.
There are **170 public traits outside test code** across `crates/*/src`, of which roughly **65 are
genuine cross-boundary ports**, plus **44 C-ABI function-pointer slots**, **11 process-wide
`install_*` statics**, **83 kernel verbs**, **122 frozen config types**, and **five dynamic plugin
ABIs at five independent version numbers**. The kernel proper is the small part: `busbar-kernel`
defines exactly **five** traits and depends on exactly **three** crates.

What follows is (1) the seam table, (2) a count by kind, (3) a candid assessment — duplicates,
what dies with D33, the target shape, and what must not move before 1.6.0 ships.

Sections of `ARCHITECTURE.md` this doc is written against: §1.1 (three blind axes, LOC ceilings),
§1.2 (core → plugin, never plugin → core), §1.3 (open vocabulary, closed shape), §1.4 (plugin
kinds and the store-ABI window), §3.1 (crate graph, unit traits), §3.2 (plane), §3.4 (transport),
§3.5 (capability types), §4.1–4.3 (journal, chains, durability), §4.5 (pricing), §4.7 (kernel
verbs, config, dual control), §4.8 (policy, boot, clock), §4.9 (audit record).

---

## 1. The seam table

Direction is from the kernel loop's point of view: **out** = the loop calls through it; **in** =
something outside calls into the loop or hands it a value; **both** = a bidirectional handle.

Status vocabulary: **1.6.0 seam** = the shape §3.1 names, survives D33. **legacy port** = dies
with `busbar-core` (D33) or with the pre-waist serving leg. **duplicate** = a second door onto a
seam that already exists.

### 1.1 The kernel's own traits — five, and that is the whole list

| # | Name | Dir | Where defined | Who calls | Who implements | Shape | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| K1 | `Units` (ten steps + `evidence`) | out | `busbar-kernel/src/teller.rs:474` | `teller.rs:712,716,722,733,744,762,794,797,1014,1017,1080,1122` | `busbar::root::kernel::ProductionUnits` `crates/busbar/src/root/kernel.rs:448`; `units_voice.rs:1306`; `units_llm.rs:896` | trait, 12 methods, every one token-sealed | 1.6.0 seam | The §3.1 unit-trait row, collapsed into one object. Entry points `run_unit` `teller.rs:675`, `run_unit_async` `:703`, `exit` `:1108`, `terminal` `:1004`. |
| K2 | `RouteAwait` | out | `busbar-kernel/src/teller.rs:588` | the loop's one `.await`, `teller.rs:1073` | `Blocking<'u,U>` `teller.rs:615`; `units_llm.rs:1281` | trait, 1 method returning a boxed future | 1.6.0 seam | The only async seam in the loop. §2.2. |
| K3 | `ArrivalDoor` | out | `busbar-kernel/src/inflight.rs:332` | free fn `arrival_hold` `inflight.rs:343` | `busbar::root::kernel::AdmissionDoor` `crates/busbar/src/root/kernel.rs:104` → `busbar_unit_admission::arrival_hold` | trait, 1 method, borrows the kernel's `AdmitToken` for one call | 1.6.0 seam | The door. The kernel never mints a `Hold` itself. |
| K4 | `SliceStore` | out | `busbar-kernel/src/slice.rs:143` | **nothing in `busbar-kernel/src`** | `plugin_loader::store_adapter::StoreAdapter` `crates/plugin-loader/src/store_adapter.rs:768`, handed out at `:365` | trait, 3 methods (`reserve`/`release`/`epoch`) | 1.6.0 seam, **not installed** | §4.6 fleet admission. Only consumers today are tests (`store_adapter_tests.rs:660,859`). |
| K5 | `Clock` | in | `busbar-kernel/src/lib.rs:97` | **nothing** | `ManualClock` `lib.rs:120` (test only) | trait, 1 method `now() -> Millis` | 1.6.0 seam, **not installed** | Every kernel API takes `now: Millis` by parameter instead (`inflight.rs:376`). Nothing in the workspace imports `busbar_kernel::Clock`. |

Kernel dependencies (`crates/busbar-kernel/Cargo.toml`): `busbar-caps`, `busbar-contract`,
`busbar-grammar`. Nothing else. `busbar-grammar` is reached from one line,
`busbar-kernel/src/grammar.rs:40`. The manifest header comment still says "`busbar-caps` and the
standard library" — stale — and the file carries a `[workspace]` stanza marked TEMPORARY.

**Named in the brief but not present as kernel traits:**

- **`Durability`** — not a trait. `busbar::root::durability::Durability` is a *struct*,
  `crates/busbar/src/root/durability.rs:117`. The kernel's durability surface is capability-shaped:
  `Kernel::durability_token()` `teller.rs:154` and `DurabilityLost::observed(&DurabilityToken, ..)`
  called at `teller.rs:1165`, type at `busbar-caps/src/hold.rs:779`.
- **The ledger book port** — not a trait. `Book` is a struct, `busbar-unit-ledger/src/totals.rs:211`,
  owned by `Ledger` `settle.rs:67`. The kernel reaches it only through `Units::meter` / `Units::audit`
  plus `Kernel::ledger_token()`.
- **The registry seal** — two different things: `busbar_caps::KernelSeal`, a zero-field struct with
  one constructor `acquire_for_kernel()` `busbar-caps/src/token.rs:69,76` (scanned by the
  `seal-sites` gate), held at `busbar-kernel/src/teller.rs:77`; and `busbar_contract::plugin::KernelSeal`,
  a *trait* `busbar-contract/src/plugin.rs:204` with one method `seal_origin()`, used as
  `&dyn KernelSeal` at `dest.rs:156,379,440` and `unit.rs:591,706,721`. Registry "sealing" itself
  is plain functions: `seal_claims` `registry.rs:319`, `check_claims` `:404`, `bootstrap` `:525`.
- **Host entropy** — **does not exist.** No `trait Entropy | Random | Rand | Nonce` anywhere under
  `crates/`. §1.2 says "a plane reads no random source of its own: … the entropy is supplied through
  `Ctx`". Today entropy is drawn directly by codec crates —
  `busbar-llm-codec/src/openai_chat/handler.rs:308`, `openai_responses/mod.rs:365`,
  `busbar-mcp/src/mcp/callerask.rs:498`. **This is a stated contract with no seam behind it.**

### 1.2 The plugin-visible contract (`busbar-contract`) — 22 traits, the 1.6.0 wall

| # | Name | Dir | Where defined | Who calls | Who implements | Shape | Status |
|---|---|---|---|---|---|---|---|
| C1 | `Plugin` (base) | in | `busbar-contract/src/plugin.rs:142` | registry `busbar-kernel/src/registry.rs:56` | every kind | trait | 1.6.0 seam |
| C2 | `KindMarker` / `KindSeal` | — | `plugin.rs:76` / `:11` | contract-internal | the six kind markers | sealed trait | 1.6.0 seam |
| C3 | `KernelSeal` (proof-of-kernel) | in | `plugin.rs:204` | `dest.rs:156,379,440`, `unit.rs:591,706,721` | `busbar-caps/src/token.rs:112,140` | trait, 1 method | 1.6.0 seam |
| C4 | `PlaneMeta` | in | `plane.rs:22` | registry, claim sealing | each plane crate | assoc-const trait | 1.6.0 seam |
| C5 | `Plane` | out | `plane.rs:197` | kernel loop | plane crates | trait, **16 methods** = 7 codec (`:199,207,217,227,236,246,255`) + 7 fact (`:267,270,273,276,279,282,288`) + 2 introspection (`:299,307`) | 1.6.0 seam |
| C6 | `SessionPlane` | out | `plane.rs:320` | Unit 0 | session planes | trait, 2 methods (`:322,325`) | 1.6.0 seam |
| C7 | `AuthScheme` | out | `kinds.rs:147` | authenticate step | auth plugins | trait | 1.6.0 seam |
| C8 | `Signer` | out | `kinds.rs:177` | egress-auth | secret plugin | trait | 1.6.0 seam |
| C9 | `EgressAuthScheme` | out | `kinds.rs:205` | route step | egress-auth plugins | trait | 1.6.0 seam |
| C10 | `Store` (1.6.0, 22 methods) | out | `kinds.rs:313` | durability / verbs | store adapter | trait | 1.6.0 seam |
| C11 | `Secret` | out | `kinds.rs:471` | boot + `sign`/`seal` | `secret-local` | trait | 1.6.0 seam |
| C12 | `Hook` | out | `kinds.rs:572` | four seats | hook plugins | trait, 8 methods; `Seat` enum `kinds.rs:501`, `HookFacts` `:551`, `HookView` `:528` | 1.6.0 seam |
| C13 | `Export` / `Anchor` | out | `kinds.rs:642` / `:654` | journal export, checkpoint anchor | export plugins | traits | 1.6.0 seam |
| C14 | `Transport` / `TransportMeta` / `TransportConfigView` | both | `transport.rs:89` / `:43` / `:81` | pump | 7 in-tree transports (below) | traits | 1.6.0 seam |
| C15 | `ConfigView` / `SessionView` / `TransportView` | in | `unit.rs:426` / `:442` / `:460` | `Ctx` construction | root | traits | 1.6.0 seam |
| C16 | `Arena` | in | `bounded.rs:295` | `Ctx.arena` | kernel arena | trait | 1.6.0 seam |

Transport implementors (§3.4, §5): `busbar-transport-http/src/lib.rs:402`, `-tls/src/lib.rs:432`,
`-tcp/src/lib.rs:286`, `-ws/src/transport.rs:381`, `-sse/src/lib.rs:129`,
`-stdio/src/transport.rs:241`, `-grpc/src/transport.rs:159`. Seven. **The peer transport §4.6
requires does not exist** (`ls crates | grep -i peer` → empty).

Transport-facing contract crate (§1.1 ceiling ≤ 1k): `ListenerHandle`
`busbar-contract-transport/src/wire.rs:337`, `ConnHandle` `:437`, `RawIo` `:381`.

### 1.3 The substrate plane-host ports — 15 host traits + 28 more, all legacy

Defined in `crates/busbar-substrate/src/plane_host/mod.rs`. **Sole production implementor for all
fifteen is `EngineHostImpl` in `crates/busbar-core/src/plane_host/mod.rs`** — i.e. the entire host
seam is a shim onto the crate D33 deletes.

| # | Name | Dir | Def | Core impl | Methods | Status |
|---|---|---|---|---|---|---|
| S1 | `GauntletPlane` | in | `mod.rs:202` | (planes implement) | — | legacy port |
| S2 | `BreakerHost` | out | `mod.rs:517` | core `:422` | 5 (`:522,533,543,548,554`) | legacy port — duplicate of `busbar-unit-breaker` |
| S3 | `LanePoolHost` | out | `mod.rs:566` | core `:470` | 5 | legacy port |
| S4 | `MeteringHost` | out | `mod.rs:641` | core `:513` | 5: `cost_reserve :648`, `cost_settle :660`, `cost_settled :664`, `cost_close :669`, `price_usage :687` | legacy port — **duplicate of the ledger book** |
| S5 | `ClockHost` | in | `mod.rs:703` | core `:562` | 2 (`clock_now_secs`, `clock_now_ms`) | legacy port — **duplicate clock** |
| S6 | `TelemetryHost` | out | `mod.rs:716` | core `:574` | 7 | legacy port |
| S7 | `JournalHost` | out | `mod.rs:769` | core `:620` | 4: `audit_emit :774`, `audit_record :784`, `call_log_emit :790`, `call_log_emit_hostless :795` | legacy port — **duplicate journal** |
| S8 | `MountHost` | out | `mod.rs:800` | core `:655` | 2 | legacy port |
| S9 | `RegistryHost` | out | `mod.rs:826` | core `:675` | 6 incl. `secret_resolver :851`, `subkey_sign :858` | legacy port |
| S10 | `HookConfigHost` | out | `mod.rs:872` | core `:716` | 12 | legacy port — duplicate of the `Hook` seat contract |
| S11 | `BudgetHost` | out | `mod.rs:957` | core `:773` | 11 incl. `rate_headroom :978`, `cost_price_usage :1056`, `meter_ledger :1071`, `meter_series :1089` | legacy port — **the second cost seam** |
| S12 | `IdentityHost` | out | `mod.rs:1106` | core `:916` | 7 | legacy port |
| S13 | `AdmissionHost` | out | `mod.rs:1170` | core `:1001` | 11 incl. `admission_door :1263`, `finish_admitted :1299` | legacy port — **duplicate of `ArrivalDoor`** |
| S14 | `CompletionHost` | out | `mod.rs:1338` | core `:1183` | 1 | legacy port |
| S15 | `EngineHost` (the sum) | out | `mod.rs:1385` | core `:1202` | sum of S2–S14 + `run_gauntlet :1411`; non-dissolution witness `:1425` | legacy port |

Adjacent substrate seams (28 more `pub trait`s): `LaneRuntime` `store.rs:431` (~50 fns, reached via
`LanePoolHost::lane_store`), `HostlessEgress` `egress/seam.rs:89`, `ArrivalHost`
`ingress/arrival.rs:78`, `TellerPlane` `teller/steps.rs:118`, `Step` `teller/mod.rs:44`,
`PlaneStore` `plane/store.rs:27`, `PlaneCfg` `plane/config.rs:36`, `PlaneEndpointCfg` `:109`,
`PlaneBootCtx` `plane/registry.rs:121`, `PlaneAdminEnvelope` `admin_verbs.rs:244`, `PlaneTrust`
`admin_verbs.rs:64`, `CredentialProvider` `egress_auth/mod.rs:169`, `EgressSubject`
`egress_auth/gate.rs:76`, `Candidate` `failover.rs:157`, `Order` `failover.rs:393`, `Resolver`
`net_guard.rs:544`, `CatalogueItem` `catalogue.rs:113`, `DuplexPlane` `ingress/byte_duplex.rs:99`,
`Words` `ingress/protocol.rs:127`, `PinnedArtifact` `trust/mod.rs:67`, `Declares`
`trust/declared.rs:93`, `GovResolve` `trust/validate.rs:451`, `SettleAdmission`
`plane_host/scope.rs:74`, `EngineTablesView` `plane_host/engine_view.rs:53`, `ResolveNames`
`egress/engine/resolve.rs:32`, plus the testkit kits.

Non-trait plane-host seams: `identity::register/resolve` `plane_host/identity.rs:45,56` and
`trust_anchor::register/resolve` `plane_host/trust_anchor.rs:53,64` — u64 ref-handle registries so
pointers never cross the C ABI. `PlaneBuildInput` `plane_host/build_input.rs:281`, a pure data
carrier (13 nested `*Input` structs).

`DialectCodec` — `busbar-substrate-values/src/proto.rs:696`, **17 methods**, sole implementor
`DialectRef` `busbar-llm-codec/src/proto_codec.rs:921`, held as `&'static dyn DialectCodec` in
`ProtocolDecl.codec` `proto.rs:813`, reached via `ProtocolDecl::dialect()` `:1018`, called from
`busbar-llm/src/engine/wire.rs:550`. Direction out. Legacy port: §3.2's `Plane` codec methods are
its 1.6.0 replacement.

### 1.4 The hot C ABI — 44 vtable slots

| # | Name | Dir | Where | Notes |
|---|---|---|---|---|
| H1 | `PlaneHostVtable` | in (plane → host) | `crates/busbar-plugin/src/hot/host.rs:434` | `#[repr(C)]`, header `abi/size/version` `:436,438,440`; every slot `Option<extern "C-unwind" fn>` (`None` = capability withheld) |
| H2 | the 44 slots | in | `host.rs:443–581` | `govern_admit :443` · `meter_charge :445` · `breaker_admit :447` · `breaker_settle :449` · `verify_lookup :451` · `verify_store :453` · `egress_open :455` · `egress_poll :457` · `egress_write :459` · `egress_close :461` · `journal_append :463` · `journal_read :465` · `nested_dispatch :467` · `workhandle_open :469` · `workhandle_resume :471` · `drift_quarantine :473` · `approval_redeem :475` · `metrics_emit :477` · `clock_now :479` · `auth_resolve :481` · `trust_evaluate :485` · `entitlement_check :487` · `gate_scan :489` · `breaker_admit_reason :493` · `verify_decide :499` · `approval_redeem_q :501` · `govern_admit_reason :507` · `pipe_read :513` · `pipe_write :515` · `egress_fault :521` · `journal_register :528` · `journal_append_scoped :530` · `journal_read_scoped :532` · `journal_restore :534` · `journal_seed :536` · `journal_forget :538` · `journal_compact :540` · `journal_verify_scoped :542` · `subkey_sign :549` · `guard_url :557` · `identity_admit :564` · `gate_decide :571` · `cost_reserve :579` · `cost_settle :581` |
| H3 | `PlaneDecl` (out direction) | out | `hot/decl.rs:132` | 6 slots: `config_validate :163`, `build :165`, `hydrate :167`, `start :169`, `admin_routes :171`, `openapi :173`, `dispatch :175` |
| H4 | ABI preamble/version | — | `busbar-plugin/src/lib.rs:58,67,75,84,95,130` | `ABI_MAGIC` = `BUSPLANE`; `ABI_MAJOR = 1`; `ABI_MINOR = 20`; `check_preamble :130` |
| H5 | vtable builder | — | `crates/busbar-core/src/plane_host/vtable.rs:36` | all 44 slots wired, no stubs; handed out at `busbar-core/src/plane_host/mod.rs:105,122,1689,1750,1827` |

Layout is golden-tested at `crates/busbar-plugin/tests/layout_golden.rs:465`. The tree once carried a
*separate* minimal `PlaneHostVtable` for a `dlopen` PLT benchmark (`plane-abi-spike`); both spike
crates were deleted per `PLUGIN-TREE.md` §7, so this is now the only `PlaneHostVtable` in the tree.

Nine of the 44 slots are journal verbs. That is the single largest duplicate surface in the tree.

### 1.5 The cold plugin ABI — five kinds, five independent versions

| # | Kind | Loader entry | Manifest window | Version const | Consumed as | Status |
|---|---|---|---|---|---|---|
| P1 | `store` | `PluginRegistry::open_store` `crates/plugin-loader/src/registry.rs:182` (kind check `:204`) | `[STORE_ABI_FLOOR=2, cold::ABI_VERSION=4]` — `registry.rs:36,55` | `busbar-plugin/src/cold/mod.rs:162` | `busbar_api::Store` | legacy port, **frozen window** |
| P2 | `auth` | `open_auth :225` (`:247`), `open_login :266` (`:288`) | `[1, AUTH_ABI_VERSION=2]` `registry.rs:66` | `busbar_api::AuthModule` / `LoginModule` | legacy port |
| P3 | `secret` | `open_secret :355` (`:377`) | `[1,1]` `registry.rs:57`; `SECRET_ABI_VERSION` `cold/mod.rs:550` | `busbar_api::SecretModule`; dyn wrapper `plugin-loader/src/lib.rs:1259,1297` | legacy port |
| P4 | `hook` | `open_hook :310` (`:334`) | `[1,1]` `registry.rs:70`; `HOOK_ABI_VERSION` `cold/hook.rs:38` | `busbar_api::RoutingPolicy` | legacy port |
| P5 | `export` | `open_export :391` (`:413`) | `[2,2]` `registry.rs:79`; `EXPORT_ABI_VERSION` `cold/export.rs:36` | telemetry sink | legacy port |
| P6 | transport axis | — | `TRANSPORT_VERSION = 1` `cold/mod.rs:71` | every kind exports the same six kind-neutral C symbols | 1.6.0 seam |
| P7 | **the one generic loader** | out | `wire_up_raw` `crates/plugin-loader/src/lib.rs:406`; the one wire call `RawPlugin::transport_call` `:200` / `transport_call_status` `:215` | resolves `busbar_abi` / `busbar_plugin_kind` / `busbar_open` / `busbar_call` / `busbar_free` / `busbar_close` (`cold/mod.rs:170-180`, optional `busbar_set_log_sink :183`), cross-checks the kind tag against the signed manifest, installs the log sink, assembles `RawPlugin` `lib.rs:176`. **Every kind funnels through this one function**; the five `open_*` entries are typed wrappers above it. | 1.6.0 seam |
| P8 | the plugin-side choke point | in | `crates/plugin-sdk/src/boundary.rs` (`run_boundary`/`open_boundary`/`close_boundary`/`free_boundary`); root macro `export_plugin!` `plugin-sdk/src/lib.rs:977` | one `catch_unwind` + cap check (`MAX_PLUGIN_RESPONSE_LEN` `cold/mod.rs:249`, 256 MiB) + free, on a plugin worker thread (`plugin-loader/src/ffi_thread.rs`) | 1.6.0 seam |
| P9 | manifest / trust / structural validation | — | `busbar_plugin_sign::validate_structure` `crates/plugin-sign/src/lib.rs:539` (ABI range check `:603-622`, invoked `registry.rs:514`); `evaluate` `:660`; `Manifest :97`; `TrustPolicy :241`; `Verdict :272`; `KNOWN_KINDS :64`; `HOST_IDENTITY :73` | shared by `plugin-pack` and `plugin-loader`; `host_identity` is a parameter, not a const | 1.6.0 seam |

Version negotiation has **two independent axes plus two derived feature gates**:

1. *Transport* (linker level): `busbar_abi()` must **equal** `TRANSPORT_VERSION` (1) —
   `plugin-loader/src/lib.rs:447-458`, and again in `validate_plugin` `:1478-1484`. Exact match, no
   range.
2. *Payload* (per kind): `supported_abi(kind) -> &'static [u32]` `registry.rs:45`, a contiguous
   inclusive `[floor, max]`; empty slice = unknown kind, rejected at scan.
3. *Derived gates:* `speaks_new_ops(abi)` vs `STORE_ABI_WITH_NEW_OPS = 5`
   (`plugin-loader/src/store_adapter.rs:100,106`); `needs_legacy_usage_wire(abi)` vs
   `UNIT_MAP_ABI = 4` (`legacy_usage.rs:35,38`); `DynStore.abi_version` `lib.rs:638`.
4. *Airlock preamble* (hot lane only): `check_preamble` `busbar-plugin/src/lib.rs:130` — major must
   match, minor is append-only-compatible.

**There is no `widget` kind** — the brief named six; the tree has five.
**Note a doc/code discrepancy:** §1.4 says the store's "native ABI **5**" while
`cold::ABI_VERSION = 4`; the window `[2,4]` matches the §4.8 text. One of the two numbers in
`ARCHITECTURE.md` §1.4 is wrong.

SDK / packaging seams: `plugin-sdk` `SecretHandle` `crates/plugin-sdk/src/lib.rs:584`, dispatcher
`:598`, `export_secret_plugin!` `:1072`; wire schema `busbar-plugin/src/cold/mod.rs:539-568`.

### 1.6 The 1.5.5 API crate (`busbar-api`) — 7 traits, the retiring plugin wall

| # | Name | Dir | Where | Who calls | Who implements | Status |
|---|---|---|---|---|---|---|
| A1 | `Store` | out | `crates/api/src/store.rs:950` | `governance/state.rs:23,34,2238,2257`, `appbuild.rs:1089`, `calllog.rs:973`, `a2a/taskstore.rs:946,956`, `PlaneStoreView` `busbar-substrate/src/plane/store.rs:62` | `MemoryStore` `crates/store-memory/src/lib.rs:195`, `FileStore` `crates/store-example-plugin/src/lib.rs:522`, `DynStore` `plugin-loader/src/lib.rs:767` | legacy port — **duplicate of `busbar_contract::kinds::Store`**. **Only 5 of ~30 methods are required** (`put_key :973`, `get_key :974`, `list_keys :981`, `delete_key :1005`, `get_usage :1043`, `put_usage :1049`, `add_metering :1074`, `list_metering :1078`); everything else — including all eight neutral plane-record verbs `:1285-1343` — is defaulted-inert. That default-ness is what lets a v2 artifact keep working, and also what makes the trait's real surface unmeasurable. |
| A2 | `AuthModule` | out | `crates/api/src/auth.rs:105` | auth chain | auth plugins | legacy port — duplicate of `busbar_unit_auth::AuthModule` `module.rs:29` and `busbar_contract::AuthScheme` |
| A3 | `LoginModule` | out | `auth.rs:239` | browser exchange | auth plugins | legacy port |
| A4 | `AuthPlugin` | — | `auth.rs:264` | — | — | legacy port |
| A5 | `SecretModule` | out | `crates/api/src/secret.rs:94` | boot resolve | `secret-example-plugin/src/lib.rs:35`, `DynSecret` `plugin-loader/src/lib.rs:1259` | legacy port |
| A6 | `SecretResolve` | out | `secret.rs:201` | planes, TLS | `SecretResolver` `busbar-core/src/config/secret.rs:253` | legacy port |
| A7 | `RoutingPolicy` | out | `crates/api/src/hooks.rs:326` | hook chain | hook plugins, `hooks-ranking` | legacy port — duplicate of `busbar_contract::Hook` |
| A8 | `Redacted<T>` | in | `crates/api/src/redacted.rs:35` | 24 non-test `expose_secret` sites; holders at `busbar-llm/src/engine/tables.rs:47`, `busbar-substrate/src/egress_auth/{bearer_token.rs:41,oauth_client_credentials.rs:23}`, `busbar-mcp/src/mcp/client/egress.rs:61,82,109,111,388,400`, `busbar-core/src/auth/token.rs:73,703` | — | 1.6.0 seam (type, not trait). No `Serialize`/`Deserialize` — fenced by a compile-test `redacted.rs:108` → `crates/api/src/tests/redacted_no_serde.rs`. Zeroizes on drop `:74`; `Debug`/`Display` → `[REDACTED]` `:61,68`; **`PartialEq` is constant-time** `:97`. One door `expose_secret :46`. Gated by `secret-carrier-debug` (`qa/construction.toml:555`). The one plaintext boundary crossing is `crates/busbar-plugin/src/cold/auth.rs:420`. |
| A9 | `Signal` / `SignalBag` | in | `crates/api/src/signal.rs:44` / `:188` | breaker classify | — | 1.6.0 seam (value type). **Not OS signals** — these are upstream failure signals. |
| A10 | `durable::write / write_with / remove / create_dir_all` | out | `crates/api/src/durable.rs:67,160,123,136` | overlay persist, keyset | std::fs | 1.6.0 seam (free fns) |
| A11 | `Operation` / `OpShape` | in | `crates/api/src/operation.rs:192` / `:92` | dispatch | planes | legacy port |
| A12 | `usage_migration::fold_v1_*` | — | `crates/api/src/usage_migration.rs:103,121` | migration | — | legacy port |

`crates/api` is named `busbar-api` and depends only on serde/serde_json/async-trait/sha2/hex/zeroize
plus `busbar-secret-grammar`.

### 1.7 The config seam — one file, four verbs, one frozen grammar

| # | Name | Dir | Where | Notes |
|---|---|---|---|---|
| G1 | boot parse | in | `crates/busbar/src/main.rs:1114` → `load_config_from_disk` `crates/busbar-core/src/appbuild.rs:296` | read `config.yaml` → `interpolate_env_with` → legacy-marker refusal `appbuild.rs:316` → `deploy_from_yaml_str` `config/prepass.rs:403` → `providers.yaml` → `overlay::resolve_backend_with_env` → overlay read. Carrier `LoadedConfig` `appbuild.rs:260`. |
| G2 | document type | in | `DeployCfg` `crates/busbar-core/src/config/mod.rs:1113`; resolved `RootCfg` `:395`; `config::resolve` `:2044` | the 1.5.5-shaped parse; every 1.6.0-additive key lives under one `fleet:` block split off first (PB-40) |
| G3 | `--validate` | — | dispatch `main.rs:182`, handler `main.rs:288` | mirrors boot with `EnvSubst::Lenient`, zero side effects: `load_config_from_disk :293` → `apply_root_to_deploy :316` → `resolve :318` → `merge_into :332` → `validate_with_unset :334` → `preflight_plugins_and_secrets :345` → strict `validate_builtin_secrets_resolve :361` |
| G4 | `--migrate-config` | — | dispatch `main.rs:185`, handler `main.rs:2062`, engine `config/migrate.rs` | 1.4.x → 1.5.0 shape, stdout only, writes nothing; `detect_legacy_markers` also runs fail-closed inside boot at `appbuild.rs:317` |
| G5 | admin apply | in | route `busbar-core/src/admin/v1/json/mod.rs:136`; handler `handlers.rs:2548` (`ApplyConfigReq :2533`) | `If-Match` staleness `:2569`; locked-overlay refusal `:2581`; then `apply_root_to_deploy :2600` → `resolve :2605` → `merge_into :2617` → `build_app_from_config :2619` → commit `:2643` → `txn.rs:290` → `AppHandle::commit_and_swap` `state.rs:998` → `swap` `:938`. Live-only; persist is a no-op closure. |
| G6 | admin reload | in | route `json/mod.rs:133`; handler `handlers.rs:2384`; rebuild `handlers.rs:2332` | disk truth; same four merge steps at `:2343,2354,2357,2364,2377` |
| G7 | the swap | — | `AppHandle` `crates/busbar-core/src/state.rs:872`, `current: ArcSwap<App>` `:873` | readers `load :912`, `snapshot :918`, extractor `CurrentApp :1015`; `swap :938` runs each `PlaneDecl::on_swap` and rebinds the per-generation `EngineHost`; persist-then-swap fail-closed `:998` |
| G8 | overlay merge | in | `config/overlay.rs`: `apply_root_to_deploy :1038`, `apply_plugin_versions_to_deploy :1062`, `apply_named_maps_to_deploy :1087`, `apply_pre_resolve_sections :1179`, `merge_into :1232`; per-section `config/patch.rs:64` + `section_patch!` `:99` | identical order in all four rebuild paths (boot / validate / reload / apply) |
| G9 | `config-schema` | — | `cargo xtask gate config-schema` (`xtask/src/gates/config_schema/`: `schema.rs` the generator and its tracked source set, `classify.rs` the additive rule and the waiver register, `scan.rs` the Rust scrape); snapshot `crates/busbar-core/src/config/config-schema.snapshot.json`; waivers `config-schema.waivers`; CI `.github/workflows/ci.yml` job `config-stability` | five reconciled rows: `:tracked-sources` (the set resolved and every source was read), `:snapshot-drift` (snapshot byte-equals a fresh render; `--write` regenerates), `:baseline` (the ref resolves, carries the snapshot, and that snapshot has types in it), `:additive-only` (against a **git ref, never the working tree**, so a refresh cannot launder a break), `:waivers` (exact paths, reasons, no stale entry). Field removed/retyped/newly-required, enum variant dropped, or a hand-written impl's refusal added *or* removed = RED. Frozen at 1.5.3. |
| G10 | the frozen grammar | — | snapshot | **122 types: 83 structs, 23 enums, 10 manual, 6 aliases.** The brief said 63; the measured number is 83 structs / 122 types. |
| G11 | config source spread | — | `crates/busbar-core/src/config/` (30 structs) + `crates/busbar-substrate/src/config/` (50 structs) + grammar files in `crates/api/src/auth.rs`, `crates/secret-grammar/src/lib.rs`, `busbar-a2a/src/a2a/{config,creds}.rs`, `busbar-mcp/src/mcp/config.rs`, `busbar-core/src/oauth_as/config.rs`, `busbar-core/src/failover/mod.rs`, `busbar-voice/src/config.rs` | one grammar, nine homes |
| G12 | migration corpus | — | `.github/workflows/ci.yml:699`; corpus `tests/migration-corpus/from-tags` | every shipped tag's config must still migrate |

### 1.8 The secret-ref seam

| # | Name | Dir | Where | Notes |
|---|---|---|---|---|
| R1 | `SecretRef { module, settings }` | in | `crates/secret-grammar/src/lib.rs:63`; hand-written `Deserialize` visitor `:131` | rejects every inline scalar spelling **without echoing the value** (`visit_str :161`, `visit_u64 :172`, `visit_i64/f64/bool/bytes :178-201`); map form + `{env:}` / `{file:}` sugar `:204`; schema `oneof_schema :328` |
| R2 | `SecretModule` (the provider seam) | out | `crates/api/src/secret.rs:94` | `resolve(settings) -> Vec<u8>` + `resolve_with_deadline :117` |
| R3 | built-ins | out | `resolve_builtin` `crates/api/src/secret.rs:131`; string form `:213` | `env` and `file` only; anything else fail-closed |
| R4 | `SecretResolver` | out | `crates/busbar-core/src/config/secret.rs:49`; `builtins_only :66`; `with_plugin :72`; `resolve :79`; `impl SecretResolve` `:253` | built-ins inline, else delegate; empty result is a hard error |
| R5 | boot resolution | in | `build_secret_resolver` `crates/busbar-core/src/preflight.rs:737`, called from `appbuild.rs:556` | module settings resolve **once** at boot against `builtins_only` (`preflight.rs:752`, no bootstrap cycle); alias collision hard error `:775-782`; stored `App.secret_resolver` `state.rs:476` |
| R6 | boot consumers | out | provider key `appbuild.rs:608`; auth `:848,857,865`; hooks env `:937`; store settings `:954`; admin token / signing key `:1025,1032`; TLS `main.rs:1412,1574-1621,1694,1871`; voice `main.rs:1338,1352` | |
| R7 | plugin settings resolve | out | `resolve_settings` `busbar-core/src/config/secret.rs:195`; opt-out `SETTING_LITERAL_KEY :37` | configure-push only: boot / apply / reload, never per request |
| R8 | validation-time | — | `preflight_plugins_and_secrets` `preflight.rs:626` (shared by boot, `--validate`, apply); `validate_secret_modules :644`; strict `validate_builtin_secrets_resolve :709` | an unresolvable secret WARNS at boot by design |
| R9 | runtime resolve | out | `EngineHost::secret_resolver()` `busbar-substrate/src/plane_host/mod.rs:851`; used `busbar-a2a/src/a2a/originate.rs:79`, `receive.rs:1888`, `mod.rs:448` | non-hot-path; a config apply swaps the whole `Arc<App>` |

### 1.9 Durability: WAL, journal, shipper, chains

| # | Name | Dir | Where | Notes |
|---|---|---|---|---|
| D1 | `SegmentBackend` / `SegmentFactory` | out | `busbar-unit-wal/src/backend.rs:26` / `:56` | the disk I/O seam |
| D2 | `Wal` | out | `busbar-unit-wal/src/wal.rs:128`; `memory_buffered :170`, `memory_buffered_to :182`, `in_directory :197`, `with_parts :211`; **`append_batch :360`** — the one commit path | `SEGMENT_BYTES = 64 MiB` `segment.rs:27`; `STORE_BACKLOG_RECORDS = 8192` `wal.rs:72` |
| D3 | `Shipper` | out | `busbar-unit-wal/src/ship.rs:37` | one method `ship(&[Record])`. In-crate `NullShipper :64`, `BufferShipper :99`. Only non-test impl is `StoreAdapter` `plugin-loader/src/store_adapter.rs:883`, which **always returns `Ok` and retains nothing** (`:886-899`). Called only from `wal.rs:400,429,438` (→ `offer_store_debt :482`). |
| D4 | peers | — | **do not exist** | No peer registry, no fan-out, no peer transport. Only the node id `(node, node_seq)` at `crates/busbar/src/root/durability.rs:664`. §4.6 branch floats and §4.2 cross-links have no wire. |
| D5 | `Journal` | out | `busbar-unit-wal/src/journal.rs:702`; append `:895`; seal `:936`; replay `:930`; verify `:580` | `JournalRecord :305`, `JOURNAL_HEADER_BYTES = 160` `:89`, magic `BJRN` `:82`, `MEMORY_BUFFER_RECORDS = 8192` `:97`. Chain advances even when the log returns `DurabilityLost` (`:885-889`). |
| D6 | `Record` frame | — | `busbar-unit-wal/src/record.rs:48`; `FRAME_BYTES = 512` `:20` (`MAX_RECORD_BYTES` `lib.rs:103`), header 96 `:23`, magic `BWAL` `:30` | §4.1's fixed-size record |
| D7 | journal appenders | out | all in `crates/busbar/src/root/durability.rs`: `journal_audit :168`, `journal_posting :185`, `journal_checkpoint :206`, `journal_settlement :289`, `write_marker :551` | settlement + overdraft go as **one batch** `:320-327` |
| D8 | `Ledger` / `Book` | out | `busbar-unit-ledger/src/settle.rs:67` / `totals.rs:211` | 14 methods `settle.rs:88–297`; callers `durability.rs:262,283`; plane exit arms `units_mcp.rs:1271`, `units_llm.rs:1360`, `units_a2a.rs:631`, `units_voice.rs:1727`; read side `units_admin.rs:373` |
| D9 | ledger ports | out | `LegacyRows` `legacy.rs:66`, `LegacyMigrationSource` `:152`, `LegacyLedgerRows` `migration.rs:150`, `MigrationRecords` `:185`, `CheckpointSecret` `checkpoint.rs:79`, `CheckpointAnchor` `:112`, `PolicyArchive` `recompute.rs:103`, `WindowState` `verify.rs:91` | eight ports around one struct |
| D10 | legacy audit ring | out | `AuditLog::record_by` `busbar-unit-audit/src/legacy/entry.rs:307`; chain `legacy/chain.rs:189,198,304`; `Clock` `entry.rs:228`; `DurableSeam` `:240` (root binds `NoSeam` `durability.rs:698`) | pipe-separated framing, hex `String`, `MAX_AUDIT_ENTRIES = 1000` `entry.rs:116`, **no persisted head** |
| D11 | record audit chain | out | `Audit` trait `busbar-unit-audit/src/record.rs:265`; `AuditChain::seal :486`; `digest_of :332` (length-prefixed) | plus a fourth chain, `AmendChain::append` `amend.rs:227` |
| D12 | `JournalSink` | out | `busbar-unit-breaker/src/journal.rs:62` | a fifth journal door |
| D13 | `Journal` (egress port) | out | `busbar-unit-egress/src/ports.rs:376` | a sixth |

### 1.10 The legacy money dual-writes

| # | Name | Dir | Where | Notes |
|---|---|---|---|---|
| M1 | `MeteringRow` | out | `crates/api/src/store.rs:802`; `Store::add_metering :1073`, `list_metering :1078` | 11 fields, the 1.5.5 billing row |
| M2 | `flush_metering` | out | `crates/busbar-core/src/governance/state.rs:916` → `add_metering :947` | production callers `crates/busbar/src/main.rs:1539,1639` (the 100 ms tick; interval `busbar-core/src/limits/mod.rs:103`) |
| M3 | `record_metering` (the accrual) | out | `state.rs:866`, write-behind at `:889` | reached from `plane_host/govern.rs:241` and `plane_host/mod.rs:910` (`meter_series`); LLM `busbar-llm/src/engine/usage.rs:38,104`; A2A `receive.rs:1803`; MCP `method.rs:2354` |
| M4 | **dual-write #1** (ledger → legacy postings) | out | **`crates/busbar-unit-ledger/src/settle.rs:184-197`**, the `let _ = rows.write(..)` at `:189` | enabled at `crates/busbar/src/root/durability.rs:688` (`Ledger::dual_writing`). Bound impl is `RecordingRows` `legacy.rs:110` — an **in-memory `Vec`** (`durability.rs:626-635`) that can never fail, so the "count it and alarm" contract at `legacy.rs:22` has no implementation and the `Vec` grows for process life. |
| M5 | **dual-write #2** (money path → `MeteringRow`) | out | `busbar-llm/src/engine/usage.rs:80-112`: `meter_ledger :93` **and** `meter_series :104` | the new settlement for the same unit happens separately at `crates/busbar/src/root/units_llm.rs:1360`. Nothing joins them at write time. |
| M6 | the join | — | `crates/busbar/src/root/ledger_identity.rs`, called from `units_admin.rs:898`; proof `crates/busbar/tests/ledger_identity.rs`, marker `:342` | asserts Σ ledger nanos → micros == `row.spend_micros` and Σ `fee_count` == `row.billable_requests` |
| M7 | dual-write #3 (audit) | out | `crates/busbar-core/src/admin/v1/json/handlers.rs:1838` — "`audit::AUDIT` ring stays as a belt-and-suspenders dual-write (BUSBAR-1002)" | a third dual write nobody has named in the tracker |
| M8 | `MeteringRow` in the plane | out | `busbar-llm/src/unit/meter.rs:271` (`Metered.row`), built at `:467` | the plane step still constructs a 1.5.5 billing row |

### 1.11 Pricing — three implementations

| # | Name | Dir | Where | Notes |
|---|---|---|---|---|
| $1 | `BudgetHost::cost_price_usage` | out | def `busbar-substrate/src/plane_host/mod.rs:1056`; impl `busbar-core/src/plane_host/mod.rs:860` → `price_usage_nanos` `:874` | caller `busbar-llm/src/unit/meter.rs:370` |
| $2 | `MeteringHost::price_usage` | out | def `plane_host/mod.rs:687`; impl `busbar-core/src/plane_host/mod.rs:548` → same fn `:552` | callers `busbar-voice/src/runtime/metering.rs:370`, `runtime/session.rs:221`. Same function, different card (caller handle vs host snapshot). |
| $3 | `CostModel::price_usage_nanos` | — | `crates/busbar-core/src/cost.rs:693` → `rate_for :674` → `RateNanos::reserved_nanos` `cost.rs:181` | prices **only the reserved four** classes; **no tier multiplier, no flat fee**; `Option` = fail-closed on unknown model |
| $4 | `busbar_core::cost::price` | — | `crates/busbar-core/src/cost.rs:208`, documented "THE ONE ENFORCEMENT PRICER" | reserved four + open keys + tier bp — and it is `#[cfg_attr(not(test), allow(dead_code))]`, i.e. **dead outside tests**. The live seam routes around it. |
| $5 | `busbar_unit_cost::price` | — | `crates/busbar-unit-cost/src/posting.rs:129`, re-exported `lib.rs:45` | class-open lines (`rate.rs:196`), explicit fee line (`rate.rs:149`), one tier divide (`apply_tier posting.rs:119`), pinned card version, per-line `unpriced` flags. Callers `crates/busbar/src/root/units_llm.rs:635`, `crates/busbar/tests/ledger_identity.rs:56`. |

**Verdict: `cost_price_usage` and `busbar_unit_cost::price` are not two doors onto one pricer.**
They compute different things. §4.5's tier-and-fee-aware pricer exists twice — once dead
(`cost.rs:208`), once live (`posting.rs:129`) — and the seam the planes actually call is the
narrow, tier-free, fee-free one.

**`rate_apply` does not exist.** A repo-wide grep returns nothing. The nearest real seams are
`BudgetHost::rate_headroom` `plane_host/mod.rs:978` (impl `busbar-core/src/plane_host/mod.rs:808`,
caller `busbar-llm/src/engine/hooks.rs:597`) and `busbar_unit_cost::apply_tier` `posting.rs:119`.

### 1.12 The unit crates' own ports — 37 traits

| Unit | Ports | Where |
|---|---|---|
| admission | `Admission :79`, `Cells :201`, `CellStore :219` | `busbar-unit-admission/src/{lib,cells}.rs` |
| audit | `Audit :265`, `ChainedRecord legacy/chain.rs:146`, `Clock legacy/entry.rs:228`, `DurableSeam :240` | `busbar-unit-audit/src/` |
| auth | `AuthModule module.rs:29`, `KeyVerifier chain.rs:63`, `RevocationView :78`, `CredentialDigest cache.rs:63`, `HeaderView carrier.rs:32`, `HeaderProbe detect.rs:27` | `busbar-unit-auth/src/` |
| breaker | `Breaker lib.rs:147` (sealed `:138`), `Diagnostics classify.rs:102`, `JournalSink journal.rs:62` | `busbar-unit-breaker/src/` |
| egress | `Egress lib.rs:95` (sealed `:81`), and **six ports in one file** — `Breaker ports.rs:168`, `PermitHandle :281`, `Capacity :290`, `EgressAuth :317`, `Journal :376`, `Clock :409`, `Telemetry :427` | `busbar-unit-egress/src/` |
| ledger | eight (see D9) | `busbar-unit-ledger/src/` |
| scope | `PolicyView lib.rs:357` | `busbar-unit-scope/src/` |
| transport-key | `SecretSource :59`, `AccessJournal :90`, `TlsConfigSink :285` | `busbar-unit-transport-key/src/lib.rs` |
| trust | `KindFacts destination.rs:114`, `Resolver net.rs:558`, `PoolView guard.rs:62`, `OrderingHook order.rs:25`, `LaneTable lane.rs:39`, `BreakerView lane.rs:47` | `busbar-unit-trust/src/` |
| usage | (free fns, §3.1's deliberate non-trait) `meter meter.rs:89`, `settle settlement.rs:130` | `busbar-unit-usage/src/` |
| verbs | `Store store.rs:40`, `Governance governance.rs:82`, `GroupLookup mint.rs:24`, `NonceSource verbs.rs:54`, `ReplayEncoder idempotency.rs:28` | `busbar-unit-verbs/src/` |
| wal | `SegmentBackend :26`, `SegmentFactory :56`, `Shipper ship.rs:37` | `busbar-unit-wal/src/` |

### 1.12a Hook seats — four named stages, eight resolution points, ten firing sites

| # | Name | Dir | Where | Notes |
|---|---|---|---|---|
| Y1 | `HookStage` (the seat vocabulary) | — | `crates/busbar-substrate/src/config/hooks.rs:202`; `as_str :215`; `ALL_HOOK_STAGES :237`; `CORE_HOOK_PHASES :266` | `Request`, `Candidate`, `Routing`, `Response` — the four 1.5.5 stages §1.4 maps onto `Before(Approve)` / `After(Admit)` / `Before(Route)` / `After(Route)` |
| Y2 | `HookKind` / `PromptAccess` / `UserAccess` | — | `config/hooks.rs:150` / `:162` (`sends_prompt :169`, `can_rewrite :175`) / `:186` | `Tap` = fire-and-forget, `Gate` = fire-and-wait; `prompt: rw` **is** the rewrite seat |
| Y3 | `ResolvedPolicy`, `FallbackHook`, `RequestedSignals` | — | `busbar-substrate/src/hooks/mod.rs:82`, `:145`, `:49`; `failed_call_refuses :124`; `REQUIRED_HOOK_UNAVAILABLE_STATUS = 503` `:136` | the composed seat state |
| Y4 | seat resolution (8 points) | in | all `crates/busbar-core/src/appbuild.rs`: global rewrite `:1172` (`hooks::resolve_rewrite_hooks` `hooks/mod.rs:1478`); tap@request `:1175`, tap@candidate `:1183`, tap@routing `:1190`, tap@response `:1197` (all `resolve_tap_hooks` `hooks/mod.rs:1530`); global gates `:1206` (`resolve_gate_hooks` `:1580`); per-pool ordering/gates/rewrites `:1213-1230` (`hooks/mod.rs:329,367,407`); per-container `resolve_container_gates :1630` / `resolve_container_rewrites :1667` | |
| Y5 | seat accessors | out | `busbar-core/src/plane_host/mod.rs:732,740,744,748,752,756,760` | `HookConfigHost`'s twelve methods (S10) are the substrate-side mirror |
| Y6 | firing sites (10) | out | global rewrite `busbar-llm/src/engine/pipeline.rs:435,466` → `engine/hooks.rs:414`; tap@request `pipeline.rs:542` → `fire_global_taps :1417`, `.notify() :1504`; tap@candidate `pipeline.rs:1097,1118`; tap@routing `:1233`; tap@response `:212,265` (all → `fire_stage_taps` `busbar-substrate/src/proxy/proxy_vocab.rs:81`); route-unit tap `busbar-llm/src/unit/route.rs:411`; gates `pipeline.rs:680-688` → `engine/hooks.rs:750`, fallback `:864`, mapping `map_decision :931`, `coerce_on_error :993`; content gate `busbar-core/src/hooks/gate.rs:213,266` driven from `plane_host/dispatch.rs:329-353` (`gate_scan`, table `:13`), streaming `:500-510`; tool-arg rewrite `plane_host/mod.rs:1463` applied `:1598` | **Ten firing sites for four seats.** §1.4 says hooks at a gate seat run concurrently against one t0 candidate set; here each plane has its own firing code. |
| Y7 | control-plane seats | out | `configure`/`describe`/`status` `busbar-core/src/hooks/mod.rs:478,490,539`; drift detection `:1365`; scrape `hooks/scrape.rs` | not §1.4 seats — a fifth, out-of-band surface |
| Y8 | hook plugin bridge | out | `registry.open_hook` called at `busbar-core/src/hooks/mod.rs:249,797`; projectors `hooks/plugin.rs:23` | |

### 1.12b Export routes

| # | Name | Dir | Where | Notes |
|---|---|---|---|---|
| E1 | `PluginHttpDispatch` | out | `crates/busbar-core/src/plugin_routes.rs:93` (`handle_http :95`, `handle_http_with_app :103`) | a plugin-facing port declared in `busbar-core`, not in a contract crate |
| E2 | `ExportDispatch` bridge | out | `plugin_routes.rs:119`, impl `:121-123` → `DynExport::handle_http` `plugin-loader/src/export.rs:48` → `ExportRequest::HttpEndpoint` | |
| E3 | route mount pipeline | in | `RouteDecl :135`, `PluginRouteTable :158`, `mounts_for_plane :181`, `declared_auth :210`, `dispatch :223`, `confine :245`, `preflight_route_collisions :294`, `build_route_table :320`, `paths_awaiting_restart :360`, **`mount_plugin_routes :412`**, **`plugin_route_dispatch :439`**, `project_request_headers :490` (`MAX_PLUGIN_HEADERS :58`), `relay_response :532`, reserved paths `:69` | §1.2's PB-31: the kernel mounts the plugin's declared routes verbatim. Routes are collected **once at load** (`DynExport::routes()` `export.rs:41`, queried in `load_export_from_bytes :140`), so adding a route needs a restart while removal is immediate (`export/mod.rs:36-58`). |
| E4 | built-in exporters on the same seam | out | `busbar-core/src/export/mod.rs:59,66`; `export/prometheus.rs:35,43` (`PrometheusExport` serves `GET /metrics`) | |
| E5 | the deliver path | out | `DynExport::deliver` `plugin-loader/src/export.rs:69`; registry `open_export` `plugin-loader/src/registry.rs:391` | **`open_export` has no non-test caller in the engine.** The push half of §4.2's anchor/segment export is defined but unwired; today `deliver` is served by compiled-in exporters (`export/file.rs:81` called from `export/mod.rs:166`, `export/webhook.rs`), gated by `ingress/mod.rs:636-638`. **§4.2's retention rule ("an acked export of the segment") and the `ANCHOR` sink both depend on a seam nothing calls.** |

### 1.13 Verbs, routes, ops, signals, restart

| # | Name | Dir | Where | Notes |
|---|---|---|---|---|
| V1 | the verb registry | in | `crates/busbar-unit-verbs/src/verb.rs`: `KernelVerb :146` (the closed set), `VerbScope :35`, **`LEGACY_VERBS :369`** (66 rows in 1.5.5 openapi order), **`NEW_VERBS :679`** (17), `LEDGER_VERBS :706` (5), `NAMED_SURFACES :716` (8), `IRREDUCIBLE_VERBS :733`, `ADMITTED_UNDER_UNSET :748`, `READ_ONLY_POST_PATHS :86` | conformance test `busbar-unit-verbs/src/tests/table_matches_openapi.rs`; generated table `crates/busbar-plane-admin/src/generated/verb_table_1_5_5.rs`; resolver `busbar-plane-admin/src/verbs.rs:339,353`. Execution `verbs.rs:166,401`; posture gates `posture.rs:80,98,129,146,162`. `AdminDispatch` `units_admin.rs:199` is the one root-side seam. |
| V2 | root admin ports | in | `AdminDispatch :199`, `LedgerView :238`, `LegacyRowsRead :487`, `PostureView :1136` | `crates/busbar/src/root/units_admin.rs` |
| V3 | `/usage` | out | route `busbar-core/src/admin/v1/json/mod.rs:125`; handler `handlers.rs:599`; service `admin/v1/service.rs:2133`; rows from `gov.metering_for(bucket)` `:2174`; aggregation `:2210-2245`; spend `derive_spend_micros_row :2229`; taxonomy `admin/v1/contract/taxonomy.rs:537` | **`/usage` reads the legacy `MeteringRow` table, not the ledger and not the journal.** `busbar-unit-usage` produces a different report entirely, consumed only by the A2A exit arm `units_a2a.rs:1172`. |
| V4 | scrape / unauthenticated ops paths | out | `/healthz`, `/stats`, `/metrics/hooks` listed at `busbar-core/src/plugin_routes.rs:71-73`; `/metrics` special-cased `:273`; `/stats` route `busbar-core/src/router.rs:346`; `/metrics/hooks` `:368`; `HEALTHZ_PATH` `busbar-core/src/auth/mod.rs:36` | PB-43; the confined plugin-route surface of §1.2 (PB-31) |
| V5 | `PluginHttpDispatch` | out | `crates/busbar-core/src/plugin_routes.rs:93` | the `/hooks/{owner}/*` and `/exports/{owner}/*` mount seam the kernel mounts on the plugin's behalf |
| V6 | OS signals | in | `shutdown_signal()` `crates/busbar/src/main.rs:1886`, body `:1892`: `ctrl_c :1893-1899` (fail-soft — a registration error logs and parks forever), SIGTERM `:1904-1917`, Windows `CTRL_CLOSE :1936` / `CTRL_SHUTDOWN :1950` / select `:1957`, other platforms `pending :1965`; select+log `:1971-1975` | **No `SIGHUP` handler exists anywhere in the tree.** Reload is admin-API only. One broadcast channel `main.rs:1481`, bridge `:1487-1492`, one signal drains both listeners `:1480`; final budget flush `:1494-1500`. |
| V6b | restart / drain | in | `RestartReq handlers.rs:2455`, `restart() :2473` (responds `202` **before** the drain `:2517`); guards `supervisor_detected` `busbar-core/src/admin/restart.rs:135`, `can_restart :76`; drain `begin_drain :84`; statics `SHUTDOWN :25`, `DRAIN_AT_EXIT :36`, `DRAIN_ASKED :40`; `send_shutdown :68`; `publish_shutdown :42` called `main.rs:1485` | **Restart = drain + exit, no in-process rebuild** (`handlers.rs:2467-2470`): the durable audit's counters advance only via `fetch_max`, so only a process boundary resets them. Restart-scoped settings `handlers.rs:2463-2465`: `listen`, `admin_listen`, `tls`, `admin_tls`, `admin_require_mtls`, `store`. Breaker latches are RAM-only and re-learned `main.rs:1376-1380`. **`admin/restart.rs` has no destination crate in the D33 plan** (`1.6.0-wave-d-work-order.md:44`), and its three process-global statics are conceded at `main.rs:1483-1484` to be "the honest home" only because `AppHandle` is built before the channel exists. |
| V7 | plugin `Signal`/`SignalBag` | in | `crates/api/src/signal.rs:44,188` | upstream failure signals, unrelated to V6. Same word, two seams. |

### 1.14 The composition root

| # | Name | Where | Notes |
|---|---|---|---|
| X1 | root modules | `crates/busbar/src/root/`: `adapters.rs`, `auth_bindings.rs`, `durability.rs`, `kernel.rs`, `ledger_identity.rs`, `migration.rs`, `mod.rs`, `policy.rs`, `registry.rs`, `transports.rs`, `units_{a2a,admin,llm,mcp,voice}.rs`, `vocabulary.rs` | 16 files; `mod.rs:22` names the durability split |
| X2 | `adapters.rs` — three adapters | `crates/busbar/src/root/adapters.rs` (798 lines) | (1) **breaker → egress**: `BreakerPolicy :67`, `BreakerAdapter :165` (`new :172`, `with_diagnostics :181`, `impl Breaker :239`), enum folds `:200,207,217,227`, `TracingDiagnostics :138`, `root_diagnostics :154`. Installed as a `ProductionUnits` field `root/kernel.rs:180`, constructed `:294-296`, defaults `:389,775,837`. Missing pool ⇒ refuse, never a `Default` (`:27-33`). Reference proof `crates/busbar-unit-egress/tests/breaker_adapter.rs`. (2) **trust → breaker**: `LaneMap :360` (`destination :383`, `lane :389`) — **no production caller**. (3) **label banks**: `check_label_banks() :438`, `LabelDrift :402` — **no production caller either**; only its own test at `:766`. The module doc (`:41-45`) says the check runs "at boot"; boot never runs it. |
| X3 | `auth_bindings.rs` (358) | `KeyFacts :54`, `VirtualKeyDirectory :66`, `DirectoryArm` (`impl KeyVerifier :103`, `impl RevocationView :119`), `AuthBindings :131` (`new`/`without_directory :136`, `credential_cache :196`), `GovernanceDirectory :205` (`impl VirtualKeyDirectory :217`) | installed `root/kernel.rs:54,190,304,410`; used `main.rs:857`, `units_admin.rs:1356,3127,4190`, `units_mcp.rs:380`, `units_voice.rs:708,766,1984,1997`. `GovernanceDirectory` still names `busbar_core::governance::GovState` — legacy reach. |
| X3b | the rest of the root | `kernel.rs:78,90,102,117,168,448,663` · `registry.rs:111,218,241,267,315,373,412,435` (boot seal, called `main.rs:791`) · `transports.rs:68,91,111,124,142,206,282` · `durability.rs:111,117,411,452,475,493,536,589,604,625,648,670,704` · `policy.rs:82,103,120,156,188,238,352` · `ledger_identity.rs:61,104,120,137,155,164,170,214,235,240` · `migration.rs:63,79,108,148` · `vocabulary.rs:53,117` | `vocabulary.rs` is §1.3's leak-once interner. `root/mod.rs:55` still carries `#![allow(dead_code)]` — the root is partly unswitched. |
| X4 | install seams (process-wide statics) — declared → installed | `install_body_ingress` `busbar-substrate/src/ingress/arrival.rs:250` → `main.rs:650`; `install_completion_ingress` `:330` → `main.rs:657`; `install_path_ingress` `:173` → **`busbar-core/src/proto/registry.rs:176`**; `install_stream_translator_factory` `busbar-substrate-values/src/proto.rs:1702` → `main.rs:666`; `install_protocols` `:1501` → **`busbar-core/src/proto/registry.rs:175`**; `install_diagnostics` `diagnostics/mod.rs:194` → `main.rs:745`; `install_ws_arrivals` `ingress/duplex_ws.rs:263` → `main.rs:760`; `install_hostless_egress` `egress/seam.rs:114` → `main.rs:906` (impl `busbar-core/src/egress/seam.rs:347 CoreHostlessEgress`); `install_plane_sections` `plane/config.rs:239` → `main.rs:917`; `install_plane_admin_envelope` `admin_verbs.rs:286` → `main.rs:926`; `install_proxy_tunnel_if_configured` `egress/engine/mod.rs:849` | **eleven**, gated by `no-uninstalled-seam` (`qa/construction.toml:129`, ceiling 0, and it also fails if *zero* seams match — a scanner that stopped seeing anything is a failure, `rules.py:483-485`). **Nine are filled by `main.rs`; two are filled from inside a library** (`proto/registry.rs:175-176`), which is exactly the shape the rule was written for. |
| X5 | legacy reach ratchet | `qa/construction.toml:851-878` | `busbar_core::` ceiling **49**, `busbar_llm::` **17**, `busbar_substrate::` **24** distinct symbols from `crates/busbar/src/root/*.rs` + `main.rs` |

---

## 2. Count by kind

| Kind | Count | Where measured |
|---|---|---|
| Public traits under `crates/*/src`, excluding tests/testkit | **170** | `grep -rn "pub trait" crates/ \| grep -v tests\|testkit` |
| — in `busbar-substrate` | 43 | of which 15 are the plane-host slices |
| — in `busbar-contract` (the plugin wall) | 22 | §3.1's ceiling is 3.5k **surface lines**, not trait count |
| — in `busbar-unit-*` | 37 | across 12 unit crates |
| — in `busbar-kernel` | **5** | the whole kernel |
| — in `busbar-api` (1.5.5 wall) | 7 | |
| — in `busbar-substrate-values` | 9 | incl. `DialectCodec` |
| — in `crates/busbar` (the root itself) | 9 | root-local ports that should be unit-side |
| — in `busbar-core` | 2 | the rest of core is functions and statics |
| C-ABI fn-pointer slots (`PlaneHostVtable`) | **44** | `busbar-plugin/src/hot/host.rs:443-581` |
| C-ABI slots outbound (`PlaneDecl`) | 7 | `hot/decl.rs:163-175` |
| Cold plugin kinds | **5** (not six — no `widget`) | `plugin-loader/src/registry.rs:45` |
| Cold C symbols per plugin, all kinds | **6** (+1 optional) | `cold/mod.rs:170-183` |
| Generic loader functions | **1** (`wire_up_raw`) | `plugin-loader/src/lib.rs:406` |
| Hook seats declared / resolution points / firing sites | **4 / 8 / 10** | §1.12a |
| Ops verbs by table | 66 legacy + 17 new + 5 ledger + 8 named surfaces | `busbar-unit-verbs/src/verb.rs:369,679,706,716` |
| Independent ABI version numbers | **7** | `ABI_MAJOR`, `ABI_MINOR`, `TRANSPORT_VERSION`, store `ABI_VERSION`, `SECRET_ABI_VERSION`, `AUTH_ABI_VERSION`, `HOOK_ABI_VERSION`, `EXPORT_ABI_VERSION` (8 constants, 7 axes) |
| Process-wide `install_*` statics | **11** | `busbar-substrate` + `busbar-substrate-values` |
| Kernel verbs | **83** (66 legacy + 17 new) | §4.7 |
| Config: frozen types / structs | **122 / 83** | `config-schema.snapshot.json` |
| Config: rebuild paths sharing one merge order | 4 | boot, `--validate`, reload, apply |
| Config source homes | 9 crates/files | G11 |
| In-tree transports on the contract | **7** | §1.2 |
| Hash chains live at once | **4** | legacy audit ring, record audit, amend, journal |
| Journal-append doors | **6** | `Journal::append`, `JournalHost` (4 methods), 9 hot-ABI `journal_*` slots, `JournalSink` (breaker), `Journal` (egress port), `DurableSeam` |
| Clock seams | **6** | `busbar_kernel::Clock`, `ClockHost` (2 methods), `busbar_unit_audit::legacy::Clock`, `busbar_unit_egress::ports::Clock`, hot-ABI `clock_now`, `EmissionClock` (`busbar-kernel/src/pump.rs:360`) |
| Store-shaped seams | **6** | `busbar_api::Store`, `busbar_contract::kinds::Store`, `busbar_unit_verbs::Store`, `PlaneStore`, `CellStore`, `SliceStore` |
| Pricing implementations | **3** (one dead) | §1.11 |
| Money dual-writes | **3** | ledger→legacy postings, meter→`MeteringRow`, audit ring |
| Admission doors | **4** | `ArrivalDoor`, `AdmissionHost` (11 methods), `busbar_unit_admission::Admission`, `SettleAdmission` |
| Breaker seams | **4** | `busbar_unit_breaker::Breaker`, `busbar_unit_egress::ports::Breaker`, `BreakerHost`, `BreakerView` |

**Rough split of the 170:** ~65 are genuine cross-boundary ports (kernel 5, contract 22, api 7,
plane-host 15, wal/ledger/audit 13, contract-transport 3). The other ~105 are intra-crate views,
test kits, and the plane-host's satellite traits.

---

## 3. Candid assessment

### 3.1 Duplicates and near-duplicates

**Two clocks became six.** §4.8 says "wall for timestamps; monotonic for timeouts and hold expiry;
both on every entry." The kernel's own `Clock` (`busbar-kernel/src/lib.rs:97`) is *not installed and
never called* — every kernel API takes `now: Millis` as a parameter. Meanwhile `ClockHost`
(`plane_host/mod.rs:703`), `busbar_unit_audit::legacy::Clock` (`entry.rs:228`),
`busbar_unit_egress::ports::Clock` (`ports.rs:409`) and the hot-ABI `clock_now` slot
(`host.rs:479`) each supply time to a different consumer, and `EmissionClock`
(`busbar-kernel/src/pump.rs:360`) is a sixth, unrelated, name. The `unit-no-wall-clock` gate
(`qa/construction.toml:658`) polices units; nothing polices the *number of ways to ask what time it
is*. Respects §4.8.

**Two journals became six doors onto three-and-a-half chains.** §4.1 says "one journal, fixed-size
records." The tree has: `Journal::append` (`journal.rs:895`, the real one), `JournalHost`'s four
methods (`mod.rs:774-795`), **nine** hot-ABI `journal_*` slots (`host.rs:463,465,528-542`),
`JournalSink` (`busbar-unit-breaker/src/journal.rs:62`), `Journal` (`busbar-unit-egress/src/ports.rs:376`),
and `DurableSeam` (`busbar-unit-audit/src/legacy/entry.rs:240`). Underneath are four hash chains
with three framings and two hash types: legacy pipe-separated hex (`legacy/chain.rs:189`),
record length-prefixed hex (`record.rs:332`), amend (`amend.rs:257`), and the journal's raw
SHA-256 over a fixed 160-byte header (`journal.rs:430`). `durability.rs:78-90` argues the audit
split is deliberate — and it is. What is *not* argued anywhere is why a sealed `AuditRecord`'s
`prev_hash` and `hash` are then re-hashed into the journal body (`durability.rs:429-430`), giving
two independent break detectors over one fact with three different failure taxonomies
(`AuditBreakKind record.rs:530`, `ChainBreakKind chain.rs:316`, `JournalBreakKind journal.rs:491`).
Respects §4.1, §4.2, §4.9.

**Two cost seams, three pricers, and the tier-aware one is dead.** `EngineHost::cost_price_usage`
(`plane_host/mod.rs:1056`) and `MeteringHost::price_usage` (`:687`) are two seams onto one function
(`cost.rs:693`) — that pair is genuinely "a new entry point over one function," as the comment at
`busbar-core/src/plane_host/mod.rs:866` claims. The real duplication is across the crate boundary:
`busbar_core::cost::price` (`cost.rs:208`) calls itself "THE ONE ENFORCEMENT PRICER", handles the
open keys and the tier basis points, and is `allow(dead_code)` outside tests, while
`busbar_unit_cost::price` (`posting.rs:129`) does the same job again with a pinned card, a fee line
and per-line `unpriced` flags. The seam the planes actually reach is the narrowest of the three —
reserved four classes only, no tier, no fee. The `one-pricing-site` gate
(`qa/construction.toml:807`) counts *call sites*, not *implementations*, so it is green over three
pricers. Note also that `plane-no-money` (`qa/construction.toml:750`) **deliberately excludes
`cost_price_usage`** — it is handed to `one-pricing-site` so no call is double-counted — so the seam
sits in the gap between two rules that each assume the other has it.
Respects §4.5.

**`MeteringHost` beside the ledger book, and the fee identity is tautological.**
`MeteringHost::{cost_reserve, cost_settle, cost_settled, cost_close}` (`mod.rs:648-669`) is a second
hold-and-settle lifecycle beside `Ledger::{settle, post, record_*}` (`settle.rs:135-297`). The
voice plane uses the first (`busbar-voice/src/runtime/metering.rs:342,377,388,405`); the exit arms
use the second (`units_voice.rs:1727`). They are joined only after the fact by
`ledger_identity.rs`. Worse: `billable_requests` is assigned `counts.requests` verbatim at
`busbar-core/src/governance/state.rs:940`, and PB-99's check
(`crates/busbar/tests/ledger_identity.rs:342-347`) compares against `requests` too — **that half of
the reconciliation identity cannot fail.** Respects §4.2 (the one identity), §4.5.

**The legacy audit chain beside the journal** — see above; deliberate at the ring level, duplicated
at the record level.

**Six store-shaped seams.** `busbar_api::Store` (`crates/api/src/store.rs:950`, the 1.5.5 wall),
`busbar_contract::kinds::Store` (`kinds.rs:313`, §1.4's 22 methods), `busbar_unit_verbs::Store`
(`store.rs:40`), `PlaneStore` (`busbar-substrate/src/plane/store.rs:27`), `CellStore`
(`busbar-unit-admission/src/cells.rs:219`), `SliceStore` (`busbar-kernel/src/slice.rs:143`). Two of
those are the same concept at two ABIs (unavoidable until the window closes); the other four are
four different narrow views that could each be a method on one.

**Four admission doors.** `ArrivalDoor` (`inflight.rs:332`, 1 method), `AdmissionHost`
(`mod.rs:1170`, **11** methods including its own `admission_door :1263` and `admission_check :1286`),
`busbar_unit_admission::Admission` (`lib.rs:79`), `SettleAdmission`
(`plane_host/scope.rs:74`). §2.2 has one door.

**Four breakers, two resolvers, two `AuthModule`s, two `Governance`s.** `Breaker` exists at
`busbar-unit-breaker/src/lib.rs:147` and again at `busbar-unit-egress/src/ports.rs:168` — the
`adapters.rs` breaker adapter exists precisely to bridge them, and its own doc comment
(`adapters.rs:15-16`) argues correctly that a root-held adapter is the *right* answer when two
units name one object at two widths. `Resolver` at `busbar-substrate/src/net_guard.rs:544` and
`busbar-unit-trust/src/net.rs:558`. `AuthModule` at `crates/api/src/auth.rs:105` and
`busbar-unit-auth/src/module.rs:29`. Governance at `busbar-unit-verbs/src/governance.rs:82` and
`BudgetHost::governance() :1010`.

**Ten firing sites for four hook seats.** §1.4 pins the seat set at four and the composition rule at
one concurrent `join_all` per seat. The tree fires hooks from ten places (Y6) across three planes
plus the plane host, each with its own verdict mapping (`engine/hooks.rs:931,993` vs
`plane_host/dispatch.rs:322-323`). One seat, one firing site, one mapping is the whole point of a
closed seat set; today "which mapping ran" depends on which plane you arrived through.

**Seams declared but never installed.** `busbar_kernel::Clock` (K5) and `SliceStore` (K4) have no
production caller or implementor. **`PluginRegistry::open_export`
(`plugin-loader/src/registry.rs:391`) has no non-test caller in the engine** — the entire
`Export::receive` push half of §1.4, on which §4.2's retention rule ("either an acked export of the
segment") and the `ANCHOR` checkpoint sink both depend, is defined and unwired; what runs today is
the compiled-in file/webhook exporters (`export/file.rs:81` ← `export/mod.rs:166`). `LaneMap`
(`adapters.rs:360`) and `check_label_banks()` (`adapters.rs:438`) have no production caller either,
and the second is a boot check whose own module doc says it runs at boot. `Shipper` (D3) has exactly one non-test implementor, which
returns `Ok` unconditionally and keeps nothing, and every production `Durability::build*` call site
passes `NullShipper` (`durability.rs:629`, `main.rs:838`, `kernel.rs:359,765,827`,
`units_mcp.rs:2603`, `units_a2a.rs:1382,2557`, `units_voice.rs:2001,3731`, `units_llm.rs:2177`).
**In the shipped binary nothing is ever shipped anywhere, `data_dir` is `None` in `node_book()`
(`durability.rs:627`), and `DurabilityLost` is therefore unreachable in the shipped composition.**
The `no-uninstalled-seam` gate (`qa/construction.toml:129`) does not see any of these: it scans
only `install_*` / `set_*_factory` functions under the two substrate roots. §4.3's fail-closed
story has no wire behind it today, and PB-15 makes that legal for a migrated config — but the
seam-level fact should be written down rather than inferred.

**Entropy has a rule and no seam.** §1.2's "the entropy is supplied through `Ctx`, never drawn by
the plane itself" has no trait, no `Ctx` field, and three codec crates drawing their own
(`busbar-llm-codec/src/openai_chat/handler.rs:308`, `openai_responses/mod.rs:365`,
`busbar-mcp/src/mcp/callerask.rs:498`).

**Peers have a design and no wire.** §4.6's branch floats and §4.2's cross-linked checkpoints
assume peers. There is no peer registry, no peer transport crate, and no shipper fan-out.

**Two things called `Signal`.** `busbar_api::Signal` (`crates/api/src/signal.rs:44`) is an upstream
failure signal; `shutdown_signal` (`crates/busbar/src/main.rs:1886`) is SIGTERM/SIGINT. Not a
functional duplicate, but a naming collision in a tree whose whole discipline is that a name means
one thing.

### 3.2 What dies with D33, what survives

**Dies** (from `docs/design/1.6.0-wave-d-work-order.md`, DELETE + MOVE + KEEP-UNTIL classes):

- The **entire plane-host seam** — S1–S15, all 15 traits and their 43 satellites in the sense that
  their only production implementor is `busbar-core`. The work order marks `plane_host/` (8,277
  lines) **deleted, not moved**: "once planes speak `busbar-contract`'s `Plane` trait to
  `busbar-kernel`, there is no host to shim" (`1.6.0-composition-root-plan.md:585`,
  quoted at `wave-d-work-order.md:46`). It is the one module in `busbar-core` with `unsafe` — 245
  occurrences.
- The **44-slot hot ABI** goes with it: `build_plane_host_vtable`
  (`busbar-core/src/plane_host/vtable.rs:36`) is the only builder.
- `DialectCodec` (17 methods) — superseded by `Plane`'s 7 codec methods.
- `busbar_api::{Store, AuthModule, LoginModule, AuthPlugin, SecretModule, SecretResolve,
  RoutingPolicy}` — the whole 1.5.5 plugin wall, superseded by `busbar_contract::kinds::*`.
- `MeteringRow` / `flush_metering` / `record_metering` and the `/usage` service path
  (`admin/v1/service.rs:2133`) — the second money path.
- `busbar_core::cost::{price, CostModel}` — both remaining core pricers.
- The legacy `auth/` (4,323 lines), `router.rs` (840), `appbuild.rs` (1,869), `config/` (8,300),
  `config_validate/` (2,638), `governance/` (3,822), `state.rs` (1,040), `metrics.rs` (1,250),
  `tls.rs` (917), `observability.rs` (819), `export/` (1,332), `preflight.rs` (943),
  `plugin_routes.rs` (598), `endpoints.rs` (292), `core_routes.rs` (165), `limits/` (431),
  `session/` (219), `cost.rs` (848), `calllog.rs` (1,064), `telemetry.rs` (895), `failover/` (322),
  `trust/` (118), `audit/` (1,160), `ir/` (197), `store/` (3,584), `hooks/` (2,896),
  `oauth_as/` (2,388), `handlers/` (194), `proxy/` (575), `proto/` (657), `plane/` (3,798),
  `ingress/` (1,307), `egress/` (397), `boot.rs` (135), `diagnostics/` — 74,816 lines mapped.
- The legacy `LEGACY_VERBS` dispatch table shrinks to one seam (`AdminDispatch`) rather than dying.

**Survives:** K1–K5 (the five kernel traits), C1–C16 (the whole `busbar-contract` wall), the seven
transports on `Transport`, `busbar-contract-transport`'s three handles, the `busbar-unit-*` ports
(37 traits, subject to the merges below), the WAL/journal/ledger seams D1–D9, the config seam G1–G12
(relocated to the binary, not deleted — `wave-d-work-order.md:45`), the secret-ref seam R1–R9, the
five cold plugin kinds P1–P6 (the *manifest windows* are a parity obligation and outlive core), and
the composition root X1–X5.

**Named gaps in the D33 plan — seams with no destination:** `admin/restart.rs`
(`wave-d-work-order.md:44`), `metrics.rs` (`:55`), `observability.rs` (`:57`), `export/` (`:59`),
`oauth_as/` (`:101`), `telemetry.rs` (`:86`). Six seams that D33 currently deletes without a home.

### 3.3 The target shape after D33 — one seam, one owner unit

Every proposal below names the ARCHITECTURE sections it must respect and the gate rule that would
prove it.

**T1 — one `HostPorts` struct: clock, entropy, signals.** Fold `busbar_kernel::Clock`, `ClockHost`,
`busbar_unit_audit::legacy::Clock`, `busbar_unit_egress::ports::Clock` and the hot-ABI `clock_now`
into a single `HostPorts { clock: &dyn Clock, entropy: &dyn Entropy, signals: &dyn Signals }`
handed to the composition root once, and reached by units through `Ctx` only. Owner unit:
**`busbar-kernel`** (declares), **the composition root** (installs). Entropy becomes a real seam for
the first time, satisfying §1.2's `Ctx` rule. `EmissionClock` keeps its name — it is a rate shaper,
not a time source, and §1.3's allow-list already blesses "emission clock". Respects §1.2, §3.1
(`Ctx` carries exactly one resource handle plus read-only value sources), §4.8. Proved by:
`unit-no-wall-clock` extended from "no `SystemTime` in a unit" to "no `Clock` trait defined outside
`busbar-kernel`"; `no-uninstalled-seam` extended past `install_*` to *every declared port with zero
production implementors* — which would today go red on K4 and K5 and is the honest ratchet.

**T2 — one config seam with three verbs.** `Config::{boot, validate, apply}` as three verbs on one
object owned by the binary, with `--migrate-config` as a fourth off-node verb (it writes nothing and
belongs beside `busbar operator keygen`). The four rebuild paths already run the identical five-step
merge (G1, G3, G5, G6); making that a single function with three entry verbs removes the class of
bug where one path forgets `merge_into`. Owner unit: **`crates/busbar` (the binary)**, per
`wave-d-work-order.md:45`. The 122 frozen types move with it, unchanged. Respects §4.7 (the
dual-controlled key list, `config-stability-gate`), §4.8 (every boot/reload seals a `Policy`), §1.3
(config schemas are open vocabulary). Proved by: `config-stability-gate --check` staying green
across the move (it reads a git ref, so a relocation that changed a wire key is red by
construction), plus the `migration-corpus` job.

**T3 — one durability seam: journal + WAL + shipper.** `Durability` becomes a trait, not a struct,
with `append(batch) / checkpoint() / verify(since) / ship()` and the four appenders
(`journal_audit`, `journal_posting`, `journal_checkpoint`, `journal_settlement`) as its only doors.
`JournalHost`, the nine hot-ABI `journal_*` slots, `JournalSink` and the egress `Journal` port all
collapse into it. The audit unit keeps *two* chains — the legacy ring for byte-identity and the
record chain for the fixed §4.9 record — and that split stays, because changing the legacy digest
would report every deployment's history as tampered (`durability.rs:82-85`). The `AmendChain`
should fold into the record chain. Owner unit: **`busbar-unit-wal`** (the chain),
**`busbar-unit-audit`** (the two record chains), **`busbar-unit-ledger`** (the book). Respects §4.1,
§4.2, §4.3, §4.9. Proved by: a new `one-journal-door` rule in the shape of `single-terminal`
(`qa/construction.toml:157`) — enumerate the appenders, ceiling at four, list the offenders;
`seal-sites` extended with the journal appenders' token.

**T4 — one store seam.** `busbar_contract::kinds::Store` is the seam; `busbar_api::Store` is its
1.5.5 adapter and dies when the window closes; `busbar_unit_verbs::Store`, `PlaneStore` and
`CellStore` become *views* (`&dyn Store` narrowed at the call site) rather than traits; `SliceStore`
becomes three methods on `Store` (`reserve`/`release`/`epoch` are store operations, and §1.4
already lists `reserve` and `release` among the store's 22). Owner unit: **`busbar-contract`**
declares, **`plugin-loader`** adapts. Respects §1.4 (the 22 methods, "no store method signature is
inferred from prose"), §4.6 (branch floats drawn from the store, fenced by epoch). Proved by:
`ports-only:*` at 0 for every plane (already the ceiling, `qa/construction.toml:112`) plus a new
`one-store-trait` rule counting `trait .*Store` definitions outside `busbar-contract`, ceiling 1
(the api adapter) until the window closes, then 0.

**T5 — one plugin-loader seam per ABI kind, and one version axis.** Keep five `open_*` entry points
(store/auth/secret/hook/export) — a kind's window is a real, separately-versioned contract, and
`supported_abi` (`registry.rs:45`) is the right shape. But collapse the *transport* axis: every kind
already exports the same six kind-neutral C symbols at `TRANSPORT_VERSION` (`cold/mod.rs:71`), so
the five payload versions are the only ones that should be public. Add the missing `widget` kind or
strike it from §1.4. Fix the store-ABI number in §1.4 (it says native 5; the code says 4 with the
window `[2,4]`). Owner unit: **`plugin-loader`**. Respects §1.2 (manifest allow-list, source
denylist, deadlines), §1.4, §4.8's `PluginAbiTooOld` refusal and PB-11's window. Proved by:
`manifest-allowlist` + `source-denylist` (`qa/construction.toml:347,382`), and a new
`abi-window-pinned` rule asserting `supported_abi` matches §1.4's table byte for byte.

**T6 — one cost seam.** Delete `busbar_core::cost::price` (dead) and `CostModel::price_usage_nanos`
(narrow); route `cost_price_usage` and `price_usage` onto `busbar_unit_cost::price`; keep
`rate_headroom` as an admission read, not a pricing call. Owner unit: **`busbar-unit-cost`**.
Respects §4.5, §4.2 (the independent recompute must be able to re-derive `priced_amount` from the
sealed `Policy` — it cannot today if the seam prices without the tier). Proved by: `one-pricing-site`
(`qa/construction.toml:807`) **extended from call sites to implementations** — count
`fn price*` definitions outside `busbar-unit-cost`, ceiling 0; `plane-no-money`
(`qa/construction.toml:750`) already covers the plane side.

**T7 — one admission door.** `ArrivalDoor` is the seam. `AdmissionHost`'s eleven methods split:
`admission_door`/`admission_check` fold into it, `finish_admitted`/`finish_rejected` become
`Units::audit`/`audit_refused`, the gate methods become `Hook` seats, `destination_guard` becomes
`Units::verify`. Owner unit: **`busbar-unit-admission`**. Respects §2.2 (the loop, no exceptions),
§4.6. Proved by: `teller-step-order` and `one-teller-loop` (`qa/construction.toml:207,220`),
`hold-discipline` (`:471`), `token-sealed` (`:180`).

**T8 — one metering path.** Retire `MeteringHost`'s four cost-lifecycle methods onto `Ledger`;
`/usage` reads the ledger book, not `MeteringRow`. This is G3 in the tracker and cannot land before
the dual write retires. Owner unit: **`busbar-unit-ledger`** (postings) + **`busbar-unit-usage`**
(the report). Respects §4.2's identity, §4.5, PB-16, PB-99. Proved by: `ledger_identity` with a
**non-tautological** fee check — today `billable_requests` and `requests` are the same figure at
both ends (`governance/state.rs:940`, `tests/ledger_identity.rs:342-347`).

**T9 — root-local ports move home.** The nine `pub trait`s in `crates/busbar/src/root/`
(`ProviderDial`, `SessionPump`, `SessionLease`, `Carrier` in `units_voice.rs:277,304,316,342`;
`AdminDispatch`, `LedgerView`, `LegacyRowsRead`, `PostureView` in `units_admin.rs:199,238,487,1136`;
`VirtualKeyDirectory` in `auth_bindings.rs:66`) are ports declared at the composition root, which is
the one place §3.1 does not list as a home for a port. `adapters.rs`'s three adapters are the
legitimate exception and their doc comment (`adapters.rs:7-23`) argues it correctly; these nine are
not that. Respects §3.1, §1.1's LOC ceilings. Proved by: `legacy-reach` (`qa/construction.toml:851`)
extended with a `root-declared-ports` ratchet, ceiling 9 and falling.

**Target seam count.** After T1–T9: **five kernel traits + 22 contract traits + one config seam +
one durability seam + one store seam + five plugin-kind loaders + seven transports + ~24 unit ports
+ 11 install seams**. Call it **≈45 named ports** against today's 170 traits and 44 vtable slots.
Not twenty — but one owner unit each, and every one of them installed.

### 3.4 What NOT to change before 1.6.0 ships

1. **Money-path byte identity.** Do not touch `busbar-unit-audit/src/legacy/` — its digest framing
   (`chain.rs:67-123`, pipe-separated, hex) is what makes every deployment's existing history verify.
   `durability.rs:82-85` states this. Do not change `MeteringRow`'s field set
   (`crates/api/src/store.rs:802`) or `metering_row`'s construction
   (`busbar-llm/src/unit/meter.rs:467`). Do not remove the dual write at
   `busbar-unit-ledger/src/settle.rs:184-197` — §4.8 requires it "for one release" and rollback
   depends on it (`durability.rs:686`). *Do* fix the swallowed error at `settle.rs:189` and the
   unbounded `Vec` in `RecordingRows` — those are bugs inside a frozen shape, not shape changes.
2. **The 83 config structs / 122 frozen types.** `config-schema.snapshot.json` is frozen at 1.5.3
   and additive-only against a git ref. Do not consolidate `crates/busbar-core/src/config/` and
   `crates/busbar-substrate/src/config/` before the gate can prove the render is byte-identical.
   A relocation is fine; a field rename, retype or newly-required field is exit 3.
3. **The store ABI window `[2,4]`.** `STORE_ABI_FLOOR = 2` (`plugin-loader/src/registry.rs:36`) must
   stay 2 — raising it refuses every published store plugin at load (`registry.rs:50-54`), and PB-11
   pins the window. The same holds for `auth`'s floor of 1 (`registry.rs:66`). Do not renumber
   `ABI_MINOR` (`busbar-plugin/src/lib.rs:75`) while the vtable is in flux — the `version` field is
   the plane's only compatibility check (`hot/host.rs:440`).
4. **`/usage` rows.** The wire shape, key set and vocabulary are pinned by PB-16 and the G4
   reconciliation test. `/usage` reads `MeteringRow` today (`admin/v1/service.rs:2174`); switching it
   to the ledger is G3+C13 work, not a cleanup. Do not touch `derive_spend_micros_row`
   (`service.rs:2229`) or the field renames at `service.rs:2223-2225`.
5. Also do not touch, though the brief did not name them: the 66 legacy admin operations pinned by
   git object hash (§4.7); the `Redacted` non-`Serialize` property (`crates/api/src/redacted.rs`),
   which the `secret-carrier-debug` gate enforces; and the `SecretRef` visitor's
   never-echo-the-value property (`secret-grammar/src/lib.rs:161-201`).

---

## 4. What I did not read

Stated plainly, so no row above is trusted further than it was checked.

- I did not read `crates/busbar-core/src/plane_host/mod.rs` end to end (1,800+ lines); the
  implementor line numbers for S2–S15 come from a targeted scan, not a full read.
- I did not read `crates/busbar/src/main.rs` end to end (2,000+ lines). The config, signal and
  shipper call sites are grep-verified; the boot ordering between them is not.
- I did not read the 22 `busbar-contract` traits' method bodies or their compile-fail fixtures; the
  method *counts* for `Plane` (16) and `Hook` (8) are read from source, the rest are declaration
  lines only.
- I did not verify that each of the 44 vtable slots is reachable from a plane; I verified the
  builder wires all 44 (`vtable.rs:36`) and the golden layout test exists.
- I did not read `plugin-loader`'s trust/signature pipeline, `plugin-pack` or `plugin-sign` beyond
  their entry points and `validate_structure`'s range check.
- I did not read the ops/scrape handlers' bodies; the route declarations, the signal handling and
  the restart semantics are read from `router.rs:330-400`, `main.rs:1886-1975` and
  `handlers.rs:2455-2520`.
- The hook firing-site list (Y6) is grep-derived from call sites; I did not trace each one to
  confirm it reaches a distinct seat rather than the same seat twice.
- I did not read `hooks-ranking`, `busbar-plane-*` crates, `busbar-caps`'s lint fixtures, or any
  transport crate past its `impl Transport` line.
- The "170 public traits" figure excludes paths containing `tests`, `_tests` or `testkit`; it
  includes some private-in-practice traits behind `pub(crate)` re-exports and will be a few high.
- Two items the brief named do not exist and I could not find under any spelling: **`rate_apply`**
  and the **`widget`** plugin kind. Two more exist only as prose with no code: the **host entropy
  port** and **peers**. `Durability`, the **ledger book port** and the **registry seal** exist, but
  as a struct, a struct, and two unrelated things called `KernelSeal`.
