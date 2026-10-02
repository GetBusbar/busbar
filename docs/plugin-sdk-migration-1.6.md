# Rebuilding a 1.5.5 plugin against the 1.6.0 SDK

1.6.0 does not load a plugin built for 1.5.5. Every first-party plugin was rewritten, and a third-party
plugin is rebuilt against the 1.6.0 SDK. Your source keeps its logic: the traits you implemented
(`RecordStore`, `HookHandler`, `ExportHandler`) and the plugin settings you parse are still yours. What
changes is the door your crate exports, the version the host checks, and the manifest the packer signs.

This page is for plugin authors. Operators have nothing to migrate unless they run a third-party plugin
(see [Plugins](plugins.md) and [Migrating from 1.5.x](migration-1.6.md)).

## What changed, in one paragraph

A 1.5.5 plugin exported six C symbols (`busbar_abi`, `busbar_plugin_kind`, `busbar_open`,
`busbar_call`, `busbar_free`, `busbar_close`) and spoke JSON through `busbar_call`. A 1.6.0 plugin
exports ONE symbol, `busbar_plugin_door`, which answers a table of typed slots. Every kind uses the same
door, the same call shape and the same lifecycle; a kind adds only its own operations. The door carries
a Statement: the plugin's name, its kind, its kind's ABI version and the facts the host reads without
running the plugin. The host compares that Statement with the one signed into the manifest, byte for
byte, before it calls any slot.

All of it lives in the `busbar-contract` crate, under `busbar_contract::abi`: the shared mechanism in
`abi::mechanism`, one module per kind (`abi::store`, `abi::secret`, `abi::auth`, `abi::hook`,
`abi::export`, `abi::plane`, `abi::transport`), and the plugin side in `abi::sdk`.

## The build: one door, compiled in or dropped in

A plugin is two crate roles, in one package if you like (`crate-type = ["rlib", "cdylib"]`):

1. The logic crate invokes `busbar_contract::plugin_door!` once (or a kind's wrapper over it, below). It
   expands to `pub extern "C" fn door()`, which answers the `'static` door. It exports no symbol, so
   several plugins can be linked into one binary.
2. The `cdylib` invokes `busbar_contract::export_door!(path::to::door)` once. It emits the one exported
   symbol, `busbar_plugin_door`. Gate it behind a cargo feature (the first-party crates call it
   `dropped-in`) so a build that links your crate does not also export the symbol.

A host that links your crate registers the same `door` function as a compiled-in row
(`LinkedRow::of(door)`); a host that loads your tarball calls the exported symbol. Both reach the same
table through the same checks. There is no separate "built-in" shape to maintain.

Build with `panic = "unwind"`: both macros refuse to compile under `panic = "abort"`, because every slot
is a `catch_unwind` trampoline that answers FAULT when a panic unwinds. A slot is `extern "C"`, never
`extern "C-unwind"`; a panic that escaped would abort, and the trampoline stops that.

## Per kind

The "1.5.5 entry" column is what your crate called; the "1.6.0 door" column replaces it.

| kind | 1.5.5 entry | 1.6.0 door | kind ABI version |
|---|---|---|---|
| store | `export_store_plugin!(open)`, `RecordStore` | `store_door!(MyStore, "name", "version", max_inflight)`, `StoreSlots: RecordStore` | `abi::store::ABI_VERSION` (3) |
| secret | `export_secret_plugin!` | `plugin_door!` over `abi::secret::Ops`, `lifecycle: life(L)` | `abi::secret::ABI_VERSION` (2) |
| auth | `export_auth_plugin!`, `export_login_plugin!` | `auth_verify_door!(MyPlugin, STATEMENT)`, `VerifyPlugin` | `abi::auth::ABI_VERSION` (3) |
| hook | `export_hook_plugin!`, `HookHandler` | `plugin_door!` over `abi::hook::Ops` | `abi::hook::ABI_VERSION` (2) |
| export | `export_export_plugin!`, `ExportHandler` | `plugin_door!` over `abi::export::Ops` | `abi::export::ABI_VERSION` (3) |
| plane | none: planes were compiled in | `plugin_door!` over `abi::plane::Ops` | `abi::plane::ABI_VERSION` (1) |
| transport | none: transports were compiled in | `plugin_door!` over `abi::transport::Ops` | `abi::transport::ABI_VERSION` (1) |

The mechanism has its own version, `abi::mechanism::MECHANISM_VERSION` (2), stamped in every door. The
host accepts exactly one version of each: older and newer are both refused. `KindCode::abi_version()`
answers the number for a kind, and `plugin_door!` stamps it, so you never write a version by hand.

### store

Implement `StoreSlots` (`abi::sdk::store`) for your type. It extends `RecordStore`, so the 1.5.5 methods
keep their meaning; the additions are `open(settings)`, the `op_id`-carrying writes (a repeated `op_id`
with the same fields answers what the first call answered, durably for a durable store), the ledger and
money operations, and `window_caps`. Declare what the store keeps in `TAIL` (`Tail`: ephemeral, durable
plane records, fork refusal). Then `store_door!(MyStore, "my-store", "1.0.0", 64)`; the fourth argument
bounds in-flight calls. The in-tree `store-memory` crate is the worked example.

### secret

Implement `Life` (`abi::sdk::life`) for the instance state: `open(settings, secrets, generation)`, and
override `validate` to keep your own refusal text. Write one `resolve` slot, then
`plugin_door!` with `ops: busbar_contract::abi::secret::Ops`, `lifecycle: life(YourType)` and
`kind_ops: { resolve: ... }`. The doc example on `abi::sdk::life` is a complete secret plugin.

### auth

Implement `VerifyPlugin` (`abi::sdk::auth_door`): `open(settings, secrets)` and `verify(request)`
answering `Verdict::Identity`, `Reject` or `Pass`. The inbound verdict cache lives inside your plugin;
`refresh` drops it. Build the Statement with `abi::sdk::door::statement(name, version, max_inflight)`,
add the tail with `with_tail(.., &TAIL)` where `TAIL = verify_tail(facts)`, and name each header you read
with `carrier("x-name")` in `mark_words`. Then `auth_verify_door!(MyPlugin, STATEMENT)`. A verify door
refuses the login and outbound operations; a plugin that serves them writes its own `plugin_door!` over
`abi::auth::Ops`.

### hook, export, plane, transport

These four have no wrapper macro on top of `plugin_door!`. You write `plugin_door!` with the kind's `Ops`
table: the nine lifecycle slots (`lifecycle: life(L)` where the kind does not widen them; the plane kind states its own), and `kind_ops` naming the kind's slots by field
name. A slot wired to another operation's `in`/`out` structs does not compile.

- hook: `decide`, `transform`, `notify`, `configure`, `status`, `describe` (`abi::hook::Ops`). 
- export: `deliver`, `scrape`, `status`, `check`, `serve` (`abi::export::Ops`). A scrape's families are
  the whole snapshot, in the order the host's recorder gives them.
- plane: `arrive`, `on_piece`, `refusal`, `serve`, `hydrate`, `start`, `project` (`abi::plane::Ops`).
- transport: `listen`, `accept`, `dial`, `read`, `write`, `flush`, `shut`, `arrival`, `locate`, `begin`,
  `ingest` (`abi::transport::Ops`). The `busbar-transport-tcp` crate is the worked example. A carrier or
  framer written against the transport traits can instead be lowered with `export_carrier!` or
  `export_framer!`.

## What the host checks, and what you see when it fails

The host checks before it calls anything, and refuses at boot, naming the plugin. A refusal reads
`plugin '<name>' (<instance>): <reason>`; a dropped-in transport reads
`transport plugin '<name>' refused at its door: <reason>`. `busbar --validate` runs the manifest checks
without opening the library.

From the signed manifest, before `dlopen`:

- `the manifest states mechanism version {stated}; this host speaks {host} — rebuild the plugin against the 1.6.0 SDK`
- `the manifest states kind ABI {stated}; this host speaks {host} — rebuild the plugin against the 1.6.0 SDK`
- `the manifest states kind {stated:?}, not {want:?}`

From the door, after `dlopen`:

- `the library exports no busbar_plugin_door: {error}`: a 1.5.5 library, which exports the six old
  symbols and no door.
- `the door's magic {value} is not BUSBARPL`
- `the door's mechanism version {door} is not this host's {host} — rebuild the plugin against the 1.6.0 SDK`
- `the door's {kind:?} ABI version {door} is not this host's {host} — rebuild the plugin against the 1.6.0 SDK`
- `the plugin's Statement is not the one its manifest states — repack the plugin`: the door and the
  signed manifest disagree, or the manifest states no Statement at all.
- structural refusals: a door, table or Statement smaller than the host's, a NULL slot (there is no
  "unsupported" answer; every slot is filled), a kind other than the one asked for.

A manifest that states a newer version than the host speaks is refused the same way: the host accepts
only the current version of each kind.

## Packaging and signing

Unchanged in shape: one tarball holding the cdylib and a signed `manifest.json`, packed with
`busbar-plugin-pack pack`, signed with the same ed25519 key (`BUSBAR_SIGN_KEY`), trusted through the same
`plugins.trust` policy. Keys you already allowlist keep working.

One step is new and automatic. `pack` opens your library on the packing machine, reads its door, renders
the Statement and signs it into the manifest as the `statement` field. The host reads the facts it needs
(kind, name, aliases, claimed schemes, connection needs) from that rendering, so `--validate` never runs your code. Two consequences:

- Pack on a machine that can load the library (its own target). If it cannot, `pack` warns that the
  manifest states no Statement, and the host will refuse the plugin at admit.
- Rebuild, then repack. A new build changes the Statement; an old tarball's manifest no longer matches.

Leave `--abi-version` unset. The packer stamps the current version for the kind, and the version the
host enforces is the one in the Statement.

## Checklist

1. Depend on `busbar-contract` at the 1.6.0 release; drop the 1.5.5 plugin-SDK and plugin-ABI crates.
2. Replace the six-symbol export macro with the table above.
3. Set `panic = "unwind"` and add `rlib` beside `cdylib` if you want a linked build too.
4. Rebuild, then `busbar-plugin-pack pack` on the target.
5. `busbar --validate` with the plugin selected: a stale or mismatched plugin is refused there, by name,
   before the library is opened.
