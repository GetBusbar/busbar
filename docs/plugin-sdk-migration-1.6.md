# Rebuilding a plugin against the 1.6.0 SDK

Plugins must be rebuilt against the SDK revision used by the host. Busbar 1.6.0 uses one
validated memory ABI for linked and dynamically loaded plugins. An incompatible mechanism or
kind version is refused before the plugin opens. Product version 1.6.0 does not mean that every
unreleased development SDK revision is binary compatible.

The current mechanism is **3**. Rebuild every linked or dropped plugin against the
current immutable SDK pin. A mechanism-2 bundle is rejected before loading its library
or calling OPEN; it cannot obtain the new host authority through a compatibility alias.
This change does not change the seven kind wire layouts or customer persistence formats.

Operators keep the normal startup migration path. Rebuilding a plugin is an author task; it
does not introduce a separate operator migration tool. See [migration](migration-1.6.md).

## One entry, seven kinds

The boundary is:

```text
plugin ↔ typed kind SDK ↔ validated ABI ↔ core ↔ validated ABI ↔ typed kind SDK ↔ plugin
```

A plugin depends on `busbar-contract` and external libraries. It cannot depend on another
plugin implementation, the loader, kernel, migrations or a core adapter in its shipping graph.
The same repository may contain an implementation rlib and a thin cdylib wrapper. The wrapper
exports the implementation's `door` through `busbar_contract::export_door!`; it does not expose
implementation types or constructors. A combined rlib/cdylib follows the same boundary.

`busbar_contract::plugin_door!` generates the kind table, lifecycle, `door` and `MACRO_DOOR`.
The exported native symbol is `busbar_plugin_door`. Registration supplies that entry and its
metadata; it never obtains an implementation object. Both loading modes validate the signed
Statement, kind, layouts and operations before adopting the instance.

Build with `panic = "unwind"`. The SDK trampolines contain panics and report faults.

## Start from the canonical scaffold

Use the shared fleet generator's `plugin new <kind> <name>`.
Add `--enterprise` for private BusbarInc source. The command creates a local repository; its
package identities must enter the trusted admission policy before publication through GitLab.
Public mirrors follow qualified canonical dev publication. Private repositories and artifacts
never enter a public mirror.

The generated implementation initially refuses configuration and operations. Implement the
kind's behavior before offering it to users. The skeleton has a working build, a narrow entry,
and linked/dropped loading, wrong-kind and refusal checks. There is no second enterprise generator.

| Kind | SDK ownership | Plugin responsibility |
|---|---|---|
| Store | `abi::sdk::store::v4`, `Backend` | Translate prepared reads, scans, atomic commits, clocks and native bootstrap operations into backend operations. |
| Secret | `abi::sdk::life`, `abi::sdk::secret`, guarded credential helpers | Resolve a reference and return a protected value through the secret ABI. |
| Auth | `abi::sdk::auth_door` | Verify identities, conduct declared login exchanges or prepare outbound authorization. Core owns grants and policy. |
| Hook | `abi::sdk::hook`, `Hook`, `HookOpen` | Decide, transform or observe the permitted projection. Configuration uses the SDK checkpoint contract. |
| Export | `abi::sdk::export` | Deliver or render the observations core provides. |
| Plane | `abi::sdk::plane_life`, `PlaneLife` | Interpret its protocol and publish bounded declarations and answers. |
| Transport | `abi::sdk::life`, typed transport slots | Frame or carry bytes using the host's granted I/O facilities. |

The kind's `Ops` and its `ABI_VERSION` live under `abi::<kind>`; the current store wire is
`abi::store::v4`. Use SDK constants and generated headers rather than copying numeric versions.

## Kind-bound access

`Life` declares its associated `Kind`. `Instance`, host services, connector access and lifecycle
loans retain that kind in their types. `SafeSlot` must match the table's kind and exact input/output
layout. A Secret instance cannot become a Plane service client, even through an alias or generic
helper. There is no unrestricted safe host-services conversion.

The host issues caller identity. Plugins cannot construct its namespace/incarnation authority or
mint a kernel seal. Runtime callbacks check the actual bound kind, lifecycle phase and instance
before entering the provider. Compile-time access does not replace runtime checking: C and raw ABI
callers meet the same host checks. Revoked or stale handles do not regain authority on reopen.

Keep internal modules and runtime constructors private. Tests needing internal algorithms belong
inside the implementation crate under `cfg(test)`. External tests exercise the actual door through
the loader. A `compiled_in::door` alias is permitted only when it exposes that same entry.

## Preserve custody and domain ownership

Secret-bearing buffers must use the existing guarded credential SDK. Return opaque held values
and release readable material as soon as the operation permits. Do not duplicate readable token
storage or turn secrets into ordinary request headers when the host's credential mechanism applies.

A store implements native persistence primitives, not accounting, credential revocation or plane
rules. Core prepares operations and owns replay, arithmetic and domain relationships. Plugins do
not know which other plugin consumes their output. Automatic migration coordination belongs to
core's migration path; a store supplies its native inspection and bootstrap adapter.

## Build and qualification

Pin all first-party SDK dependencies to one immutable revision. Keep `.busbar-ref`, manifests,
lockfiles, assembly pins and generated C headers coherent. Do not use sibling checkout overrides
in committed plugin manifests. Test-only SDK features (`test-seal`, `test-support`) are permitted
only in approved test graphs and must not enter the shipping dependency closure.

Locally run formatting, clippy/build and the targeted regressions for the change. Full suites and
native assembled-product qualification run in CI. Build the real cdylib before a dropped-loading
test and supply `BUSBAR_PLUGIN_CDYLIB`; a missing library is a failure, not a skipped success.

Trusted admission checks resolved Cargo identities, normal/build and inactive declarations,
shipping features, source pins, public surfaces and forbidden-use fixtures. The candidate cannot
approve its own broader policy or replace the trusted checker. The exact candidate revision must
pass required checks against the current target before protected admission.

These boundaries prevent accidental architectural coupling in maintained Rust code and enforce
runtime authority at the ABI. Native plugins remain trusted native code; this is not a sandbox for
intentionally hostile machine code.
