# Architecture Decision Records

These records document the load-bearing design decisions the code refers to by
ADR number (e.g. `ADR-0001`, `ADR-0002`, `ADR-0005`). Each one states the
context, the decision, and the consequences that shipped, and cross-references
the modules that implement it.

| ADR | Title | Primary code |
|---|---|---|
| [0001](0001-weighted-selection.md) | Smooth weighted round-robin (SWRR) selection | `crates/busbar-kernel/src/store/mod.rs` |
| [0002](0002-circuit-breaker.md) | Circuit breaker: disposition taxonomy & recovery | `crates/busbar-substrate-values/src/breaker.rs`, `crates/busbar-kernel/src/store/mod.rs`, `crates/busbar-llm/src/engine/attempt/classify.rs` |
| [0005](0005-ir-fidelity.md) | Superset IR & translation fidelity | `crates/busbar-llm-codec/src/ir/mod.rs`, `crates/busbar-kernel/src/proto/` |
| [0010](0010-plugin-licensing.md) | Plugin licensing: plugin self-validates; core resolves SecretRefs & delivers settings | `crates/busbar-kernel/src/config/secret.rs`, `crates/busbar-kernel/src/auth/mod.rs`, `crates/busbar-kernel/src/hooks/mod.rs` |

Other ADR numbers referenced in code but not written up here (the references are
in comments only):

- `ADR-0006`: the `ProtocolReader` / `ProtocolWriter` seam (`crates/busbar-kernel/src/proto/mod.rs`).
- `ADR-0007`: `IrError` kept compatible with `CanonicalSignal` (`crates/busbar-kernel/src/proto/mod.rs`).
- `ADR-0008`: the string-keyed `ProtocolRegistry` (`crates/busbar-kernel/src/proto/mod.rs`, `crates/busbar-kernel/src/config/mod.rs`).
- `ADR-0009`: the durable governance `Store` seam / SqliteStore (`crates/busbar-kernel/src/governance/mod.rs`, `crates/busbar-kernel/src/config/mod.rs`).

See [docs/internals.md](../internals.md) for the design deep-dive these ADRs
underpin, and [docs/architecture.md](../architecture.md) for the public
request-lifecycle overview.
