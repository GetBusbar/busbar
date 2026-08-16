# PoC — the plane crossing cost, measured against real libraries

Backs §0 and §4 of `docs/design/1.6.0-plane-abi-two-layer.md`.

## Why this exists rather than the in-tree test

`crates/api/src/tests/marshal_cost_tests.rs` hand-rolls its zero-copy side with a bare
length-prefixed offset table. That measures the *class* of approach, which was the right thing to do
first, but it flatters the result in two specific ways that change the conclusion:

1. **It never builds the buffer inside the measurement**, so *"the serialize step must vanish too —
   the plugin builds the archived buffer as its NATIVE output"* is asserted rather than tested.
2. **It never VERIFIES.** An unverified zero-copy read of a buffer authored by an untrusted plugin
   hands out typed references derived from attacker-controlled offsets. It is not a crossing you can
   put a trust boundary on, so its cost does not answer the question.

This PoC removes both. It uses flatc-generated code, real rkyv, and a real `dlopen`'d cdylib.

## The result it establishes — and the one it does NOT

**Establishes:** verifying the **whole IR** is LINEAR in payload bytes, so zero-copy alone does not
bound the read. Verifying only the **Layer 1 facts**, with the body riding as an untraversed
`[ubyte]` vector, is FLAT. **The bounded read comes from the layer split, not from the format.**

**Does NOT establish, and an earlier draft of the design doc wrongly said it did:** that the
end-to-end crossing is flat. **Every column here is VERIFY + READ ONLY** — the buffers are built
outside the timing loop, so no allocation, `memcpy`, free or DSO transit is timed. These are half a
crossing.

The other half is the transport, and the frozen contract mandates *plugin allocates → host copies out
→ host calls `busbar_free`*. That copy is O(bytes) **by construction**, indifferent to how little the
host reads; `perf/1.6.0-plugin-abi-measurement` measures it at ~0.03 ns/byte. Flat + linear = linear.

So a flat column here is **necessary and not sufficient** for the latency bar. Getting a flat crossing
also requires borrow-not-copy transport — Part 3.10 of `../../1.6.0-plane-abi-two-layer.md`. That
transport has **not** been built or measured by anyone yet.

## Deliberately outside the workspace

Its own `[workspace]` table keeps it out of the engine build. It is documentation that runs, not a
shipped crate, and it must not put `flatbuffers` or `rkyv` into the engine's dependency graph.

## Running it

Requires `flatc` only if you regenerate; the generated files are committed.

```sh
cd docs/design/poc/plane-crossing
cargo build --release
cargo build --release --manifest-path dso/Cargo.toml
REPS=15 ./target/release/zcpoc dso/target/release/libzcdso.dylib   # .so on Linux
```

**Every number is RELEASE profile.** Debug is ~16x and exists in no shipped build. The harness prints
the load average at start and end, and every cell is `median [min-max]` across `REPS` repeats —
because a point estimate taken on a contended machine is a fiction, and the spread is the honest
column. Regenerate the schemas with:

```sh
flatc --rust --gen-all -o src/ ir.fbs facts.fbs
```
