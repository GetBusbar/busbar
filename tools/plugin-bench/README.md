# busbar-plugin-bench

Load ONE plugin and hammer it, with no gateway in the way. Report only: it never passes or fails a
build.

## What it measures

The plugin is reached the way core reaches it. A dropped-in cdylib goes through the loader's door
discovery (`busbar_plugin_door`, `rendering_of_library` + `load_dropped`). A compiled-in door goes
through `LinkedRow` + `load_linked`. The loader validates and binds both.

The instance is opened with the loader's own lifecycle. A store opens through `LoadedPersistence`
and has its dataset bootstrapped; a plane is opened, readied, hydrated and started. After that,
every measured op is ONE inline crossing (`Plugin::answer`) over frames and lent buffers that the
bench allocates once and reuses. The host-mediated crossing costs about 0.2 µs; `store.clock` shows
that floor.

The measured path has no dispatcher hop, sealing, journal, HTTP or router. The bench's host
services are a fake clock and a fast `random.fill`. Every other service answers "unimplemented"
immediately (`src/host.rs`). Envelope metrics and diagnostics are counted, never formatted.

For each op it reports:

| column | meaning |
|---|---|
| p50 / p99 / mean | wall ns per crossing, from a log-linear histogram (about 3% resolution, no per-call allocation) |
| minbatch | lowest mean over a batch of 1000 calls. Min-of-batches is the stable number on a loaded host. |
| cpu/call | thread CPU per call, sampled on 1 call in 64 |
| allocs / bytes | per call, from the counting global allocator (linked mode: exact, the plugin's own allocations included) |
| rss10k / rss100k / rss1M | process RSS (MiB) after that many calls of the op, to catch growth |
| offcpu | share of thread wall time not on a CPU. Lock waits park a thread, so this stands in for lock-wait share under N threads. |
| p50 by call window | p50 over calls <1k, <10k, <100k and the rest: how cost moves as the plugin's state grows |

The default run is 1,000,000 calls per op, split over the threads, at 1 and 4 threads. Each
scenario has a wall budget (`--budget-secs`, default 10). A run that hits the budget says so and
reports the calls it made.

The output is a table on stdout plus `target/plugin-bench/<kind>.json`.

## Workloads

**store.** These are the kernel journal's append shape:

- `commit`: a CAS on a head key plus a 1 KiB record put (`--record-bytes`), a 64-byte result, and a
  fresh attempt id each time, so every commit leaves one receipt behind.
- `read`: two keys.
- `clock`: the floor.

Records rotate over 1024 keys per thread, so only what the store keeps per commit grows.

**plane.** Each unit is driven the way the plane driver drives it: `arrive` → ATTEMPT piece →
caller-body piece → far-end answer. The answer is either one whole piece, or a status piece plus
one piece per SSE event. Every unit runs to `EMIT_DONE`. The scenarios are:

- OpenAI → OpenAI whole answers with 1 KiB, 8 KiB and 100 KiB bodies (`--body-sizes`).
- Anthropic → Anthropic and OpenAI → Anthropic whole answers with 8 KiB bodies.
- Streams with `--deltas` deltas (default 200) for oai>oai, ant>ant, oai>ant and ant>oai.

The default settings name providers `oai` and `ant` and models `gpt` and `claude`. Use
`--settings` to override them.

**secret.** No workload: the door secret kind is retired (WP3 step 2); a native secret workload is a follow-up.

**auth.** Outbound `fields` as the far-end request path calls it (`POST /v1/chat/completions`):
the operator's own key, a caller passthrough key, and an invalid passthrough key. Inbound
`verify` is benched only for plugins that serve it.

**hook.** `decide` over an OpenAI chat projection with 1 KiB / 8 KiB / 100 KiB of content and
three members. Only the FIRST crossing is measured: a hook's classifier child needs a
dispatcher-bound child ticket, which an inline call cannot bind, so the child call is refused and
the hook abstains. The resumed crossing (replay + classify) is not measured.

**export.** `deliver` of 1 span, one request's spans (3) and a full 256-span batch, on the
loader's inline-ticket path (`deliver` needs a ticket to reach its connection), plus the ticket
retire/mint as its own op. The far end is `SinkConns` (`src/host.rs`): an in-memory connection
table that admits the plugin's declared need, takes each framed request whole and answers 200.

**transport.** In-memory bytes, no sockets: `begin` / `ingest` / `emit` on the inline-ticket path
under the connector's framing context, `finish` direct. h1 keep-alive with 1/8/100 KiB request
bodies and a JSON or 200-chunk SSE response; h2 (prior knowledge) the same; h1
connection-per-request. Every crossing goes through the loader's public `answer`/`answer_inline`, as
core's connector does, which release each answer's lease inside the crossing, so timed ops include
that RELEASE. Compare numbers only against runs taken after this change.

Adding a kind's workload means a `specs()` module that builds that kind's frames.

## Running it

From a core checkout, against any cdylib:

```sh
cargo run --release --manifest-path tools/plugin-bench/Cargo.toml --example busbar-plugin-bench -- \
  --plugin /path/to/target/release/libbusbar_store_memory_plugin.so --kind store
```

In a dropped-in cdylib, the plugin's allocations go through the cdylib's own allocator and are not
counted; the report says "HOST SIDE ONLY". For exact allocation counts, link the door.

From a plugin repo, linked: this is the mode to use in CI. Add a dev-dependency at the core rev the
repo already pins:

```toml
[dev-dependencies]
busbar-plugin-bench = { git = "https://github.com/GetBusbar/busbar", rev = "<the .busbar-ref rev>" }
```

Then add a one-line example, `examples/bench.rs`:

```rust
busbar_plugin_bench::bench_main!(busbar_store_memory::door);
```

Then run:

```sh
cargo run --release --example bench -- --kind store
```

`--plugin target/release/libX.so` on the same binary benches the dropped-in image instead.

Other options: `--ops`, `--threads 1,8`, `--only commit`, `--json path`, `--budget-secs`.
`BUSBAR_BENCH_VERBOSE=1` echoes the plugin's diagnostics, the host services it calls, and every
plane piece's answer. Use it to debug a workload, never to measure.

## Why it is its own workspace

It enables `busbar-contract/test-seal` and `busbar-plugin-loader/test-support`. Those must never
unify into a root-workspace build of the engine, so the root workspace excludes
`tools/plugin-bench`.

## Retiring the per-repo harnesses

This keeps the useful parts of the perf pass's ad-hoc harnesses:

- the exact counting allocator;
- the min-of-batches timer;
- thread CPU per op;
- one reused frame per call.

It drops the Python helpers. To profile one op, run the bench under `samply record` with
`--only <scenario>` and a fixed `--ops`.
