# adapt: the engine's side of the revised plugin contract (crates/plugin-loader)
Branch `house/d-adapt` off `origin/house/engine-lint-pm` cb2a1790c3. Written against `origin/house/iface-solo`
6d0a019566 (every surface checked by reading: ASSUMED.tsv). NEVER COMPILED: format only.

## What is written (code, with tests)
- `call/`: the one place a call is built and a table entry invoked. `frame.rs` (typed arguments into
  head/texts/blobs on the stack: 0 heap calls, 0 copies of lent bytes, `known()` cuts to an older image),
  `mod.rs` (one function per shim: plain, opens, on, on_fixed, ends, chain), `ffi.rs` (THE BOLT: every
  boundary signature is used there and nowhere else), `kinds/*.rs` (the seven faces, 34 methods), `layout.rs`
  (the method table as data), `record.rs` (the crossing recorder: one hook, call + open + resume).
- All seven adapters cross through `call` and take the operation's one clock reading. Transport is on the one
  output model: every answer judged by the session's shared `wire::Wire`, emit as a piece set, SESSION,
  STREAM_BUSY, NO_NEW_STREAMS, sealed marks. Auth lost verify_io. Plane accepts the two route describe items.
- `validate.rs`: one validator per answer grammar (adapters and suites call the same functions).
- `agree.rs` + `admit.rs`: agreement at load on two-part versions; dev stamp refused by a release engine
  (feature `release-engine`); a too-new plugin refused naming both numbers; 8 outcome tests on a real stamp.
- `abi_crossings.rs` + `dist/default/tests/abi_crossings.rs`: the security test, with its red half; a
  feature-gated witness build judges the real binary. `watchdog.rs`: the hang report names method and thread.
- `tools/iface-adapt/`: the rename as ONE script (dry-run here: 355 files, 10 manifests, 0 left), the parts
  for files this line does not own, the lists for the deletion (74 files, 29,507 lines left under abi/).

## Waves
2: ADAPT-000..003 (parts into solo's, ports', verifier's files), 004 compile the loader, 005 its tests,
006..009 callers, 012, 014. 3: ADAPT-010 abi_crossings RED on first boot. 4: ADAPT-011 green after sealing.
5: ADAPT-013 the rename, last, once.

## Done for DONE when
The distribution test `abi_crossings` (package busbar-default, feature crossing-witness) prints
`abi_crossings: N crossings scanned, 2 secrets planted, 0 leaks` (G.1 item 7), and the rename script ends
`files still naming the old crate: 0`.

## Faults expected, and how each is recognised
- First compile: lifetime inference in `call::chain` (the start closure borrows the instance): error in
  call/mod.rs or ffi.rs `starts`. Fix there; no face changes.
- `against_the_contract` fails on one method: that face's head or position order differs from the generated
  packer (most likely an alignment gap: select_resources, render, deliver). The test names it.
- First boot: `SHAPE:` lines in the abi_crossings verdict = a face drifted from the method table;
  `transport_fault` with rule L5/L6 on a dial or L2 on a WebSocket upgrade = ADAPT-000 not applied.
- A dev plugin refused "not a released version": the engine was built with `release-engine` in dev.

## Chosen without the owner (defaults stand unless he says no)
1. The loader's `call::kinds` are the host's typed faces; the contract crate's generated host `Proxy` per
   kind goes on the dead list (the recorder needs the instance's identity; the boundary crate has none).
2. A caller's own credential is owned by its auth plugin AND the transport that framed it; a provider
   credential by its secret plugin alone.
3. Ports whose calls carry no clock reading (store, plane and transport session calls) hand in none (0).
4. Version and fingerprint refusals keep the existing codes (KindAbi, Mechanism, Layout).
