# busbar-ffi

The plugin boundary, and the only busbar crate that may hold `unsafe` (UNSAFE-MIN r3.1).

## The rule

busbar-ffi is for the plugin boundary **only**. An item belongs here only if it exists because native
plugin code and the host call each other across the C ABI, and it cannot be safe without costing speed.
It is never a place where any other `unsafe` can be parked.

Any non-plugin need for `unsafe` (allocators, ACLs, `AsyncFd`, OS calls, anything else) uses a safe crate
or goes to the owner. It never comes here.

## What is pinned (`unsafe.yaml` at the repository root, owner-approved)

- **Files.** Only `src/{lib,raw,header,vt,shim,slots,host,image}.rs` exist. A new
  file fails the check.
- **Counts.** The crate total and every file's own count of `unsafe` tokens (tests and doc code included)
  plus `allow`/`expect(unsafe_code)` attributes. A count above its pin fails; one below fails with "lower
  it to N". `unsafe` cannot move between files to make room.
- **Dependencies.** `zerocopy`; `libloading` and `object` behind feature `host`; `loom` only under
  `cfg(loom)`. A new dependency fails.
- **Dependents.** busbar-plugin-abi, busbar-plugin-loader (`host`), busbar-plugin-test and plugin crates,
  which never enable `host`.

The total only falls (UNSAFE-MIN §5 lists the eliminations, none at the cost of speed).

## Rules inside the crate

- Root `#![deny(unsafe_code)]`; `#![allow(unsafe_code)]` only on the pinned modules.
- `unsafe_op_in_unsafe_fn`, `clippy::undocumented_unsafe_blocks` and `clippy::multiple_unsafe_ops_per_block`
  are denied at the root and never allowed below it. Every `unsafe` block has a `// SAFETY:` comment.
- One exported macro, `export!`; its `#[unsafe(no_mangle)]` is the only `unsafe` token in any macro body.
- No `build.rs`, no `include!`, no proc macro of its own, no `test-support` feature.
- The blocking `ffi-lint` CI job lints this crate with `-D warnings`, with default features and with
  `--all-features`.
