# Dedicated local sanitizer qualification

These scripts qualify a separate, disposable local sanitizer container. They do
not configure the normal native backend, a CI runner, or a production service.
The earlier toolchain README records the unchanged-default-profile obstruction;
this experiment subsequently exercised the explicitly authorized narrow remedy.

`sanitizer_profile.py` requires the exact Docker Engine 29.5.2 vendored seccomp
baseline identified by `sanitizer-profile-pins.json`. It appends exactly:

```json
{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":262144,"op":"SCMP_CMP_EQ"}]}
```

All existing rules, default actions, architecture mappings, and other fields must
remain equal. Mutation tests reject wildcard or masked arguments, additional
personality flags, extra syscalls, and changes to existing policy. The pinned
baseline SHA-256 is
`536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74`;
the derived canonical profile SHA-256 is
`edd4f4b5a5186f79987fa08da7cd8a7ddf9aec285435df54092ed5d3af385623`.

This exception **disables per-process ASLR** for the sanitizer process and its
descendants after re-execution. It changes a seccomp restriction: it is not an
unchanged blanket seccomp claim. It does not modify a host sysctl or add
capabilities, ptrace, namespace, filesystem, or network authority. Seccomp cannot
authenticate the calling executable; any code inside this dedicated container
can invoke the allowed argument. Selection of this profile belongs to the
trusted controller and requires separate authorization from the normal candidate
profile.

The Linux [personality flags](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/personality.h)
define `ADDR_NO_RANDOMIZE` as `0x0040000`. The
[syscall implementation](https://github.com/torvalds/linux/blob/v6.8/kernel/exec_domain.c)
updates the calling task's personality. GCC 12.2's
[TSan runtime](https://github.com/gcc-mirror/gcc/blob/releases/gcc-12.2.0/libsanitizer/tsan/tsan_platform_linux.cpp)
sets that flag and re-executes on this platform.

## Reproduce within an authorized local runtime

First prepare the digest-pinned toolchain image and exact runtime configuration
described in README.md. Download the baseline URL from the pins file into the
task scratch directory; the script verifies its bytes against the pinned hash.
Use new, nonexistent output directories under the task scratch directory:

```sh
python3 scripts/architecture/toolchain/sanitizer_probe.py \
  --config "$RUNTIME_CONFIG" --config-sha256 "$RUNTIME_SHA256" \
  --baseline "$PINNED_BASELINE" --work "$NEW_SANITIZER_OUTPUT"
```

The command requires the pinned local engine, inspects the applied profile and
the existing isolation constraints, records container disposal, and removes its
temporary source/build trees. It retains result JSON and controller evidence.
Product-specific witness recipes remain outside the core controller tooling.

## Actual local result, 2026-11-10

On existing ARM64 Colima Linux 6.8, Docker Engine 29.5.2, runc, and the fixture
toolchain image
`busbar-native-task@sha256:3a1da8849c215e0fa25044ec4ba215e3bfb449c125cedcd1eb6a15307366f03c`:

- The unchanged pinned baseline reproduces TSan exit 245 at the denied
  `personality(old_personality | ADDR_NO_RANDOMIZE)` call.
- Genuine GCC `-fsanitize=thread` binaries compiled under the unchanged baseline.
  Under the dedicated profile, the mutex-protected control exits 0 and reports
  personality 262144; the deliberately racing control exits 66 and reports a
  ThreadSanitizer data race.
- With personality 262144, filesystem writes to checkout, harness, trusted
  inputs, and root filesystem remain denied; metadata and external networking
  remain unreachable; controller secrets/socket/credential variables remain
  absent; user/mount namespace creation and broader personality flags remain
  denied. UID is nonroot, effective/permitted/bounding capabilities are zero,
  no-new-privileges is 1, and seccomp mode is 2.
- An externally prepared, source-hashed product unit witness also compiles and
  exits 0 under TSan, with no stderr. Its separate retained receipt records the
  selected source/header bytes, revision names, compiler invocation, binary
  digest, exact profile, and container disposal.

Evidence is retained in the authorized task scratch directory at
`toolchain/sanitizer-local/result.json`; the external product witness receipt is
`toolchain/secret-c-tsan/result.json`, alongside the scratch-only
`toolchain/product_sanitizer_probe.py` recipe.
This is a local ARM64 fixture/product witness, not qualification of the final
release vector, a deployed runner, or an independently observed production host.
Both reports explicitly set release eligibility and production activation false.
