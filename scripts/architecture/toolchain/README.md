# Offline native compiler image and seed

This directory prepares a digest-pinned Rust/C compiler image and an exact-lock
Cargo seed. It does not activate native CI or signing. The image contains the
repository's Rust 1.98.0, Clippy and rustfmt, plus the Python/GCC tools from its
immutable official Rust Bookworm base. Both Linux platform manifests and component
archives are pinned in `pins.json`; the actual local checks used Linux ARM64.

The approved input plan has schema `busbar.native-toolchain-inputs/1` and exactly
these fields:

| Field | Meaning |
| --- | --- |
| `platform` | `linux/amd64` or `linux/arm64` |
| `source_date_epoch` | Fixed integer timestamp used for image/file reproducibility |
| `toolchain` | `{path, sha256}` for the repository's `rust-toolchain.toml` |
| `vector` | `{path, sha256}` for the independently selected product vector |
| `locks` | Complete expected map of relative Cargo.lock paths to SHA-256 |
| `git` | Every locked Git URL mapped to `{path, files}` for its precollected bare repository; `files` is its complete regular-file digest map |

Paths are relative to the protected `--source` directory. The planner must include
every product, trusted harness and tooling lock needed by the qualification;
omitted roots cannot be inferred from an arbitrary caller's list. A changed
vector, toolchain file, lock or Git object inventory requires a new approved plan.
Canonical private Git fetches happen before this step, in the authorized source
collector. No source-fetch credential is supplied to image preparation.

`prepare.py` verifies the independently supplied plan digest and all input bytes.
It constructs new Cargo manifests containing only the exact external package
identities from approved locks. Candidate source, build scripts and `.cargo`
configuration are not copied into those collector workspaces. Bare Git config,
hooks, FETCH_HEAD and external object stores are excluded; only pinned objects,
refs and credential-free generated config are retained.

`seed.py` is the sole network-enabled image step. It runs `cargo fetch`, never
build/test, from those generated manifests with a fresh HOME/Cargo home and a
fixed environment. Git permits only local-file transport; every allowed Git URL
is rewritten to its precollected repository. Registry fetches use crates.io.
The resolved external package/version/source/checksum set must exactly equal
the approved lock set, then `cargo fetch --frozen` must succeed. Expansion or
resolver drift fails. Git index filesystem metadata and reflogs are normalized;
every resulting regular seed file is hashed.

`install.py` runs without network. It installs the checksum-pinned Clippy/rustfmt
archives, checks tool versions and rechecks the seed inventory. `build.py` requires
the exact prepared-context digest and pinned Docker/Buildx executables. It exports
an OCI archive with fixed timestamps, loads it into the existing local daemon and
requires the resulting immutable `name@sha256:…` reference to resolve. It never
substitutes a mutable tag. Temporary images use the `busbar-native-task` name.

Typical invocation, with real protected paths and independently approved digests:

```sh
python3 scripts/architecture/toolchain/prepare.py \
  --plan /protected/inputs.json --plan-sha256 APPROVED_PLAN_SHA256 \
  --source /protected/inputs --output /scratch/context --downloads /scratch/downloads
python3 scripts/architecture/toolchain/build.py \
  --context /scratch/context --context-sha256 APPROVED_CONTEXT_MANIFEST_SHA256 \
  --docker /usr/bin/docker --docker-sha256 PINNED_DOCKER_SHA256 \
  --buildx /usr/libexec/docker/cli-plugins/docker-buildx --buildx-sha256 PINNED_BUILDX_SHA256 \
  --endpoint unix:///var/run/docker.sock --tag busbar-native-task:qualification \
  --output /scratch/build --no-cache
```

The context digest covers `context.sha256.json`; its entries cover every other
context file. Supply scratch paths under the authorized task directory. No
network-dependent tooling installation occurs in candidate containers: their
`CARGO_HOME` starts from a fresh copy of the measured image seed. Use the built
image's Python `/usr/bin/python3`, PATH `/usr/local/cargo/bin:/usr/bin:/bin`,
`RUSTUP_HOME=/usr/local/rustup` and `CARGO_HOME=/opt/busbar-native/cargo-seed` in the
separate, approved confinement configuration.

`probe.py` executes small actual compiler witnesses through `native_confinement`.
Its fixture seed contains the current lock's `itoa` 1.0.18 and may include the
synthetic `busbar-seed-git` fixture. The latter's build script deliberately refuses
execution in the collector; it must run only in the confined compiler phase.
The probe checks actual tool versions, offline registry/Git use, a positive Cargo
test, Clippy, an exact negative E0308 witness, denied build-script writes to the
trusted harness, external harness lockfiles, C execution and TSan behavior.
`--require-tsan` makes an unsupported sanitizer runtime a failing result.

On 2026-11-10, those Rust/Clippy/C fixtures passed on the existing ARM64 Linux
runtime. Two uncached builds of the same prepared fixture context produced the
same image digest. TSan is blocked under the unchanged default profile; the
separately authorized local profile below passed its bounded controls. These are fixture
results, not qualification of the changing release vector or deployed native
worker. Additional native roster tools such as nextest/deny/vet, Node and Python
packages still need explicit pins and full-vector CI qualification before this
base image can serve the complete native job.

Run only the targeted unit checks locally:

```sh
PYTHONPATH=scripts/architecture/toolchain python3 -m unittest test_toolchain
```

The recipe follows Cargo's documented distinction between dependency fetching
and frozen offline operation, and BuildKit's timestamp controls; no GitHub
workflow or release-attestation identity is involved.
[Cargo fetch](https://doc.rust-lang.org/cargo/commands/cargo-fetch.html),
[OCI export timestamp controls](https://docs.docker.com/build/exporters/oci-docker/).

## TSan dedicated profile — locally qualified, not deployed

The existing local runtime reported Docker 29.5.2/runc 1.3.5, ARM64 Linux 6.8.
The confined process's read-only personality query returned `0`, errno `0`.
Both GCC 12.2 TSan binaries exited **245** before their test bodies:
`tsan_platform_linux.cpp:315`, `personality(old_personality | ADDR_NO_RANDOMIZE)`
returned `-1`. Explicit `setarch --addr-no-randomize` exited **1**, operation not
permitted. Neither result is a sanitizer pass.

A separately authorized local experiment used a controller-selected sanitizer
profile that retains the independently pinned engine baseline and appends only
this rule:

```json
{
  "names": ["personality"],
  "action": "SCMP_ACT_ALLOW",
  "args": [{"index": 0, "value": 262144, "op": "SCMP_CMP_EQ"}]
}
```

`262144` is `0x0040000`, exactly `PER_LINUX | ADDR_NO_RANDOMIZE` for the observed
initial personality `0`. Do not use a wildcard, a masked comparison accepting
other flags, CAP_SYS_ADMIN, ptrace, seccomp-unconfined or a host sysctl. Recheck the
initial value on each qualified target. Linux changes the calling task's
personality; the sanitizer's re-execution and descendants inherit the changed
address-layout behavior. It does not change the host's ASLR setting.
[Linux personality implementation](https://github.com/torvalds/linux/blob/v6.8/kernel/exec_domain.c),
[flag definitions](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/personality.h),
[GCC sanitizer startup](https://github.com/gcc-mirror/gcc/blob/releases/gcc-12.2.0/libsanitizer/tsan/tsan_platform_linux.cpp).

This reduces the **sanitizer process's ASLR mitigation**. It leaves the required
nonroot identity, zero capabilities, no-new-privileges, seccomp filtering,
network/PID/mount separation, read-only policy and absent host socket intact.
Claims of unchanged default seccomp or universally enabled process ASLR would no
longer be accurate. Seccomp does not authenticate the caller's executable: code
inside that sanitizer container could invoke the allowed argument too.

The controller must therefore select this profile only for a fixed trusted
sanitizer invocation, bind its profile/image/binary digests into observations,
and reject every JSON policy difference beyond that single rule. The local
experiment pins the vendored baseline from Docker Engine commit
`568f755ebeb1ac9c6a8febbda6cd371ea0a9630b`, SHA-256
`536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74`, rather than
assuming an upstream-main profile matches the engine. The normal native backend
has no custom-profile activation path; the separate local probe is the only
implementation here that selects the exception.

The bounded local experiment passed a genuine race-free TSan control, detected a
deliberate race, and retained the confinement denial witnesses. An external
source-hashed product unit witness also passed. See [the local qualification
record](SANITIZER-LOCAL.md) for exact profile hashes, reproducible fixture commands,
and evidence locations. The unchanged default profile still blocks TSan. The
dedicated profile has not been deployed to a native worker or qualified against
the complete final release vector; that requires target-specific baseline
verification, authorization, and full CI qualification. Release eligibility
remains false.
