# Native x86 sanitizer runtime qualification

`tsan_linux29_probe.py` is a fixed-source control probe for the existing native
CI fleet: Linux x86_64, Docker Engine 29.1.3, and an immutable toolchain image.
It does not select or activate a profile for candidate jobs. The ordinary
`native_confinement.Execution` constraints remain in force for every launch.
The separate local ARM experiment remains in `SANITIZER-LOCAL.md`.

## C unit-test activation

On Linux, the trusted C branch in `native_plugins.qualify_plugin` calls
`native_sanitizer.run_c_unit_tsan` only for `c-unit-tsan`. The helper runs fresh
fixed-source controls with the current execution configuration, image, and
daemon before selecting the profile. The baseline is bundled as
`tsan-linux29-baseline.json` and must match the pinned digest. The helper accepts
no command or profile from candidate input, and refuses host execution.

After all controls pass, `CUnitExecution` permits only
`setarch --addr-no-randomize <candidate-work>/unit-tsan`, the checkout working
directory, and `TSAN_OPTIONS=halt_on_error=1`. It retains the default execution
state and shared observation list, and the helper restores the original
execution object in `finally`. Compilation, the ordinary unit test, schema
checks, and all other commands continue through default confinement. Failed
controls or product tests remain failures. The admission receipt binds the
runtime configuration, control receipt, profile, exact command, and test binary
digests; control results and engine observations are retained in evidence.

The engine source is Moby commit
`fbf3ed25f893e6ce21336f1101590e40a13934f4`, which vendors
`github.com/moby/profiles/seccomp@v0.1.0`. The baseline and derived policy hashes
are pinned in `tsan-linux29-pins.json`. The worker uses Ubuntu's exact
`docker.io` build `29.1.3-0ubuntu3~24.04.2`. Ubuntu's `debian/rules` sets
`DOCKER_GITCOMMIT := $(DEB_VERSION)`, so the daemon reports that package version
as `GitCommit`, rather than the upstream source SHA. The probe checks exact
`Version=29.1.3` and `GitCommit=29.1.3-0ubuntu3~24.04.2`; other package builds,
suffixes, empty commits, and upstream SHA prefixes are rejected.

The official Ubuntu source archives were downloaded and their SHA-256 values
checked against the package's `.dsc`. The archived
`engine/vendor/github.com/moby/profiles/seccomp/default.json` and
`default_linux.go` match the upstream pinned hashes byte for byte. None of the
six patches in `debian/patches/series` modifies the seccomp package. Source
archive URLs and hashes are retained in the pins file. The source commit and
binary build identity remain distinct, independently pinned fields.
See [Ubuntu's package record](https://packages.ubuntu.com/noble/docker.io).

The only added rule permits
`personality(262144)` (`PER_LINUX | ADDR_NO_RANDOMIZE`). The probe checks the
engine version and exact build identity, baseline bytes, exact policy delta, and actual
container configuration. Compilation uses the unchanged baseline. Only the two
instrumented controls and the denial witness use the dedicated profile.

GCC 12's x86 runtime does not reliably repair incompatible randomized layouts.
The controller invokes the controls through `setarch --addr-no-randomize` under
the dedicated policy. This changes ASLR only for that process and its descendants;
it grants no additional filesystem, network, namespace, or capability authority.
Any candidate code sharing such a container could invoke the same allowed
argument: seccomp does not authenticate a caller executable. Therefore this
policy must remain limited to separately selected sanitizer invocations.

Run through the existing exclusive GitLab native-worker fixture path. Do not
reuse another job's worker or its Fleeting credentials. Do not start or extend
bake VMs. Prepare a new work directory under the authorized task scratch root
and download the pinned `baseline_url` there; the probe verifies its SHA-256.
Then run from the approved trusted policy checkout:

```sh
python3 -B scripts/architecture/toolchain/tsan_linux29_probe.py \
  --config "$RUNTIME_CONFIG" --config-sha256 "$RUNTIME_SHA256" \
  --baseline "$DOCKER_29_1_3_BASELINE" --work "$NEW_PROBE_OUTPUT"
```

A pass requires a successful fixed-source negative control that observes
`personality(262144)` returning `-1` with `EPERM` under the unchanged baseline,
with the personality remaining zero. An unexpected success, different error,
or unsuccessful control process fails qualification. The randomized baseline
TSan attempt is retained as diagnostic evidence only: its exit status or error
text never substitutes for this syscall control or establishes a sanitizer pass.
A pass also requires an instrumented mutex control
exiting 0 with personality 262144, a deliberately racing control exiting 66
with a TSan data-race diagnostic, and the boundary-denial witness. It retains
compiler/platform output, exact commands, binary and policy hashes, container
observations, and disposal evidence. No failed attempt is retried or hidden.
`engine.json` retains the raw daemon response before parsing or checking its
identity. An identity mismatch also produces a failed `result.json` containing
the observed engine, while cleaning up the probe source/build roots.
`release_eligible` and `production_activation` remain false: passing these
controls qualifies the runtime configuration, not a product revision.

## Current evidence

[Diagnostic job 3763](https://github.com/GetBusbar/busbar/-/jobs/3763)
(pipeline 1995, trusted policy `9f564fdedb5c851d69656ddbf7e0ebcacfb6aad1`)
passed the fixed-source controls on runner 32: Linux 7.0.0-1017-gcp x86_64,
Docker 29.1.3 with Ubuntu build identity `29.1.3-0ubuntu3~24.04.2`, and GCC
12.2.0. The unchanged baseline reproduced an unexpected-memory-mapping failure
with exit 66. The dedicated profile produced clean exit 0 and deliberate-race
exit 66 with a TSan data-race diagnostic. The denial witness passed with UID
1001, seccomp mode 2, and personality 262144. All eight probe containers were
inspected and disposed; bootstrap reported candidate-container and storage
disposal, and all six confinement controls passed.

The retained `acceptance-close/native-diagnostic-9f564fd/tsan-result.json`
records `native-x86-sanitizer-controls-pass`, `production_activation=false`,
and `release_eligible=false`. This qualifies the observed runtime controls.
Actual C plugin qualification through the controller activation added at
`ec527084ec5112805027641ce7b3b62b92802058` remains pending. The per-job control
gate remains mandatory; this result does not grant blanket profile activation
or qualify a product revision.

C plugin job 3880 (pipeline 2053) subsequently stopped before the dedicated
profile controls because its baseline TSan attempt exited 245 with no stdout
or stderr. The old message-matching prerequisite incorrectly assumed every
randomized startup failure would print the mapping/personality diagnostic.
The direct syscall negative control above replaces that prerequisite; the
clean, deliberate-race, boundary-denial, and disposal requirements remain
mandatory. Job 3880's failed attempt remains retained and is not a sanitizer
pass. The corrected per-job gate still requires native CI execution.

A compiler-only upgrade is not a demonstrated remedy: LLVM 23.1.0 still attempts
`personality(ADDR_NO_RANDOMIZE)` when its initial layout is incompatible and
fails if that syscall is denied. See the official
[LLVM runtime](https://github.com/llvm/llvm-project/blob/llvmorg-23.1.0/compiler-rt/lib/tsan/rtl/tsan_platform_linux.cpp)
and the pinned
[Docker baseline](https://github.com/moby/moby/blob/fbf3ed25f893e6ce21336f1101590e40a13934f4/vendor/github.com/moby/profiles/seccomp/default.json).
