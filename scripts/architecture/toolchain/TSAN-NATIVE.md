# Native x86 sanitizer runtime qualification

`tsan_linux29_probe.py` is a fixed-source control probe for the existing native
CI fleet: Linux x86_64, Docker Engine 29.1.3, and an immutable toolchain image.
It does not select or activate a profile for candidate jobs. The ordinary
`native_confinement.Execution` constraints remain in force for every launch.
The separate local ARM experiment remains in `SANITIZER-LOCAL.md`.

The engine source is Moby commit
`fbf3ed25f893e6ce21336f1101590e40a13934f4`, which vendors
`github.com/moby/profiles/seccomp@v0.1.0`. The baseline and derived policy hashes
are pinned in `tsan-linux29-pins.json`. The only added rule permits
`personality(262144)` (`PER_LINUX | ADDR_NO_RANDOMIZE`). The probe checks the
engine version and commit, baseline bytes, exact policy delta, and actual
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

A pass requires the original startup obstruction, an instrumented mutex control
exiting 0 with personality 262144, a deliberately racing control exiting 66
with a TSan data-race diagnostic, and the boundary-denial witness. It retains
compiler/platform output, exact commands, binary and policy hashes, container
observations, and disposal evidence. No failed attempt is retried or hidden.
`release_eligible` and `production_activation` remain false: passing these
controls qualifies the runtime configuration, not a product revision.

## Current evidence

The existing x86 worker's GCC controls fail before main with an unexpected
memory mapping under the default profile. The local ARM64 Docker 29.5.2 narrow
profile has passed controls and boundary checks, but is a different engine and
architecture. This Docker 29.1.3 probe and profile have not yet run on the native
x86 worker. Unit checks validate the policy pins and rejection of broader rules;
they do not establish native runtime support.

A compiler-only upgrade is not a demonstrated remedy: LLVM 23.1.0 still attempts
`personality(ADDR_NO_RANDOMIZE)` when its initial layout is incompatible and
fails if that syscall is denied. See the official
[LLVM runtime](https://github.com/llvm/llvm-project/blob/llvmorg-23.1.0/compiler-rt/lib/tsan/rtl/tsan_platform_linux.cpp)
and the pinned
[Docker baseline](https://github.com/moby/moby/blob/fbf3ed25f893e6ce21336f1101590e40a13934f4/vendor/github.com/moby/profiles/seccomp/default.json).
