# Native candidate execution

The confined path is opt-in and is not activated in the protected CI bootstrap.
The deployed development path continues to report `host-subprocess`,
`isolated:false`, `release_eligible:false`. Configured confinement never falls
back to host execution. Its controller observations also remain
`release_eligible:false`: the release producer requires an independently pinned
host observation, not fields copied from a native receipt.

The protected bootstrap must supply both `--confinement /protected/runtime.json`
and `--confinement-sha256 <independently approved file digest>`. Do not derive that
digest from a candidate file or expose configuration through candidate pipeline
variables. The JSON object has exactly these fields:

| Field | Required value |
| --- | --- |
| `schema` | `busbar.native-confinement/1` |
| `docker` | Absolute trusted Docker client path |
| `docker_sha256` | That executable's SHA-256 |
| `docker_host` | Existing local `unix:///…` endpoint |
| `image` | Already-present `repository@sha256:<64 lowercase hex>` |
| `runtime` | Explicit installed `runc` or `runsc` |
| `uid`, `gid` | Positive integer workspace identity; never root |
| `python` | Absolute Python path inside that pinned image |
| `environment` | Required absolute-entry `PATH`; optional absolute immutable-image `CARGO_HOME`, `RUSTUP_HOME`, `RUSTC`, `RUSTDOC`, `GOROOT` |
| `resources` | Positive integers `cpus` (≤64), `memory_bytes` (≤256 GiB), `pids` (≤65536) |

The image must contain Python, all required native compilers/test tools and the
complete offline dependency seed. Each command copies the image's Cargo seed to
a fresh candidate cache so Cargo can take writable locks and prior commands
cannot poison a later trusted harness cache. The toolchain stays in the read-only
image. Harness source stays read-only; Cargo 1.98 redirects its lockfile outside
the harness and uses a fresh target directory. No image pull is performed.

`--work` is the controller directory. Its `candidate` child is writable in the
container; `evidence`, generated `harness`, execution context, fixture map and
Docker client state stay outside that writable root. The original candidate
checkout is read-only, except explicit Cargo/nextest target directories. Trusted
policy and fetched immutable sources are read-only. Source symlinks refuse. Git
history is copied without clone credentials, hooks or external object stores.

Before execution, the controller inspects the exact container user, resources,
mounts and network/IPC/PID/cgroup settings. The image entry verifies nonroot,
zero effective/permitted/bounding capabilities, no-new-privileges, seccomp and
loopback-only interfaces. Every exit, timeout or cancellation removes the named
container and confirms a successful empty container listing. Regular artifact
and JUnit files are copied with no-follow/nonblocking opens, bounds and mutation
checks, then hashed from the controller copy. These observations are distinct
from assertions or reports authored by candidate tests.

Only the controller manages service containers. Each fixture capability connects
one Unix socket to one fixed loopback port. The candidate gets a loopback TCP
adapter for that socket inside its network-none namespace. Requests cannot choose
a host or port. The broker limits concurrent connections and idle time; socket
paths must fit the portable Unix path limit. Candidate Docker access is never
provided. The 1.5.5 online migration recorder, Docker-spawning conformance,
external-network judges and generated-project qualification currently refuse
in confined mode until their separate interfaces are implemented.

Local checks use tiny fixtures only:

```sh
PYTHONPATH=scripts/architecture python3 -m unittest test_native_confinement
```

Four real-runtime tests additionally run when `BUSBAR_CONFINEMENT_TEST_CONFIG`
names an existing pinned test configuration. They create disposable containers
without pulls or provisioning. Set temporary directories explicitly; systems
with long temporary paths can use `BUSBAR_TEST_SOCKET_TMP` for short socket paths.
The real 2026-11-10 local Colima/runc checks passed, including denied host access,
network, failure/timeout cleanup and controller/candidate dispatch. They do not
establish native Cargo/TSan image compatibility, deployed core confinement,
cross-namespace production fixtures, filesystem quotas, a user-namespace policy
or independent host attestations. Those remain required deployment engineering.
