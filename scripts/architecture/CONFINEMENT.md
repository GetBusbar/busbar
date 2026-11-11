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
| `schema` | `busbar.native-confinement/2` |
| `docker` | Absolute trusted Docker client path |
| `docker_sha256` | That executable's SHA-256 |
| `docker_host` | Existing local `unix:///…` endpoint |
| `image` | Already-present `repository@sha256:<64 lowercase hex>` |
| `runtime` | Explicit installed `runc` or `runsc` |
| `uid`, `gid` | Positive integer workspace identity; never root |
| `python` | Absolute Python path inside that pinned image |
| `environment` | Required absolute-entry `PATH`; optional absolute immutable-image `CARGO_HOME`, `RUSTUP_HOME`, `RUSTC`, `RUSTDOC`, `GOROOT` |
| `resources` | Positive integers `cpus` (≤64), `memory_bytes` (≤256 GiB), `pids` (≤65536) |
| `isolation` | Exact storage kind/root/byte/inode/reserve contract and subordinate UID/GID maps described below |
| `collector` | Protected local `docker_host` and mapped host `uid`/`gid` for trusted dependency fetching only |

Schema 2 refuses the earlier partial fixture configuration. A protected root
controller prepares fresh bounded storage using `linux_job_isolation.py` before
staging job inputs. Full native jobs use `storage_kind: "loop-ext4"`: a private,
fully preallocated sibling `storage_image`, fixed byte and inode ceilings, and an
explicit host free-space reserve. This prevents Cargo outputs consuming the
worker's RAM or exhausting unrelated host storage. Tiny probes may use `tmpfs`.
Every writable bind, including checkout targets and private dependency collection,
lies under that one quota; nested mount bypasses refuse. `/tmp` has a separate
1 GiB / 65,536 inode bound and `/dev/shm` a 64 MiB bound, both inspected.

The candidate daemon must enable userns-remap and run in dedicated private mount
and network namespaces. Protected UID/GID maps are
`[0, subordinate_host_start, range_length]`, starting at least 65,536; the entry
checks the actual kernel maps before any candidate command. The root controller
grants mapped ownership to writable inputs and retains control/intake authority.
The separate existing daemon handles only trusted dependency fetching, as the
mapped nonroot host UID/GID with bounded quota mounts and no executable candidate
source. Its endpoint never enters candidate environment. This avoids altering
an existing runner's bridge to provide the trusted collector internet access.

Per-invocation Cargo homes are removed by the controller only after confirmed
container disposal; prior commands cannot poison later caches or accumulate seed
copies until quota exhaustion. Candidate containers receive no host root,
capabilities or daemon socket. Teardown confirms every container's removal, stops
the dedicated namespace/daemon, then normally unmounts/detaches bounded storage.
These requirements need protected bootstrap integration; they never silently
modify a runner daemon or choose subordinate identity ranges.

The reusable image contains only public compilers, tools, the signed oracle and
a measured public RustSec snapshot. `native_seed.py` separately prepares each
job's authorized dependency closure, bound to its candidate, assembled host, SDK
and product locks. It preserves the original Cargo manifest graph but replaces
source contents with inert placeholders and excludes Cargo configuration and Git
credentials. Its bounded network-enabled collector runs only `cargo fetch
--locked`, never candidate build scripts, then verifies unchanged exact external
package identities and frozen fetch. It copies only the image's public advisory
cache; product/private source caches are never baked into the reusable image.
Each candidate command copies that measured job seed to a fresh writable cache,
so prior commands cannot poison a later trusted harness cache. The toolchain stays in the read-only
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
and JUnit files are copied with descriptor-relative no-follow/nonblocking opens
for every path component, regular-file checks, byte bounds and mutation checks, then hashed from a new
single-link controller copy. Reports require single-link source files. Cargo
compiler outputs may have stable hard links only when owned by the candidate
identity; Cargo itself links its public and deps output names. Observations bind command,
environment, mount set, runtime configuration, dependency seed, resources and
engine exit/OOM state before confirmed container disposal. These observations are distinct
from assertions or reports authored by candidate tests.

Only the controller manages service containers. Each fixture capability connects
one Unix socket to one fixed loopback port. The candidate gets a loopback TCP
adapter for that socket inside its network-none namespace. Requests cannot choose
a host or port. The broker limits concurrent connections and idle time; socket
paths must fit the portable Unix path limit. Candidate Docker access is never
provided. The historical 1.5.5 SQLite fixture is selected by the protected
`ci/native-fixtures.json` catalogue, fetched from its exact existing commit and
checked against the published binary/plugin digest tables. No replacement golden
is recorded. An explicit protected `--fixture-inputs` plus digest can provide the
same typed intake. Generated projects are checked for bounded regular sources
and registered read-only before trusted structural/compiler harnesses inspect them.

Conformance accepts only a protected `--conformance-capabilities` manifest and
independently supplied digest. The default denies every suite explicitly. The
candidate receives a read-only manifest and no Docker socket; unavailable suites
produce failure verdicts through the published capability-aware wrapper/helper.
Public instruments can be staged per job with `--conformance-inputs` and its
independently supplied SHA-256. `busbar.native-conformance-inputs/1` contains a
`bundles` map; each named bundle has an absolute protected source `path`, a
complete `files` map of `{sha256, executable}` and HTTPS `{uri, sha256}` provenance
rows. The controller copies bounded regular single-link files, rejects symlinks,
checks every digest, strips write permissions and mounts only
`/opt/busbar-conformance/<name>`. The sanitized manifest is read-only at
`/__busbar_conformance_inputs.json` (`BUSBAR_CONFORMANCE_INPUTS`). Bundle presence
does not itself authorize a suite. An OIDF bundle additionally receives exactly
two fixed loopback host aliases, inspected against the container configuration;
no arbitrary destination or DNS access is granted. The `pack` command emits a
deterministic `manifest.json` plus `bundles/<name>/**` archive with relative paths;
`unpack` verifies independently pinned archive and manifest digests and rejects
links, special files, duplicates, traversal and oversized contents before native
intake. Immutable GitLab archive provenance may contain only its exact SHA query,
never credential query parameters.

The controller requires those two files to match its published trusted copies,
so older plugin wrappers cannot silently ignore the capability contract. Runtime
repository identity comes from that protected manifest, not a credential-bearing
Git remote. External endpoint judges still require a separate scoped network
interface; they remain unavailable in confined mode.

Local checks use tiny fixtures only:

```sh
PYTHONPATH=scripts/architecture python3 -m unittest test_native_confinement
```

Six real-runtime tests additionally run when `BUSBAR_CONFINEMENT_TEST_CONFIG`
names an existing pinned test configuration. They create disposable containers
without pulls or provisioning. Set temporary directories explicitly; systems
with long temporary paths can use `BUSBAR_TEST_SOCKET_TMP` for short socket paths.
The 2026-11-10 local Colima and actual Linux x86 checks passed denied host access,
network, failure/timeout cleanup and controller/candidate dispatch. The x86 checks
also passed the same-kernel fixed fixture socket bridge, read-only capability
manifest, signed oracle, offline deny/vet, nextest, Cargo/Clippy and C controls.
These bounded fixtures do not establish complete assembled-vector qualification,
generated/migration product execution, storage/user-namespace deployment or full
external-suite support. TSan failed before test bodies on the observed x86 host
both inside and outside the container; it is not a sanitizer pass or exemption.
Independent controller observations describe development execution; production
release eligibility still requires the separately protected release evidence flow.

Controller service peers use their exact catalogue image digests in the separate
remapped daemon. Each peer has `network=none`, private PID/IPC namespaces, a
read-only image root, 1 GiB memory, 256 PIDs, one CPU, 64 MiB `/tmp` and shared
memory bounds, and a 1 MiB rotating log cap. Image bootstrap/data directories
are copied without following links into the same bounded job filesystem;
image numeric ownership is mapped into subordinate identities. The protected
controller verifies the requested settings and actual kernel identity maps.
Peers retain only the capabilities needed by their pinned bootstrap (OpenLDAP
also needs KILL to stop its temporary daemon within its private PID namespace).
Candidate containers continue to drop all capabilities.

No peer publishes a host port or joins a bridge. The controller captures an open
FD for the running peer's network namespace and exposes one fixed loopback port
through its Unix socket capability. A small trusted relay enters only that pinned
network namespace, drops to the mapped nonroot identity, and copies opaque bytes.
There is no destination address or Docker command in the candidate protocol.
Relay processes and sockets close before peer containers and namespace FDs are
disposed. Imported service images are checked against the approved digest and
full image configuration/root-filesystem layer identities across Docker's
containerd and legacy image-ID representations.

Conformance capability rows are generated only after the locked per-job seed
and a real fixed-source Python/PyYAML/Cargo/Node preflight. Known suites additionally
require their verified public instrument bundles. `available` means the isolated
suite may execute; its actual verdict remains independent. Release engineering
controls require their own offline bundle and never substitute for production
release subjects or attestations.

Each invocation recreates its private Cargo cache at a stable per-job path and
preserves seed mtimes. The controller removes that cache only after disposal is
confirmed. This resets dependency bytes while retaining legitimate target-cache
fingerprints between runtime preparation and nextest.
