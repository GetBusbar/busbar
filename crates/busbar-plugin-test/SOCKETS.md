# Live database tests through the SDK host

Enable `target-sockets` on the plugin's **dev-dependency** on `busbar-plugin-test`. Use the plugin's existing linked/admitted image and `Harness`; do not create a test plugin or bring the production kernel/connector into its dependency graph.

The target performs real asynchronous TCP and verified TLS against explicitly registered numeric loopback endpoints. It does not implement a database protocol, simulate authentication, or claim kernel policy coverage. `socket_report().subject()` identifies it as `host target; kernel not present`.

```rust,ignore
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::sockets::{Limits, Security, SocketTargets, TlsProfile, TrustSource};
use busbar_plugin_test::suites::harness::Harness;
use std::time::Duration;

let mut sockets = SocketTargets::new(Limits {
    connect: Duration::from_secs(10),
    io: Duration::from_secs(30),
    live: 8, // total physical sockets, including idle and pending reservations
    idle: 4,
    idle_lifetime: Duration::from_secs(60),
    read: 1024 * 1024,
})?;
sockets.allow("db", endpoint, Security::Tls(TlsProfile {
    server_name: "localhost".into(),
    alpn: vec![],
    trust: TrustSource::Bound { pointer: "/tls_ca_pem".into() },
    client: None,
}))?;
let mut needs = FakeNeeds::new();
needs.secret("/password", password.as_bytes());
let h = Harness::admit_linked(&PLUGIN, needs.with_sockets(sockets)?)?;
// config contains the service endpoint, original CA PEM at /tls_ca_pem,
// and the plugin's ordinary secret reference at /password.
let store = h.block_on(h.registry().open_store(&h.spec("db", &config)))?;
// Drive the typed store API here, including commit/readback and pooled reuse.
drop(store);
h.needs().socket_report().unwrap().finish()?;
```

`endpoint` must parse as `SocketAddr` and be loopback after IPv4-mapped normalization. Hostnames, remote destinations, wildcard addresses, port zero and duplicate registrations are refused. The instance name must match `InstanceSpec.name`. A scripted connection and live endpoint cannot overlap. Existing scripted FETCH and other host services remain scripted.

For Oracle's plaintext loopback CI service, register `Security::Plaintext` and use the instance's explicit plaintext acceptance when opening it through the registry. This does not waive production admission checks. MSSQL's strict-TLS service supplies its CA PEM and `localhost` server name; use the bound trust configuration above. `TrustSource::Explicit` supplies an explicit root set for trust handle zero only. There is no system-root fallback, hostname waiver or unverified TLS mode.

`ClientSource { pointer }` names a declared secret path whose scripted custody value is a PEM client certificate chain/private key. MemBinder records concrete declared pointers and opaque handle numbers per runtime instance. Unknown/wrong handles, mismatched SNI/ALPN or client identity are refused. Rebinding/unbinding revokes the prior instance generation and its sockets. No raw TLS config/verifier can be installed by a test.

OPEN creates a fresh chain-owned connection id. Reusable CLOSE preserves the physical pooled id across a later OPEN and returns `REUSED`; a completed in-band TLS connection also returns `TLS_DONE`. Endpoint, runtime instance, binding generation, TLS identity, ALPN and egress differences never share a socket. In-band TLS must match its original OPEN parameters. Plaintext sockets can be reused; unupgraded in-band sockets cannot.

All network phases honor the earlier of the caller deadline and explicit target budget. Dropping an operation or releasing its chain revokes ownership, shuts down established TCP synchronously and prevents a pending operation from publishing its result or rejoining the pool. The physical reservation remains counted until it is actually dropped. Expired callers cannot check out idle sockets.

`events()` reports ids, endpoint and lifecycle categories, never payloads or credentials. `finish()` requires no active/pending operations, checks exact expected failure counts and closes idle sockets. Omitting finish with unresolved failures or live operations panics on target drop (unless already unwinding). Negative host-capability tests may register an exact `expect_failure(category, count)` before the action; this does not suppress returned Need errors or allow unexpected failures.

The Enterprise CI service jobs own database provisioning. Restore the live Oracle/MSSQL suites against this API, run an instrumented plugin pipeline, and record its exact SDK/plugin SHAs and coverage. SDK unit tests and historical coverage do not establish the current plugin's coverage percentage. A configured live-service job must fail if its service environment is missing.
