# Test rigs

The unit and integration tests live beside the code they cover, in each crate's own test files.
This directory holds the rigs that judge the assembled product from outside. How to run the tests,
and what CI runs, is in [docs/testing.md](../docs/testing.md) and [docs/ci.md](../docs/ci.md).

| Directory | What it is |
|---|---|
| `shadow-oracle/` | The upgrade oracle's corpus: `cells.json`, the golden outputs recorded from the published 1.5.5 binary, and the signed `accepted-differences.json` and `accepted-gaps.json` that say which 1.6.0 differences the owner has accepted. |
| `oracle/` | The black-box package that runs the corpus against a built `busbar` binary, with the bundled plugins loaded from packages and never compiled in. It reports differences and gates nothing. |
| `conformance/` | The conformance check every repository runs (`run.sh`, `suites.tsv`): each official suite against the assembled host, one verdict file per suite. |
| `h2-conformance/` | The `h2` suite: h2spec over TLS against the HTTP/2 listener, with a known-good third-party server as the control leg. |
| `tls-conformance/` | The `tls` suite: testssl.sh and tlsfuzzer against the listener, judged by named assertions and never by a letter grade. |
| `oidf-conformance/` | The OpenID Foundation OAuth and FAPI conformance suite, run through native CI. See its README. |
| `evidence-conformance/` | The audit-trail, RBAC and TLS evidence rigs. Busbar supplies evidence; these rigs never issue a certificate of their own. |
| `sbom/` | The CycloneDX SBOM of the shipped binary, generated and validated against a third-party control. |
| `fleet-fixtures/` | Shared container fixtures (service images and their identity checks) for the rigs that need a backing service. |

The protocol batteries for MCP, A2A and the other planes live with each plane in its own repository,
and run in that repository's CI against a Busbar binary with the plane dropped in.
