# External authorization role assessment

The RBAC evidence suite now requires the unmodified ZAP Access Control addon to
judge the existing fixture's complete role/method matrices. Full execution is
CI-only; local adapter tests do not establish a Busbar pass. This is a scoped
external authorization assessment, not OWASP certification or all of WSTG.

External criteria: OWASP WSTG 4.2
[ATHZ-02](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/)
and [ATHZ-03](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation/).
They call for checking functions across identities and roles, including vertical
and horizontal authorization and privilege manipulation. They are assessment
guidance. The executable external judge is the published
[ZAP Access Control addon](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/),
release 13. The Busbar configuration, expected access rules and credential
fixtures remain authored by Busbar; the scanner's replay, authorization detection
and VALID/ILLEGAL/UNKNOWN judgments come from unmodified upstream code.

## Exact upstream and dependency pins

`upstream.json` pins the release-13 source commit and inspected source digests.
`runtime.lock.json` independently pins released executable bytes:

- ZAP 2.17.0 cross-platform archive, including core JAR dependencies.
- Access Control alpha 13, source commit
  `e7aaf9014287478da76bdbd56316ea171ee840d3`.
- Common Library 1.40.0, required by that Access Control release. The runtime
  ships 1.39.0, which does **not** satisfy its dependency; the adapter installs
  the exact separately pinned 1.40.0 release.
- The runtime's exact GraalJS 0.12.0, Scripts 45.17.0, Passive Scanner 0.6.0 and
  Network 0.25.0 and Call Home 0.20.0 archives, including their embedded libraries.
  These are the complete required addon dependency closure; ZAP requires Call
  Home even in silent mode, which disables its network calls. Other bundled addons are not
  installed. No scanner source or assertion is patched.
- Temurin JRE 21.0.13+9, separately pinned for Darwin arm64/x86_64 and Linux
  aarch64/x86_64. No installed Java, Docker or new service is required.

Digests were obtained from the official GitHub release assets and checked against
actual downloaded ZAP/AccessControl/Common Library bytes. Temurin archive digests
come from its official release checksum assets. Full CI verifies every selected
artifact before extracting or executing it. All runtime and addon updates are
explicitly disabled; ZAP runs headless with a private home and 512 MiB Java heap.

## Method-sensitive upstream behavior

The scanner clones historical requests and replays them for configured users,
preserving method/body. Access rules key by site-node name and URI; ZAP leaf names
include the method. Thus Busbar's method-sensitive admin API is applicable.

The release-13 report generator nevertheless groups results by **URI alone**, and
its TreeSet comparator treats same-user entries as equal. It discards later
methods for that URI. See pinned
[ExtensionAccessControl.java lines 415–441](https://github.com/zaproxy/zap-extensions/blob/e7aaf9014287478da76bdbd56316ea171ee840d3/addOns/accessControl/src/main/java/org/zaproxy/zap/extension/accessControl/ExtensionAccessControl.java#L415).
The adapter uses a fresh ZAP session and one exact operation/context/report per
scan. Every declared principal is scanned for that operation. `report.py` rejects
missing/extra methods, users or cells and preserves the upstream classifications.
Zero alerts or a stopped scan are insufficient: missing history responses and
send errors can omit cells, so an independent transport ledger must also contain
exactly one real request/response for every cell.

## Existing fixture boundary and required legs

`evidence.py::suite_rbac` builds the actual subject once before starting ZAP, then
uses one `ExternalRBAC(work, output)` context for the suite. Its `matrix` method
accepts the existing port, operation tuples, principal mint/expect functions and
`concrete` path function. It does not create another subject, issuer or policy.
Each operation imports explicit ALLOWED/DENIED rules for named upstream users.
The rules adapter checks that each method-bearing rule was installed; all
response judgments remain upstream. Original exact status/code, role, per-verb,
provider ceiling, key revocation and dispatch-isolation assertions remain required.

The mandatory external leg roster is:

1. Correct reference: normal provider and provider capped read-only.
2. Deliberately broken reference: both provider configurations. Upstream must
   report ILLEGAL scope/per-verb cells, including full-scope mutations; the normal
   provider must also produce ILLEGAL expired-token cells. Unknown results,
   unrelated illegal cells, server/rate/transport errors cannot satisfy controls.
3. Actual subject: every admin OpenAPI operation × every original principal,
   including the live data-plane key; both normal and capped providers.
4. Data `/stats` gate: absent credential, admin-only credential, live data key.
5. Admin listener `/stats` isolation and data listener GET/POST admin `/keys`
   isolation, including absent, invalid, admin-only and live data credentials.
6. Revoked key denied by the data `/stats` gate.

The fixed roster is ten legs. A duplicate, missing or unsuccessful leg prevents
completion. Each matrix declares full expected operation and cell counts; partial
artifacts stay red and are retained when execution fails. HTTP 429 and 5xx
transport/server failures never count as a successful denial or control failure.
The upstream authorization detector is configured for 401/403; isolation contexts
add 404 because the route is absent on that listener. The original internal
checks still distinguish exact statuses, body content and dispatch effects.

## Credential transport and evidence

`transport.js` is an HTTP sender adapter, not a response judge. For Access Control
requests only, it removes inherited Authorization/Cookie headers and asks the
private loopback Python callback for the existing fixture's fresh header set for
that exact method/URI/named principal. This preserves fresh JWT subjects/rate
buckets. The absent-credential principal receives no Authorization header. Each
request and response is counted; unknown principals, wrong operations, duplicate
callbacks or missing responses fail. No authentication bypass or fake token
verification is injected into Busbar.

Published output under `CONFORMANCE_OUT/external-rbac/` contains the exact full
input roster, access-rule context export, unmodified upstream HTML reports,
method/user cell classifications, response statuses and binary/config/source/tool
digests. No JWT is written by the adapter. ZAP's private history can contain JWTs;
it is removed on success or failure along with runtime dependencies. Only a
redacted bounded runtime log tail is retained. Scratch/build dependencies are
outside published output. Per-operation scans have a 60-second bound, startup has
120 seconds, and the complete external runner has 900 seconds after subject
compilation. Requests retain upstream network timeouts. There is no test retry,
case skip or partial-count pass; only asynchronous seed-tree preparation is polled.

## Execution and claim limits

The existing CI launcher runs:

```sh
CONFORMANCE_OUT=<published-output> TMPDIR=<private-scratch> \
  PYTHONDONTWRITEBYTECODE=1 python3 testing/evidence-conformance/evidence.py rbac
```

Do not run that full matrix locally. Local targeted validation:

```sh
TMPDIR=<private-scratch> PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s testing/evidence-conformance/external-rbac -p 'test_*.py' -v
node --check testing/evidence-conformance/external-rbac/transport.js
node --check testing/evidence-conformance/external-rbac/rules.js
```

A successful complete run supports the declared role/verb authorization profile
using ZAP's external judge. Arbitrary parameter fuzzing, horizontal object
ownership, logged-out session invalidation and a complete WSTG assessment are not
established by this static role replay. The existing row's custom audit-dispatch
and exact HTTP assertions remain internal supporting evidence. No full WSTG pass,
formal certification or external subject pass is claimed before actual CI results.
