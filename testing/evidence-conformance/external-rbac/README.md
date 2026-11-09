# External RBAC assessment: applicability and report accounting

Status: **not integrated and not executed against Busbar**. These files do not
produce an external RBAC pass. `report.py` only accounts for independently judged
ZAP results. The existing internal role/verb matrix remains required.

The external criteria are OWASP WSTG 4.2
[ATHZ-02](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/)
and [ATHZ-03](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation/).
They require checking functions across identities and roles, including vertical
and horizontal authorization and privilege manipulation. They are published
assessment guidance, not an executable certification suite. The proposed
executable judge is the unmodified
[ZAP Access Control addon](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/),
release 13; exact source provenance is in `upstream.json`.

## Proven applicability and upstream limitation

The released scanner clones the historical HTTP request and replays it for each
configured user. Its judge compares detected authorization against the configured
ALLOWED/DENIED access rule, producing VALID, ILLEGAL or UNKNOWN. Method and body
are preserved. Rule keys contain both site-node name and URI; ZAP's site-tree
leaf names include the HTTP method. Thus Busbar's method-sensitive admin API is
not inherently incompatible with this scanner.

However, the release-13 report generator groups results by **URI alone**, then
uses a TreeSet comparator that treats entries for the same user as equal. Later
methods for the same URI are discarded from the exported report. See pinned
[ExtensionAccessControl.java lines 415–441](https://github.com/zaproxy/zap-extensions/blob/e7aaf9014287478da76bdbd56316ea171ee840d3/addOns/accessControl/src/main/java/org/zaproxy/zap/extension/accessControl/ExtensionAccessControl.java#L415).
A normal whole-context HTML report cannot establish complete role/verb coverage.
Zero alerts or a stopped scan are also insufficient: missing historical responses
and request-send errors can omit cells.

The bounded faithful route is **one actual operation per scan context/report**,
with every declared principal in that scan. Retain the upstream scanner and
assertions unchanged. `assess_all` requires the complete declared operation set;
`assess` requires exactly one method/URI row, the exact ordered user roster and
one upstream VALID classification for every cell. Missing, extra, duplicate,
UNKNOWN and ILLEGAL results fail. Labels may be localized; the upstream verdict
class is not translated into a new HTTP-response judge.

## Remaining orchestration before CI can assess the subject

1. Pin a ZAP runtime and released addon archive plus its runtime dependencies by
   digest. `upstream.json` pins inspected source, **not an installed executable**.
2. Boot the isolated real Busbar subject and its actual pinned OIDC plugin using
   the existing rig PKI/JWKS. Record binary/plugin digests, source commit/tree,
   configuration digest and external tool digests with the resulting reports.
3. Derive the full operation roster from admin OpenAPI, retaining the independent
   published scope/verb checks. Include every existing identity: absent, malformed,
   foreign-key, expired, wrong-audience, unbound-role, read-only, verb-granted,
   full, data-key, and the provider-capped variants. Include data-plane and
   admin/data separation cells. Do not silently exclude destructive operations;
   run them against disposable state in a sequence or fresh subjects that permits
   the entire roster to finish.
4. Configure named ZAP users with real Bearer/JWT session transport. Prove the
   transport does not leak a seed request's Authorization into another identity,
   and preserve fresh-subject/rate-bucket behavior. This adapter does not yet
   implement authentication/session management or context import.
5. Seed each exact method/body request into ZAP history, including a response.
   Import explicit ALLOWED/DENIED rules for every user and the method-bearing
   site-node leaf. Configure upstream authorization detection for actual denial
   responses. Preserve the rule/context export and ordered user-ID roster. Use
   separate operation contexts so the upstream report cannot discard methods.
6. Use the addon scan API; enforce a bounded deadline and process cleanup. Retain
   a distinct upstream HTML report per operation, then call `assess_all` with the
   complete expected roster. Run valid and deliberately broken controls through
   this same upstream judge; require the broken control to be ILLEGAL for the
   actual violated rule, not merely a scanner/transport error.
7. Keep the existing internal exact 401/403/error-code assertions. ZAP's upstream
   authorization judge is binary; it does not independently prove those details.
   WSTG horizontal ownership and privilege-parameter manipulation require explicit
   application scenarios; a static role replay alone does not complete ATHZ-02/03.
   Report any inapplicable ownership model with its configuration rationale.

No broad WSTG pass, OWASP certification, or complete RBAC claim is supported by
this partial adapter. Full execution belongs in actual CI after orchestration is
implemented. Locally only the report adapter tests run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s testing/evidence-conformance/external-rbac -p test_report.py -v
```
