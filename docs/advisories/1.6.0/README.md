# 1.6.0 advisories

These are shipped-behavior and billing-correctness disclosures gathered for the 1.6.0 release —
distinct from [`docs/security/advisories/`](../security/advisories/), which (where that
directory exists on a given branch) tracks confirmed security vulnerabilities disclosed per
[SECURITY.md](../../SECURITY.md)'s severity/backport process. None of the four items below is a
SECURITY.md-scoped vulnerability; each says so explicitly and states why.

| Id | Title | Classification |
|---|---|---|
| ADV-1.6.0-1 | [Voice/streams session fee draws once per session](voice-session-fee-draws-once-per-session.md) | Billing behavior change (fee previously never drawn) |
| ADV-1.6.0-2 | [MySQL store split-flush request-count loss](mysql-store-split-flush-request-count-loss.md) | Store-backend billing/rate-cap integrity defect, fixed as a contract change |
| ADV-1.6.0-3 | [Upstream 429 answered to the client as 503](upstream-429-answered-as-503.md) | Working-as-designed circuit-breaker behavior, not a defect |
| ADV-1.6.0-4 | [Refund-across-window unrecordable (no key-level billing window)](refund-across-window-unrecordable.md) | Measurement gap tracing to an open product question; no defect |

Each advisory states its affected versions, its evidence (file:line and/or commit sha), and
either a fix commit or an explicit "no fix proposed" / "owner decision open" line. Where the
ledger this was compiled from had no ruling on a question, the advisory says "not found" rather
than inferring one.

See also: [the 1.6.0 migration guide](../../migration-1.6.md), section 3, "What you will notice
after the upgrade," for the operator-facing summary these advisories back.
