// Differential comparison: control run vs subject run.
//
// Three distinct outcomes, and keeping them apart is the entire point:
//
//   FAILURE     a MUST-level assertion failed. This is a defect regardless of
//               what the control did. Cited to a spec clause.
//
//   DIVERGENCE  both sides are spec-legal but they behave differently at a
//               variance point. NOT a failure. A lead for a human, with the
//               governing clause named as "none" so nobody mistakes it for a
//               conformance breach.
//
//   REGRESSION  the control passed a test that the subject failed. This is the
//               strongest signal the harness produces, because the control
//               proves the test is satisfiable.
//
// A harness that reports every legal difference as a failure gets muted within
// a week, so DIVERGENCE never affects the exit code by default.

import { CLAUSES } from './spec.mjs';

function indexById(results) {
  return new Map(results.map((r) => [r.id, r]));
}

function failedAssertions(record) {
  return record.assertions.filter((a) => !a.ok);
}

function varianceMap(record) {
  const m = new Map();
  for (const v of record.variance) m.set(v.key, v.value);
  return m;
}

// A MISSING ROW IS A ROW NOBODY RAN, AND IT COUNTS.
//
// THE DEFECT THIS REPLACES. `missing` was counted, rendered, and then left OUT of the exit-code
// gate: `blocking = failures + regressions`. A control run of 63 scenarios against a subject run of
// 15 therefore printed `missing tests : 48` and exited 0 — a differential whose whole claim is
// "the control proves these scenarios are passable" reporting success while three quarters of them
// were never put to the subject at all. That is the same false green as an unarmed leg, arriving
// through the comparison instead of through the run.
//
// THE ONE LEGITIMATE MISSING ROW, and it must be DECLARED rather than assumed. A side that did not
// measure a ROLE cannot have rows for it: the python control has no seam direction, a subject armed
// only as a server has no CLI.* rows. Both runs already record `roleAudit.selected` — the roles the
// run actually measured, written by the run itself — so a missing row whose role was not measured
// by the side that lacks it is EXPLAINED: still listed, still counted separately, not blocking.
// Anything else blocks. A side with no roleAudit at all (an old report) explains nothing.
function explainMissing(role, side, roleAudit) {
  if (!roleAudit || !Array.isArray(roleAudit.selected)) return null;
  if (roleAudit.selected.includes(role)) return null;
  const why = (roleAudit.unarmed || []).includes(role)
    ? `the ${side} run did not ARM the ${role} role`
    : `the ${side} run was narrowed with --role and did not request ${role}`;
  return why;
}

export function compare(controlResults, subjectResults, opts = {}) {
  const control = indexById(controlResults);
  const subject = indexById(subjectResults);
  const ids = [...new Set([...control.keys(), ...subject.keys()])].sort();

  const failures = [];
  const divergences = [];
  const regressions = [];
  const missing = [];
  const explained = [];

  for (const id of ids) {
    const c = control.get(id);
    const s = subject.get(id);

    if (!s || !c) {
      const side = s ? 'control' : 'subject';
      const present = s || c;
      const audit = side === 'subject' ? opts.subjectRoleAudit : opts.controlRoleAudit;
      const reason = explainMissing(present.role, side, audit);
      const row = { id, side, title: present.title, role: present.role, reason };
      if (reason) explained.push(row); else missing.push(row);
      continue;
    }

    // 1. MUST-level failures on the subject, cited.
    for (const a of failedAssertions(s)) {
      failures.push({
        testId: id,
        title: s.title,
        catches: s.catches,
        clause: a.clause,
        level: a.level,
        specUrl: a.url,
        specQuote: a.quote,
        detail: a.detail,
        controlSatisfiedSameClause: !failedAssertions(c).some((x) => x.clause === a.clause),
      });
    }

    // 2. Regression: control green, subject not.
    if (c.verdict === 'PASS' && (s.verdict === 'FAIL' || s.verdict === 'ERROR')) {
      regressions.push({
        testId: id,
        title: s.title,
        catches: s.catches,
        controlVerdict: c.verdict,
        subjectVerdict: s.verdict,
        subjectError: s.error,
        failedClauses: failedAssertions(s).map((a) => a.clause),
      });
    }

    // 3. Divergence at spec-permitted variance points.
    const cv = varianceMap(c);
    const sv = varianceMap(s);
    for (const key of new Set([...cv.keys(), ...sv.keys()])) {
      const a = cv.has(key) ? cv.get(key) : '<not recorded>';
      const b = sv.has(key) ? sv.get(key) : '<not recorded>';
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        divergences.push({
          testId: id,
          title: c.title,
          variancePoint: key,
          controlValue: a,
          subjectValue: b,
          // The honest answer for a variance point is almost always "none".
          // Saying so explicitly stops readers treating it as a breach.
          governingClause: opts.clauseForVariance && opts.clauseForVariance[key]
            ? opts.clauseForVariance[key]
            : 'none (spec permits variation here)',
        });
      }
    }
  }

  return {
    controlName: opts.controlName || 'control',
    subjectName: opts.subjectName || 'subject',
    counts: {
      failures: failures.length,
      regressions: regressions.length,
      divergences: divergences.length,
      missing: missing.length,
      explainedMissing: explained.length,
    },
    failures,
    regressions,
    divergences,
    missing,
    explainedMissing: explained,
  };
}

export function renderDifferential(report) {
  const L = [];
  L.push('='.repeat(78));
  L.push(`DIFFERENTIAL REPORT   control=${report.controlName}   subject=${report.subjectName}`);
  L.push('='.repeat(78));
  L.push('');
  L.push(`  spec failures : ${report.counts.failures}`);
  L.push(`  regressions   : ${report.counts.regressions}  (control passed, subject did not)`);
  L.push(`  divergences   : ${report.counts.divergences}  (both legal, behaviour differs)`);
  L.push(`  missing tests : ${report.counts.missing}  (ran on one side only, UNEXPLAINED — blocking)`);
  L.push(`  explained     : ${report.counts.explainedMissing || 0}  (absent because that side did not measure the role)`);
  L.push('');

  if (report.failures.length) {
    L.push('-'.repeat(78));
    L.push('SPEC FAILURES  (a MUST-level clause was violated)');
    L.push('-'.repeat(78));
    for (const f of report.failures) {
      L.push('');
      L.push(`  [${f.testId}] ${f.title}`);
      L.push(`    catches      : ${f.catches}`);
      L.push(`    clause       : ${f.clause}  (${f.level})`);
      L.push(`    spec says    : "${f.specQuote}"`);
      L.push(`    spec url     : ${f.specUrl}`);
      L.push(`    detail       : ${f.detail}`);
      L.push(`    control ok?  : ${f.controlSatisfiedSameClause ? 'YES - the control satisfies this clause, so the test is satisfiable' : 'NO - the control fails it too; suspect the TEST or the SPEC READING'}`);
    }
    L.push('');
  }

  if (report.regressions.length) {
    L.push('-'.repeat(78));
    L.push('REGRESSIONS  (strongest signal: the control proves this test is passable)');
    L.push('-'.repeat(78));
    for (const r of report.regressions) {
      L.push('');
      L.push(`  [${r.testId}] ${r.title}`);
      L.push(`    catches       : ${r.catches}`);
      L.push(`    control       : ${r.controlVerdict}`);
      L.push(`    subject       : ${r.subjectVerdict}`);
      if (r.failedClauses.length) L.push(`    clauses failed: ${r.failedClauses.join(', ')}`);
      if (r.subjectError) L.push(`    error         : ${String(r.subjectError).split('\n')[0]}`);
    }
    L.push('');
  }

  if (report.divergences.length) {
    L.push('-'.repeat(78));
    L.push('DIVERGENCES  (both spec-legal. NOT failures. Human review, not a gate.)');
    L.push('-'.repeat(78));
    for (const d of report.divergences) {
      L.push('');
      L.push(`  [${d.testId}] ${d.variancePoint}`);
      L.push(`    control  : ${JSON.stringify(d.controlValue)}`);
      L.push(`    subject  : ${JSON.stringify(d.subjectValue)}`);
      L.push(`    governed by: ${d.governingClause}`);
    }
    L.push('');
  }

  if (report.missing.length) {
    L.push('-'.repeat(78));
    L.push('MISSING  (a test ran on ONE SIDE ONLY and nothing explains it. BLOCKING: a scenario');
    L.push('          the control passed and the subject never ran is not a scenario the subject');
    L.push('          passed. Arm the role, narrow BOTH runs the same way, or fix the filter.)');
    L.push('-'.repeat(78));
    for (const m of report.missing) {
      L.push(`  [${m.id}] (role ${m.role}) not present in the ${m.side} run`);
    }
    L.push('');
  }

  if (report.explainedMissing && report.explainedMissing.length) {
    L.push('-'.repeat(78));
    L.push('EXPLAINED ABSENCES  (that side did not measure the role, and said so in its report)');
    L.push('-'.repeat(78));
    for (const m of report.explainedMissing) {
      L.push(`  [${m.id}] absent from the ${m.side} run: ${m.reason}`);
    }
    L.push('');
  }

  L.push('='.repeat(78));
  const gate = report.counts.failures + report.counts.regressions + report.counts.missing;
  L.push(gate === 0
    ? 'RESULT: no spec failures, no regressions, and every scenario ran on both sides.'
    : `RESULT: ${gate} blocking finding(s). See SPEC FAILURES, REGRESSIONS and MISSING above.`);
  L.push('='.repeat(78));
  return L.join('\n');
}

export function knownClauseIds() {
  return Object.keys(CLAUSES).sort();
}
