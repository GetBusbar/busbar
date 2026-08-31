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

export function compare(controlResults, subjectResults, opts = {}) {
  const control = indexById(controlResults);
  const subject = indexById(subjectResults);
  const ids = [...new Set([...control.keys(), ...subject.keys()])].sort();

  const failures = [];
  const divergences = [];
  const regressions = [];
  const missing = [];

  for (const id of ids) {
    const c = control.get(id);
    const s = subject.get(id);

    if (!s) { missing.push({ id, side: 'subject', title: c && c.title }); continue; }
    if (!c) { missing.push({ id, side: 'control', title: s.title }); continue; }

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
    },
    failures,
    regressions,
    divergences,
    missing,
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
  L.push(`  missing tests : ${report.counts.missing}`);
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
    L.push('MISSING  (a test ran on one side only; usually a filter or version mismatch)');
    L.push('-'.repeat(78));
    for (const m of report.missing) {
      L.push(`  [${m.id}] not present in the ${m.side} run`);
    }
    L.push('');
  }

  L.push('='.repeat(78));
  const gate = report.counts.failures + report.counts.regressions;
  L.push(gate === 0
    ? 'RESULT: no spec failures and no regressions against the control.'
    : `RESULT: ${gate} blocking finding(s). See SPEC FAILURES and REGRESSIONS above.`);
  L.push('='.repeat(78));
  return L.join('\n');
}

export function knownClauseIds() {
  return Object.keys(CLAUSES).sort();
}
