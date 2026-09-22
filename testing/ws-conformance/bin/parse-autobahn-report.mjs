#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// Reads Autobahn|Testsuite's `index.json` (the fuzzingclient's per-agent, per-case summary) and
// decides pass/fail, then (optionally) writes a `verdict.json` in the schema
// `docs/design/... CONFORMANCE-SYNC-DESIGN.md` §2 defines for every conformance suite's
// aggregator to publish.
//
// THE RULE: any case whose `behavior` is not `OK` is RED, with one allow-listed exception
// (`INFORMATIONAL` — Autobahn's own "no verdict, informational only" cases, e.g. reserved-bits
// cases some peers legitimately treat differently). `NON-STRICT` is RED, not a warning: it means
// the peer diverged from the strict reading of the spec, and a suite that treated that as a pass
// would be grading on a curve nobody asked for.
//
// FLOOR: an empty report (no agents, or an agent with zero cases) is RED. A suite that returns
// vacuously green over a run that tested nothing is the exact failure mode
// `testing/verdict-covers-every-leg.py`'s docstring is about, one level down: the aggregator
// trusted a leg that "passed" by not running.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ALLOWED_BEHAVIORS = new Set(['OK', 'INFORMATIONAL']);

/**
 * @param {object} report Autobahn's parsed `index.json`.
 * @returns {{ ok: boolean, totalCases: number, failures: Array<{agent:string, case:string, behavior:string}> }}
 */
export function judge(report) {
  const failures = [];
  let totalCases = 0;
  const agents = Object.keys(report ?? {});
  for (const agent of agents) {
    const cases = report[agent] ?? {};
    for (const [caseId, result] of Object.entries(cases)) {
      totalCases += 1;
      const behavior = result?.behavior ?? 'MISSING';
      if (!ALLOWED_BEHAVIORS.has(behavior)) {
        failures.push({ agent, case: caseId, behavior });
      }
    }
  }
  // FLOOR: zero agents, or an agent that ran zero cases, is refused rather than accepted.
  if (agents.length === 0 || totalCases === 0) {
    failures.push({ agent: '(none)', case: '(none)', behavior: 'EMPTY_REPORT' });
  }
  return { ok: failures.length === 0, totalCases, failures };
}

export function buildVerdict({ status, armed, commit, runId, evidence, generatedAt }) {
  return {
    schema: 'busbar.conformance.verdict/1',
    suite: 'ws',
    standard: 'RFC 6455 WebSocket Protocol (Autobahn|Testsuite)',
    plan: 'Autobahn|Testsuite fuzzingclient, full default case set',
    spec_version: 'autobahn-testsuite 0.8.2',
    status,
    armed,
    commit: commit ?? null,
    run_id: runId ?? null,
    evidence: evidence ?? null,
    generated_at: generatedAt ?? new Date().toISOString(),
  };
}

function main(argv) {
  if (argv.includes('--selftest')) {
    return selftest();
  }
  const reportIdx = argv.indexOf('--report');
  const outIdx = argv.indexOf('--out');
  if (reportIdx === -1) {
    console.error('usage: parse-autobahn-report.mjs --report <index.json> [--out verdict.json] [--armed true|false] [--commit sha] [--run-id url] [--evidence uri]');
    return 2;
  }
  const reportPath = argv[reportIdx + 1];
  let report;
  try {
    report = JSON.parse(readFileSync(reportPath, 'utf8'));
  } catch (e) {
    console.error(`could not read/parse ${reportPath}: ${e.message}`);
    report = null;
  }
  const { ok, totalCases, failures } = report ? judge(report) : { ok: false, totalCases: 0, failures: [{ agent: '(none)', case: '(none)', behavior: 'UNREADABLE_REPORT' }] };
  const armedArg = (argv[argv.indexOf('--armed') + 1] ?? 'false') === 'true';
  const commit = argv.includes('--commit') ? argv[argv.indexOf('--commit') + 1] : undefined;
  const runId = argv.includes('--run-id') ? argv[argv.indexOf('--run-id') + 1] : undefined;
  const evidence = argv.includes('--evidence') ? argv[argv.indexOf('--evidence') + 1] : undefined;

  // status:"pass" is permitted only if the run judged something AND every subject leg was armed.
  const status = armedArg && ok ? 'pass' : armedArg ? 'fail' : 'not-run';
  const verdict = buildVerdict({ status, armed: armedArg, commit, runId, evidence });

  console.log(`ws-conformance: ${totalCases} case(s) judged, ${failures.length} failure(s)`);
  for (const f of failures.slice(0, 50)) {
    console.log(`  RED  ${f.agent} :: ${f.case} -> ${f.behavior}`);
  }
  if (outIdx !== -1) {
    writeFileSync(argv[outIdx + 1], JSON.stringify(verdict, null, 2) + '\n');
  }
  return status === 'pass' ? 0 : 1;
}

function selftest() {
  let failures = 0;
  const good = judge({
    firefox: {
      '1.1.1': { behavior: 'OK' },
      '1.1.2': { behavior: 'INFORMATIONAL' },
    },
  });
  if (!good.ok) {
    console.log('  MISS: an all-OK report was refused');
    failures += 1;
  } else {
    console.log('  ok: an all-OK report is accepted');
  }

  const bad = judge({
    firefox: {
      '1.1.1': { behavior: 'OK' },
      '2.1.1': { behavior: 'FAILED' },
    },
  });
  if (bad.ok) {
    console.log('  MISS: a report containing FAILED was accepted');
    failures += 1;
  } else {
    console.log('  ok: a report containing FAILED is refused');
  }

  const nonStrict = judge({ firefox: { '3.1.1': { behavior: 'NON-STRICT' } } });
  if (nonStrict.ok) {
    console.log('  MISS: a NON-STRICT case was accepted');
    failures += 1;
  } else {
    console.log('  ok: a NON-STRICT case is refused (no curve)');
  }

  const empty = judge({});
  if (empty.ok) {
    console.log('  MISS: an empty report (zero agents) was accepted -- FLOOR did not bite');
    failures += 1;
  } else {
    console.log('  ok: an empty report is refused (FLOOR)');
  }

  const emptyCases = judge({ firefox: {} });
  if (emptyCases.ok) {
    console.log('  MISS: an agent with zero cases was accepted -- FLOOR did not bite');
    failures += 1;
  } else {
    console.log('  ok: an agent with zero cases is refused (FLOOR)');
  }

  // The armed/status contract: unarmed can never be "pass", regardless of the report.
  const unarmedVerdict = buildVerdict({ status: 'not-run', armed: false });
  if (unarmedVerdict.status === 'pass') {
    console.log('  MISS: an unarmed verdict rendered as pass');
    failures += 1;
  } else {
    console.log('  ok: an unarmed verdict is never pass');
  }

  if (failures) {
    console.error(`\n${failures} selftest fixture(s) did not behave as declared`);
    return 1;
  }
  console.log('selftest: 6 fixture(s) passed');
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(main(process.argv.slice(2)));
}
