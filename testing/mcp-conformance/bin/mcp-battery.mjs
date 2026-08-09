#!/usr/bin/env node
// Independent MCP conformance battery.
//
//   run      execute the battery against one target, write a result JSON
//   compare  diff a control result against a subject result
//   list     list every test with its tier, role and the defect it catches
//
// The harness knows nothing about any particular implementation. A target is a
// launch command supplied on the command line or in the environment.

import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { runAll, allTests, VERDICT } from '../src/core/runner.mjs';
import { Target } from '../src/core/target.mjs';
import { compare, renderDifferential } from '../src/core/differential.mjs';
import { REVISION } from '../src/core/spec.mjs';

// Registering the suites is what populates the test registry.
import '../src/suites/server-conformance.mjs';
import '../src/suites/server-adversarial.mjs';
import '../src/suites/server-concurrency.mjs';
import '../src/suites/client-role.mjs';
import '../src/suites/seam.mjs';

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) out[a.slice(2, eq)] = a.slice(eq + 1);
      else if (argv[i + 1] && !argv[i + 1].startsWith('--')) out[a.slice(2)] = argv[++i];
      else out[a.slice(2)] = true;
    } else out._.push(a);
  }
  return out;
}

function usage() {
  console.log(`
Independent MCP conformance battery  (protocol revision ${REVISION})

  mcp-battery run --name NAME [--server-cmd CMD] [--client-cmd CMD] [options]
  mcp-battery compare --control FILE --subject FILE [--fail-on-divergence]
  mcp-battery list [--tier push|pr|prerelease]

run options
  --name NAME            label for the report                (env MCP_SUBJECT_NAME)
  --server-cmd CMD       launch the subject as an MCP server (env MCP_SUBJECT_SERVER_CMD)
  --client-cmd CMD       launch the subject as an MCP client (env MCP_SUBJECT_CLIENT_CMD)
  --failing-tool NAME    a tool that always fails            (env MCP_SUBJECT_FAILING_TOOL)
  --tier TIER            push | pr | prerelease  (default: push,pr)
  --area AREAS           comma list: conformance,adversarial,hostile,concurrency,seam
  --role ROLES           comma list: server,client,seam
  --only SUBSTR          run only tests whose id contains SUBSTR
  --out FILE             write the result JSON here
  --quiet                summary only

exit codes
  0  no failing tests
  1  at least one test FAILED or ERRORED
  2  the target was not runnable at all (nothing was tested)
`);
}

function summarise(results) {
  const by = { PASS: 0, FAIL: 0, SKIP: 0, ERROR: 0 };
  for (const r of results) by[r.verdict] = (by[r.verdict] || 0) + 1;
  return by;
}

function renderRun(results, target, quiet) {
  const L = [];
  const by = summarise(results);
  if (!quiet) {
    for (const r of results) {
      const mark = { PASS: 'PASS', FAIL: 'FAIL', SKIP: 'SKIP', ERROR: 'ERR ' }[r.verdict];
      L.push(`  ${mark}  [${r.tier.padEnd(10)}] ${r.id}`);
      if (r.verdict === 'FAIL') {
        for (const a of r.assertions.filter((x) => !x.ok)) {
          L.push(`          clause ${a.clause} (${a.level}) : ${a.detail}`);
          L.push(`          spec: ${a.url}`);
        }
      }
      if (r.verdict === 'ERROR') L.push(`          ${String(r.error).split('\n')[0]}`);
      if (r.verdict === 'SKIP') L.push(`          skipped: ${r.error}`);
    }
    L.push('');
  }
  L.push(`target      : ${target.name}`);
  L.push(`revision    : ${REVISION}`);
  L.push(`server role : ${target.hasServerRole ? target.serverLaunch : 'NOT CONFIGURED'}`);
  L.push(`client role : ${target.hasClientRole ? target.clientLaunch : 'NOT CONFIGURED'}`);
  L.push(`results     : ${by.PASS} pass, ${by.FAIL} fail, ${by.ERROR} error, ${by.SKIP} skip`);
  return L.join('\n');
}

async function cmdRun(args) {
  const target = new Target({
    name: args.name || process.env.MCP_SUBJECT_NAME || 'unnamed',
    serverLaunch: args['server-cmd'] || process.env.MCP_SUBJECT_SERVER_CMD || null,
    clientLaunch: args['client-cmd'] || process.env.MCP_SUBJECT_CLIENT_CMD || null,
    failingTool: args['failing-tool'] || process.env.MCP_SUBJECT_FAILING_TOOL || null,
    sampleCallFor: args['sample-calls']
      ? JSON.parse(args['sample-calls'])
      : (process.env.MCP_SUBJECT_SAMPLE_CALLS
        ? JSON.parse(process.env.MCP_SUBJECT_SAMPLE_CALLS) : null),
  });

  if (!target.hasServerRole && !target.hasClientRole) {
    console.error(`
FATAL: no target configured. Nothing was tested.

This gate refuses to pass vacuously. Supply at least one of:
  --server-cmd "<command that starts the subject as an MCP server on stdio>"
  --client-cmd "<command that starts the subject as an MCP client>"
or set MCP_SUBJECT_SERVER_CMD / MCP_SUBJECT_CLIENT_CMD.
`);
    process.exit(2);
  }

  const filter = {};
  const tier = args.tier || 'push,pr';
  filter.tiers = tier === 'all' ? ['push', 'pr', 'prerelease'] : String(tier).split(',');
  if (args.area) filter.areas = String(args.area).split(',');
  if (args.role) filter.roles = String(args.role).split(',');
  if (args.only) filter.only = String(args.only).split(',');
  if (!target.hasServerRole) {
    filter.roles = (filter.roles || ['server', 'client', 'seam']).filter((r) => r !== 'server');
  }
  if (!target.hasClientRole) {
    filter.roles = (filter.roles || ['server', 'client', 'seam']).filter((r) => r !== 'client');
  }

  const started = new Date().toISOString();
  const results = await runAll(target, filter);
  const payload = {
    harnessVersion: '1.0.0',
    revision: REVISION,
    target: target.toJSON(),
    startedAt: started,
    filter,
    results,
  };

  const outPath = args.out ? resolve(args.out) : null;
  if (outPath) {
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, JSON.stringify(payload, null, 2));
  }

  console.log(renderRun(results, target, Boolean(args.quiet)));
  if (outPath) console.log(`written     : ${outPath}`);

  const by = summarise(results);
  if (results.length === 0) {
    console.error('\nFATAL: zero tests selected. This gate refuses to pass vacuously.');
    process.exit(2);
  }

  // Expected-failure baseline. Every entry is a KNOWN, DOCUMENTED deviation of
  // the target from the spec. It keeps a gate green without hiding the
  // deviation, and it reports an UNEXPECTED PASS when the target is fixed so
  // the entry gets deleted rather than rotting.
  let expected = new Set();
  let baseline = null;
  if (args['expected-failures']) {
    baseline = JSON.parse(readFileSync(resolve(args['expected-failures']), 'utf8'));
    expected = new Set((baseline.expectedFailures || []).map((e) => e.testId));
  }

  const failedIds = results.filter((r) => r.verdict === 'FAIL' || r.verdict === 'ERROR')
    .map((r) => r.id);
  const unexpectedFailures = failedIds.filter((id) => !expected.has(id));
  const unexpectedPasses = [...expected].filter((id) => {
    const r = results.find((x) => x.id === id);
    return r && r.verdict === 'PASS';
  });

  // Pinned observations: spec-ambiguous behaviour the battery deliberately
  // RECORDS rather than asserts. Pinning the control's observed choice means
  // an ambiguity record cannot silently flip, silently start passing, or
  // silently grow. Any drift is a build failure that forces the documented
  // analysis to be revisited.
  const pinDrift = [];
  const stalePins = [];
  let pinsChecked = 0;
  if (baseline && Array.isArray(baseline.pinnedObservations)) {
    const registryIds = new Set(allTests().map((t) => t.id));
    for (const p of baseline.pinnedObservations) {
      // A pin naming a test that no longer exists is a STALE PIN: the test was
      // renamed or deleted and the recorded ambiguity silently stopped being
      // checked. That is exactly the rot this mechanism exists to prevent.
      if (!registryIds.has(p.testId)) { stalePins.push(p); continue; }
      const r = results.find((x) => x.id === p.testId);
      // Not selected by this run's tier/area filter: legitimately absent, not
      // drift. The full-tier run is what checks it.
      if (!r) continue;
      if (r.verdict === 'SKIP') continue;   // nothing observed; not a drift
      pinsChecked += 1;
      const v = r.variance.find((x) => x.key === p.variancePoint);
      const actual = v ? v.value : '<variance point not recorded>';
      if (JSON.stringify(actual) !== JSON.stringify(p.expectedValue)) {
        pinDrift.push({ ...p, actual });
      }
    }
  }

  if (baseline) {
    console.log(`baseline    : ${resolve(args['expected-failures'])}`);
    console.log(`              ${expected.size} enumerated deviation(s) and `
      + `${(baseline.pinnedObservations || []).length} pinned observation(s) of ${baseline.control}`);
    for (const id of failedIds.filter((i) => expected.has(i))) {
      const e = baseline.expectedFailures.find((x) => x.testId === id);
      console.log(`  KNOWN DEVIATION ${id}`);
      console.log(`    clause    : ${e.clause}`);
      console.log(`    judgement : ${e.judgement.split('.')[0]}.`);
    }
    for (const id of unexpectedPasses) {
      console.log(`  UNEXPECTED PASS ${id}: this deviation is fixed. Delete it from the baseline.`);
    }
    if (pinDrift.length === 0 && stalePins.length === 0) {
      console.log(`  pinned observations: ${pinsChecked} checked, all match`
        + ` (${(baseline.pinnedObservations || []).length} pinned, rest not selected by this tier)`);
    }
    for (const p of stalePins) {
      console.error(`  STALE PIN ${p.testId} / ${p.variancePoint}`);
      console.error('    No test with this id exists. It was renamed or deleted, so the');
      console.error(`    recorded ambiguity ${p.ambiguity} silently stopped being checked.`);
    }
    for (const p of pinDrift) {
      console.error(`  PINNED OBSERVATION DRIFT ${p.testId} / ${p.variancePoint}`);
      console.error(`    ambiguity : ${p.ambiguity}`);
      console.error(`    expected  : ${JSON.stringify(p.expectedValue)}`);
      console.error(`    actual    : ${JSON.stringify(p.actual)}`);
      console.error('    This is spec-ambiguous behaviour whose recorded value changed.');
      console.error('    Revisit the documented analysis before updating the pin.');
    }
  }

  if (unexpectedFailures.length) {
    console.error(`\nunexpected failures: ${unexpectedFailures.join(', ')}`);
  }
  const blocking = unexpectedFailures.length + unexpectedPasses.length
    + pinDrift.length + stalePins.length;
  process.exit(blocking > 0 ? 1 : 0);
}

function cmdCompare(args) {
  if (!args.control || !args.subject) {
    console.error('FATAL: compare needs --control FILE and --subject FILE');
    process.exit(2);
  }
  const c = JSON.parse(readFileSync(resolve(args.control), 'utf8'));
  const s = JSON.parse(readFileSync(resolve(args.subject), 'utf8'));
  const report = compare(c.results, s.results, {
    controlName: c.target.name,
    subjectName: s.target.name,
  });
  console.log(renderDifferential(report));
  if (args.out) {
    mkdirSync(dirname(resolve(args.out)), { recursive: true });
    writeFileSync(resolve(args.out), JSON.stringify(report, null, 2));
  }
  const blocking = report.counts.failures + report.counts.regressions
    + (args['fail-on-divergence'] ? report.counts.divergences : 0);
  process.exit(blocking > 0 ? 1 : 0);
}

function cmdList(args) {
  const tests = allTests().filter((t) => !args.tier || t.tier === args.tier);
  const rows = tests.map((t) => ({
    id: t.id, tier: t.tier, role: t.role, area: t.area, peer: t.peer,
    timing: t.timing ? 'TIMING' : '', catches: t.catches,
  }));
  for (const r of rows) {
    console.log(`${r.tier.padEnd(11)} ${r.role.padEnd(7)} ${r.area.padEnd(12)} ${r.peer.padEnd(5)} ${r.timing.padEnd(7)} ${r.id}`);
    console.log(`${' '.repeat(45)}catches: ${r.catches}`);
  }
  console.log(`\n${rows.length} tests`);
}

const args = parseArgs(process.argv.slice(2));
const cmd = args._[0];
if (cmd === 'run') await cmdRun(args);
else if (cmd === 'compare') cmdCompare(args);
else if (cmd === 'list') cmdList(args);
else { usage(); process.exit(args._.length ? 2 : 0); }
