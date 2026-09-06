// Test registry and runner.
//
// THE CENTRAL DESIGN DECISION OF THIS HARNESS:
//
//   assert(...)   a spec clause says the behaviour is mandatory. Deviation is
//                 a FAILURE, against the control or against any subject.
//                 Must cite a clause id from spec.mjs.
//
//   variance(...) the spec permits more than one legal behaviour here. We
//                 RECORD the value and never fail on it. The differential
//                 comparison diffs variance points between control and subject
//                 and raises a DIVERGENCE for a human to read.
//
// A differential harness that fails on every legal difference gets switched
// off within a week. The whole value is in keeping these two apart.

import { cite } from './spec.mjs';

export const VERDICT = {
  PASS: 'PASS',
  FAIL: 'FAIL',
  SKIP: 'SKIP',
  ERROR: 'ERROR',
  // Not run because the CALLER's --tier did not select it -- as opposed to SKIP, which is the
  // TEST deciding at run time that it could not reach its surface. A tier default is a coverage
  // decision made before the battery ever starts, and it must leave the same kind of trace a
  // SKIP does, or the scenario silently leaves the denominator: see EXCLUDED_TIER below.
  EXCLUDED_TIER: 'EXCLUDED_TIER',
};

const registry = [];

/**
 * Define a test.
 *
 * @param {object} def
 *  id        stable identifier, used to line up control and subject runs
 *  title     one line
 *  role      'server' (subject acts as MCP server) | 'client' | 'seam'
 *  area      conformance | adversarial | hostile | concurrency | seam | interop
 *  tier      'push' | 'pr' | 'prerelease'   -- CI cost tier
 *  peer      'fake' | 'real'  -- does it need a real implementation?
 *  catches   ONE LINE: what defect or breaking change this catches.
 *  timing    true if it depends on a quiet period / wall clock. Default false.
 *  transports ['stdio'] | ['http'] | ['stdio','http']
 *  run       async (ctx) => void
 */
export function test(def) {
  if (!def.id) throw new Error('test needs an id');
  if (!def.catches) throw new Error(`test ${def.id} needs a "catches" line`);
  if (registry.some((t) => t.id === def.id)) {
    throw new Error(`duplicate test id: ${def.id}`);
  }
  registry.push({
    tier: 'pr',
    peer: 'fake',
    timing: false,
    transports: ['stdio'],
    // WHICH SCENARIOS OWE POSITIVE EVIDENCE. The client role is observed ENTIRELY through what the
    // subject volunteers onto the wire — nothing in it is a request/response exchange the harness
    // can force — so a client scenario's row is meaningless without a recorded observation that the
    // subject acted. Server and seam scenarios drive the subject and assert on its answers, so
    // their absence rows already cannot be satisfied by silence. Any scenario may opt in.
    requiresEvidence: def.role === 'client',
    ...def,
  });
}

export function allTests() {
  return registry.slice();
}

class Ctx {
  constructor(target, record) {
    this.target = target;
    this._record = record;
  }

  /** Spec-mandated. Fails the test if false. */
  assert(clauseId, condition, detail) {
    const c = cite(clauseId);
    const ok = Boolean(condition);
    this._record.assertions.push({
      clause: c.id,
      level: c.level,
      url: c.url,
      quote: c.quote,
      ok,
      detail: detail === undefined ? null : detail,
    });
    if (!ok) this._record.failed = true;
  }

  /**
   * Spec-permitted variation. Never fails. Recorded for differential diffing.
   * `key` must be stable across runs; `value` must be JSON-serialisable and
   * deterministic (no timestamps, no pids, no random ids).
   */
  variance(key, value, note) {
    this._record.variance.push({
      key,
      value: value === undefined ? null : value,
      note: note || null,
    });
  }

  /** Our own opinion. Advisory only, never fails, never diffed as a defect. */
  recommend(key, ok, text) {
    this._record.recommendations.push({ key, ok: Boolean(ok), text });
  }

  /** Free-form evidence attached to the report so a human can read the wire. */
  note(key, value) {
    this._record.notes.push({ key, value });
  }

  // A SCENARIO MUST ASSERT SOMETHING THE SUBJECT DID.
  //
  // THE DEFECT THIS REPLACES. `/usr/bin/true` — a subject that connects to nothing, sends nothing
  // and exits — scored 9 PASS out of 14 in the client role. Every one of those nine was an ABSENCE
  // row: "the client sent no forbidden responses", "the client answered no server-initiated
  // request", "the client emitted no unparseable frames". All true of a program that did nothing at
  // all, so the row's verdict was a statement about the subject's silence and rendered as a
  // statement about its conformance. Two more rows recommended on a literal `true`.
  //
  // THE RULE NOW. Every scenario declares, with this call, the OBSERVATION that makes its absence
  // row mean anything: the stimulus reached the subject, and the subject acted. A scenario that
  // records no satisfied evidence cannot pass — it FAILS as vacuous, by name, with the same
  // reasoning as `MCP_NO_SKIPS`: a row nobody could have failed is not a row anybody passed.
  //
  // It is recorded as an assertion so it travels into the report, the differential and the
  // regression comparison exactly like every other assertion, and so a reader of a red sees the
  // sentence "the stimulus was never delivered" rather than a bare count.
  evidence(key, condition, detail) {
    this._record.evidence.push({
      key,
      ok: Boolean(condition),
      detail: detail === undefined ? null : detail,
    });
  }

  // A SKIPPING TEST IS NOT A PASSING TEST.
  //
  // A skip is honest about one thing only: this run could not reach the surface the test is
  // about. That is the right report when the harness is being exercised for its own sake. It is
  // the WRONG report when the run is a RELEASE GATE, because the gate's reader sees a green tick
  // over a surface nobody touched, and "we never tested the seam" becomes indistinguishable from
  // "the seam is correct".
  //
  // So under MCP_NO_SKIPS=1 the same unavailability is recorded as a FAILURE, by name, with the
  // reason the test would have skipped for. The subject leg sets it; the control and
  // negative-control legs do not, because there the skips are the harness telling the truth about
  // a peer it was never pointed at.
  skip(reason) {
    if (process.env.MCP_NO_SKIPS === '1') {
      const e = new Error(
        'UNAVAILABLE, and MCP_NO_SKIPS=1 refuses to report that as a skip. '
        + 'The surface this test covers was NOT tested by this run, and this run is a gate. '
        + 'Original skip reason: ' + reason,
      );
      e.__unavailable = true;
      throw e;
    }
    const e = new Error(reason);
    e.__skip = true;
    throw e;
  }
}

export async function runOne(t, target) {
  const record = {
    id: t.id,
    title: t.title,
    role: t.role,
    area: t.area,
    tier: t.tier,
    peer: t.peer,
    timing: Boolean(t.timing),
    catches: t.catches,
    assertions: [],
    variance: [],
    recommendations: [],
    notes: [],
    evidence: [],
    requiresEvidence: Boolean(t.requiresEvidence),
    failed: false,
    verdict: VERDICT.PASS,
    error: null,
  };
  const ctx = new Ctx(target, record);
  try {
    await t.run(ctx);
    // THE VACUITY GATE. See Ctx.evidence. A scenario that requires evidence and satisfied none of
    // it did not observe the subject doing anything, so its verdict is about silence.
    const unmet = record.evidence.filter((e) => !e.ok);
    if (record.requiresEvidence && (record.evidence.length === 0 || unmet.length > 0)) {
      record.failed = true;
      record.error = 'VACUOUS: a PASS here would be a statement about silence, not about the '
        + 'subject. ' + (record.evidence.length
          ? `Evidence not satisfied: ${unmet.map((e) => `${e.key}${e.detail ? ` — ${e.detail}` : ''}`).join('; ')}`
          : 'The scenario declared NO evidence at all, which is a defect in the SCENARIO, not in '
            + 'the subject: it can be passed by a subject that does nothing.');
    }
    record.verdict = record.failed ? VERDICT.FAIL : VERDICT.PASS;
  } catch (err) {
    if (err && err.__unavailable) {
      // Deliberately FAIL and not ERROR: ERROR reads as "the harness broke", and the harness did
      // not break. The subject could not be driven through this surface, which is a finding about
      // the subject's readiness, and it must be counted alongside every other failure.
      record.verdict = VERDICT.FAIL;
      record.failed = true;
      record.error = err.message;
    } else if (err && err.__skip) {
      record.verdict = VERDICT.SKIP;
      record.error = err.message;
    } else {
      record.verdict = VERDICT.ERROR;
      record.error = err && err.stack ? err.stack : String(err);
    }
  }
  return record;
}

// Filters OTHER than tier: a deliberate, requested narrowing (--area, --role, --only, transport).
// Tier is handled separately below, because an EXCLUDED-by-tier scenario still has to be reported
// -- these other filters are asked for on the command line and are already visible there.
function passesNonTierFilter(t, filter) {
  if (filter.areas && !filter.areas.includes(t.area)) return false;
  if (filter.roles && !filter.roles.includes(t.role)) return false;
  if (filter.transport && !t.transports.includes(filter.transport)) return false;
  if (filter.only && !filter.only.some((p) => t.id.includes(p))) return false;
  return true;
}

function excludedByTierRecord(t, filter) {
  return {
    id: t.id,
    title: t.title,
    role: t.role,
    area: t.area,
    tier: t.tier,
    peer: t.peer,
    timing: Boolean(t.timing),
    catches: t.catches,
    assertions: [],
    variance: [],
    recommendations: [],
    notes: [],
    failed: false,
    verdict: VERDICT.EXCLUDED_TIER,
    error: `excluded by --tier ${filter.tiers.join(',')}: this scenario is tier '${t.tier}'`,
  };
}

export async function runAll(target, filter = {}) {
  const results = [];
  for (const t of allTests()) {
    if (!passesNonTierFilter(t, filter)) continue;
    // A SCENARIO A TIER DEFAULT LEAVES OUT STILL APPEARS IN THE VERDICT.
    //
    // This used to be a plain `.filter()` that dropped a tier-excluded scenario before it ever
    // became a result: it left no row, no verdict, and no line in any count. A `prerelease`-tier
    // scenario run under the push/pr default (run-subject.sh's MCP_TIER) then vanished from the
    // denominator exactly like the unarmed-role hole this harness already refuses elsewhere --
    // except with no SKIP, no FAIL, and nothing to grep for. Recording it as EXCLUDED_TIER instead
    // means the same scenario appears in every run's results with a count attached, so a reader
    // can tell "never selected by this tier" apart from "selected and green".
    if (filter.tiers && !filter.tiers.includes(t.tier)) {
      results.push(excludedByTierRecord(t, filter));
      continue;
    }
    results.push(await runOne(t, target));
  }
  return results;
}
