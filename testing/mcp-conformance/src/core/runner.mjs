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
    failed: false,
    verdict: VERDICT.PASS,
    error: null,
  };
  const ctx = new Ctx(target, record);
  try {
    await t.run(ctx);
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

export async function runAll(target, filter = {}) {
  const selected = allTests().filter((t) => {
    if (filter.tiers && !filter.tiers.includes(t.tier)) return false;
    if (filter.areas && !filter.areas.includes(t.area)) return false;
    if (filter.roles && !filter.roles.includes(t.role)) return false;
    if (filter.transport && !t.transports.includes(filter.transport)) return false;
    if (filter.only && !filter.only.some((p) => t.id.includes(p))) return false;
    return true;
  });
  const results = [];
  for (const t of selected) {
    results.push(await runOne(t, target));
  }
  return results;
}
