// The target under test.
//
// PARAMETERISATION RULE: this file, and the whole harness, knows NOTHING about
// any particular implementation. A target is a launch command (server role), a
// launch command (client role), and a few optional hints. There are no
// "if subject is X" branches anywhere in this codebase, and adding one would be
// a defect in the harness, not a feature.
//
// If you find yourself wanting a per-subject branch, that is a finding about
// the specification being underspecified. Write it up in the battery document
// instead of coding around it.

import { StdioPeer, parseLaunch } from './stdio-peer.mjs';

export class Target {
  /**
   * @param {object} cfg
   *  name          label used in reports
   *  serverLaunch  command line that starts the subject AS AN MCP SERVER on stdio
   *  clientLaunch  command line that starts the subject AS AN MCP CLIENT; it is
   *                given the fake server's launch command via argv/env
   *  failingTool   optional: name of a tool that always fails, to test the
   *                isError path. Without it that test SKIPs rather than lying.
   *  sampleCallFor optional: map of toolName -> arguments, used to exercise
   *                output schemas and echo behaviour.
   */
  constructor(cfg) {
    this.name = cfg.name;
    this.serverLaunch = cfg.serverLaunch || null;
    this.clientLaunch = cfg.clientLaunch || null;
    this.failingTool = cfg.failingTool || null;
    this.sampleCallFor = cfg.sampleCallFor || null;
    this.env = cfg.env || {};
    this.cwd = cfg.cwd || process.cwd();
  }

  get hasServerRole() { return Boolean(this.serverLaunch); }

  get hasClientRole() { return Boolean(this.clientLaunch); }

  /**
   * Spawn the subject in its MCP SERVER role and return a raw stdio driver.
   *
   * `extraEnv` is merged over the target's own environment for THIS spawn only, and it is what the
   * seam suite uses to tell an `MCP_SUBJECT_UPSTREAM_CONFIG_CMD` launcher which attack to arm and
   * where to record the upstream transcript. It used to take no environment at all, which made
   * `seam.mjs:seamEnv()` DEAD CODE: the mode and the transcript path could not reach the spawned
   * launcher by any route, so every seam test would have run against the honest baseline and read
   * an empty transcript — five of the six clauses passing on evidence that could not exist. That is
   * a defect in the battery and it is fixed here rather than worked around in the suite.
   *
   * It is still not per-subject knowledge: the harness passes an environment it documents and does
   * not care what the launcher does with it, exactly as `spawnClient` already passed
   * `MCP_TARGET_SERVER_COMMAND`.
   */
  spawnServer(extraEnv = {}) {
    if (!this.serverLaunch) {
      throw new Error(`target "${this.name}" has no serverLaunch configured`);
    }
    const { command, args } = parseLaunch(this.serverLaunch);
    return new StdioPeer(command, args, {
      env: { ...this.env, ...extraEnv },
      cwd: this.cwd,
    }).start();
  }

  /**
   * Spawn the subject in its MCP CLIENT role, pointed at a fake server we
   * control. The fake server launch command is passed both as the final argv
   * element and as MCP_TARGET_SERVER_COMMAND, because there is no standard for
   * how a client is told where to connect. Subjects may honour either.
   */
  spawnClient(fakeServerLaunch, extraEnv = {}) {
    if (!this.clientLaunch) {
      throw new Error(`target "${this.name}" has no clientLaunch configured`);
    }
    const { command, args } = parseLaunch(this.clientLaunch);
    return new StdioPeer(command, [...args, fakeServerLaunch], {
      env: {
        ...this.env,
        MCP_TARGET_SERVER_COMMAND: fakeServerLaunch,
        ...extraEnv,
      },
      cwd: this.cwd,
    }).start();
  }

  toJSON() {
    return {
      name: this.name,
      serverLaunch: this.serverLaunch,
      clientLaunch: this.clientLaunch,
      failingTool: this.failingTool,
      hasServerRole: this.hasServerRole,
      hasClientRole: this.hasClientRole,
    };
  }
}

export function targetFromEnvAndArgs(args) {
  const cfg = {
    name: args.name || process.env.MCP_SUBJECT_NAME || 'unnamed-target',
    serverLaunch: args.serverLaunch || process.env.MCP_SUBJECT_SERVER_CMD || null,
    clientLaunch: args.clientLaunch || process.env.MCP_SUBJECT_CLIENT_CMD || null,
    failingTool: args.failingTool || process.env.MCP_SUBJECT_FAILING_TOOL || null,
  };
  if (process.env.MCP_SUBJECT_SAMPLE_CALLS) {
    cfg.sampleCallFor = JSON.parse(process.env.MCP_SUBJECT_SAMPLE_CALLS);
  }
  if (args.sampleCalls) cfg.sampleCallFor = JSON.parse(args.sampleCalls);
  return new Target(cfg);
}
