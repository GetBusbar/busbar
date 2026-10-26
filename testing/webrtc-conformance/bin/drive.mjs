#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE BROWSER CELL'S DRIVER: headless Chromium and Firefox (Playwright, pinned in package.json)
// open the subject's page and run its cell, or its control; every graded cell is one line
//
//   webrtc-conformance: <browser> <cell> PASS|FAIL <detail>
//
// and the verdict (`--out <dir>/verdict.json`) is judged from those lines alone (`judge`), so the
// selftest proves the same judgement on captured fixtures without a browser.
//
// MODES
//   --url <u> --mode cell|control --out <dir>   drive both browsers; exit 0 pass, 1 fail, 3 not-run
//   --judge <lines> --armed true|false --out <f> judge captured lines; exit as above
//   --selftest                                    the judgement bites (no browser)

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export const BROWSERS = ["chromium", "firefox"];
export const CELLS = [
  "answer",
  "connected",
  "channel-text",
  "channel-binary",
  "media-round-trip",
  "media-codec",
  "close",
];
const PREFIX = "webrtc-conformance: ";

/** The verdict a run's lines earn: every browser, every cell, PASS; a browser that did not launch,
 *  or an unarmed subject, is not-run, never pass. */
export function judge(lines, armed) {
  const browsers = {};
  const unavailable = [];
  for (const raw of lines) {
    if (!raw.startsWith(PREFIX)) continue;
    const [browser, cell, result, ...rest] = raw.slice(PREFIX.length).split(" ");
    if (!BROWSERS.includes(browser)) continue;
    if (cell === "launch" && result === "FAIL") {
      unavailable.push(`${browser}: ${rest.join(" ")}`);
      continue;
    }
    (browsers[browser] ||= {})[cell] = { pass: result === "PASS", detail: rest.join(" ") };
  }
  if (!armed) {
    return { armed: false, status: "not-run", reason: "the subject was not armed", browsers };
  }
  if (unavailable.length) {
    return { armed: true, status: "not-run", reason: `browser unavailable: ${unavailable.join("; ")}`, browsers };
  }
  const failed = [];
  for (const b of BROWSERS) {
    for (const c of CELLS) {
      const got = browsers[b] && browsers[b][c];
      if (!got || !got.pass) failed.push(`${b}/${c}${got ? ": " + got.detail : ": not graded"}`);
    }
  }
  return failed.length
    ? { armed: true, status: "fail", reason: failed.join("; "), browsers }
    : { armed: true, status: "pass", reason: `${BROWSERS.length * CELLS.length} cell(s) passed`, browsers };
}

function exitFor(v) {
  return v.status === "pass" ? 0 : v.status === "fail" ? 1 : 3;
}

function write(out, v) {
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(v, null, 2) + "\n");
}

function selftest() {
  const all = (browser, result) => CELLS.map((c) => `${PREFIX}${browser} ${c} ${result} x`);
  const good = [...all("chromium", "PASS"), ...all("firefox", "PASS")];
  const checks = [
    ["good lines pass", judge(good, true).status === "pass"],
    ["unarmed never passes", judge(good, false).status === "not-run"],
    ["one failed cell fails", judge(good.map((l, i) => (i === 4 ? l.replace(" PASS ", " FAIL ") : l)), true).status === "fail"],
    ["a missing cell fails", judge(good.slice(1), true).status === "fail"],
    ["a missing browser fails", judge(all("chromium", "PASS"), true).status === "fail"],
    ["a browser that did not launch is not-run", judge([...good, `${PREFIX}firefox launch FAIL no binary`], true).status === "not-run"],
    ["foreign lines are ignored", judge(["noise", ...good], true).status === "pass"],
  ];
  let red = 0;
  for (const [name, held] of checks) {
    console.log(`  ${held ? "ok" : "RED"}: ${name}`);
    if (!held) red++;
  }
  return red === 0 ? 0 : 1;
}

async function drive(url, mode, out) {
  let pw;
  try {
    pw = await import("playwright");
  } catch (e) {
    const v = { armed: true, status: "not-run", reason: `playwright is not installed: ${e.message}`, browsers: {} };
    write(out, v);
    console.log(`${PREFIX}${v.reason}`);
    return 3;
  }
  const lines = [];
  const say = (l) => {
    lines.push(l);
    console.log(l);
  };
  // THE PAGE'S ORIGIN IS A SECURE CONTEXT. The subject serves the page over plain http on the
  // host's non-loopback address (the one candidate its answer advertises), and a browser exposes
  // `navigator.mediaDevices` only to a secure context, so without this every leg dies in the page
  // before any cell is graded. Each browser is told to treat exactly this origin as secure.
  const origin = new URL(url);
  const launch = {
    chromium: () =>
      pw.chromium.launch({
        headless: true,
        // The full build in its headless mode: the headless shell ignores the secure-origin switch.
        channel: "chromium",
        args: [
          "--use-fake-ui-for-media-stream",
          "--use-fake-device-for-media-stream",
          `--unsafely-treat-insecure-origin-as-secure=${origin.origin}`,
        ],
      }),
    firefox: () =>
      pw.firefox.launch({
        headless: true,
        firefoxUserPrefs: {
          "media.navigator.streams.fake": true,
          "media.navigator.permission.disabled": true,
          "dom.securecontext.allowlist": origin.hostname,
          "media.devices.insecure.enabled": true,
          "media.getusermedia.insecure.enabled": true,
        },
      }),
  };
  for (const b of BROWSERS) {
    let browser;
    try {
      browser = await launch[b]();
    } catch (e) {
      say(`${PREFIX}${b} launch FAIL ${String(e.message).split("\n")[0]}`);
      continue;
    }
    try {
      const page = await (await browser.newContext()).newPage();
      await page.goto(url);
      const cells = await page.evaluate((m) => (m === "control" ? window.runControl() : window.runCell()), mode);
      for (const c of Object.keys(cells)) {
        const r = cells[c];
        say(`${PREFIX}${b} ${c} ${r.pass ? "PASS" : "FAIL"} ${String(r.detail).replace(/\s+/g, " ").slice(0, 300)}`);
      }
    } catch (e) {
      say(`${PREFIX}${b} page FAIL ${String(e.message).split("\n")[0]}`);
    } finally {
      await browser.close();
    }
  }
  const v = judge(lines, true);
  write(out, v);
  console.log(`${PREFIX}${mode}: ${v.status}: ${v.reason}`);
  return exitFor(v);
}

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
if (args.includes("--selftest")) {
  process.exit(selftest());
} else if (opt("--judge")) {
  const v = judge(readFileSync(opt("--judge"), "utf8").split("\n"), opt("--armed") === "true");
  write(opt("--out"), v);
  process.exit(exitFor(v));
} else if (opt("--url")) {
  process.exit(await drive(opt("--url"), opt("--mode") || "cell", `${opt("--out")}/verdict.json`));
} else {
  console.error("usage: drive.mjs --url <u> --mode cell|control --out <dir> | --judge <f> --armed <b> --out <f> | --selftest");
  process.exit(2);
}
