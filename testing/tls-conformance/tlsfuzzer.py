#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unmodified upstream TLSfuzzer mandatory-client-auth CertificateVerify profile.

Every generated RSA algorithm and signature bit-flip case runs. The sole
inapplicable case sends an empty certificate then expects HTTP application data;
it tests optional client authentication, unlike these required-mTLS endpoints.
Explicit case selection avoids even reporting that case as a passing skip.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import urllib.request

REPOSITORY = "https://github.com/tlsfuzzer/tlsfuzzer.git"
REVISION = "5eebc4464e5197a7f7392fb9acda99cfc32441f7"
APPLICATION = "tlsfuzzer/_apps/test_tls13_certificate_verify.py"
APPLICATION_SHA256 = "533b673ef5b0c2bfd84b5b31f6a3f40d8b16eef1f390134d427d1dfba80eb501"
ENTRY = "scripts/test-tls13-certificate-verify.py"
ENTRY_SHA256 = "cc9a921f259b02c36b80c83b8647ac37bbf6c9729d776646e94e8985b1841fec"
LOCK = Path(__file__).with_name("tlsfuzzer-requirements.lock")
EXCLUDED = {"check sigalgs in cert request":
            "Upstream sends no client certificate but expects HTTP; optional client authentication only."}
PROFILE = "TLS 1.3 mandatory client authentication / RSA-PSS CertificateVerify profile"
LEG_TIMEOUT = 900
NEGATIVE_TIMEOUT = 120
BOOTSTRAP_TIMEOUT = 120
PIP_WHEEL = {
    "version": "25.3",
    "filename": "pip-25.3-py3-none-any.whl",
    "url": "https://files.pythonhosted.org/packages/44/3c/d717024885424591d5376220b5e836c2d5293ce2011523c9de23ff7bf068/pip-25.3-py3-none-any.whl",
    "sha256": "9655943313a94722b7774661c21049070f6bbb0a1516bf02f7c8d5d9201514cd",
}


class Refused(ValueError):
    pass


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bounded(argv, log, timeout, cwd=None):
    """Own the process group, including installation and upstream failure paths."""
    with Path(log).open("wb") as output:
        process = subprocess.Popen(argv, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise Refused(f"command exceeded {timeout}s; see {Path(log).name}") from error
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def capture(argv):
    return subprocess.check_output(argv, text=True, timeout=60).strip()


def installer(work):
    """Minimal CI Python has no ensurepip; verify an installer before executing it."""
    wheel = Path(work) / PIP_WHEEL["filename"]
    with (
        urllib.request.urlopen(PIP_WHEEL["url"], timeout=BOOTSTRAP_TIMEOUT) as source,
        wheel.open("xb") as target,
    ):
        shutil.copyfileobj(source, target)
    if digest(wheel) != PIP_WHEEL["sha256"]:
        raise Refused("TLSfuzzer installer wheel digest mismatch")
    return wheel


def environment_commands(work, wheel):
    python = Path(work) / "venv/bin/python"
    # No host pip, system-site-packages, mutable get-pip script or build backend.
    # The pinned wheel is executable as a zip import and installs only itself.
    bootstrap = ('import runpy,sys;sys.path.insert(0,sys.argv.pop(1));'
                 'runpy.run_module("pip",run_name="__main__")')
    return [
        [sys.executable, "-B", "-I", "-m", "venv", "--without-pip", str(Path(work) / "venv")],
        [str(python), "-B", "-I", "-c", bootstrap, str(wheel), "install",
         "--disable-pip-version-check", "--no-cache-dir", "--no-index", "--no-deps", str(wheel)],
        [str(python), "-B", "-I", "-m", "pip", "install", "--disable-pip-version-check",
         "--no-cache-dir", "--only-binary=:all:", "--require-hashes", "-r", str(LOCK)],
    ]


def expected_cases(octets, algorithms):
    """Expected roster only; all handshake/signature judgments remain upstream."""
    if not isinstance(octets, int) or octets < 256 or not algorithms:
        raise Refused("the profile requires an RSA client key of at least 2048 bits")
    cases = ["sanity"]
    for name in algorithms:
        result = "works" if name in (
            "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512") else "is refused"
        cases.append(f"check {name} signature {result}")
    cases += [f"check signature with salt length {size}" for size in (0, 31, 33)]
    cases += ["check pkcs1 signature with rsa-pss envelope fails",
              "check rsa-pss signature with mismatched hash fails",
              "check rsa-pss signature with mismatched mgf1 fails"]
    cases += [f"check that fuzzed signatures are rejected. Malformed rsa - xor {hex(bit)} at {position}"
              for position in range(octets) for bit in (1, 2, 4, 8, 16, 32, 64, 128)]
    if len(cases) != len(set(cases)):
        raise Refused("duplicate declared upstream cases")
    return cases + ["sanity"]  # Upstream runs sanity both first and last.


def judge(text, rc, roster, negative=False):
    counts = {}
    for field in ("TOTAL", "SKIP", "PASS", "XFAIL", "FAIL", "XPASS"):
        values = re.findall(rf"^{field}: (\d+)$", text, re.M)
        if len(values) != 1:
            raise Refused(f"missing or duplicate upstream {field} summary")
        counts[field] = int(values[0])
    if re.findall(r"^version: (\d+)$", text, re.M) != ["9"]:
        raise Refused("missing or changed upstream application version")
    actual = re.findall(r"^(.+) \.\.\.$", text, re.M)
    if not roster or collections.Counter(actual) != collections.Counter(roster):
        raise Refused("upstream executed case roster differs from the complete declared profile")
    expected = dict(TOTAL=len(roster), SKIP=0, PASS=0 if negative else len(roster),
                    XFAIL=0, FAIL=len(roster) if negative else 0, XPASS=0)
    if counts != expected or rc != (1 if negative else 0):
        raise Refused(f"upstream verdict refused: exit={rc}, counts={counts}, expected={expected}")
    if negative and "Alert(fatal, unknown_ca)" not in text:
        raise Refused("invalid-client control failed without the expected TLS unknown_ca alert")
    return counts


class Profile:
    def __init__(self, work, output, checkout, binary):
        self.work, self.output = Path(work) / "tlsfuzzer", Path(output) / "tlsfuzzer"
        if (self.work.resolve() == self.output.resolve() or
                self.work.resolve() in self.output.resolve().parents or
                self.output.resolve() in self.work.resolve().parents):
            raise Refused("upstream source/dependency workspace must be separate from published evidence")
        self.work.mkdir()
        self.output.mkdir(parents=True)
        self.checkout, self.binary = str(Path(checkout).resolve()), str(Path(binary).resolve())
        head = capture(["git", "-C", self.checkout, "rev-parse", "HEAD"])
        if head != os.environ.get("CONF_HEAD", head) or head != os.environ.get("BUSBAR_PIN", head):
            raise Refused("TLSfuzzer subject source differs from the admitted core revision")
        self.record = {"profile": PROFILE, "source": head, "binary_sha256": digest(self.binary),
                       "upstream": REPOSITORY, "revision": REVISION,
                       "application_sha256": APPLICATION_SHA256, "entry_sha256": ENTRY_SHA256,
                       "dependency_lock_sha256": digest(LOCK), "excluded_configuration": EXCLUDED,
                       "installer": PIP_WHEEL,
                       "upstream_socket_timeout_seconds": 5, "leg_timeout_seconds": LEG_TIMEOUT,
                       "negative_timeout_seconds": NEGATIVE_TIMEOUT,
                       "legs": {}, "pass": False}
        self.record["source_binding"] = self.source_binding()
        self.save()
        self.source = self.work / "source"
        self.python = self.work / "venv" / "bin" / "python"
        commands = [
            ["git", "init", "-q", str(self.source)],
            ["git", "-C", str(self.source), "fetch", "-q", "--depth", "1", REPOSITORY, REVISION],
            ["git", "-C", str(self.source), "checkout", "-q", "--detach", "FETCH_HEAD"],
            *environment_commands(self.work, installer(self.work)),
        ]
        for index, command in enumerate(commands):
            if bounded(command, self.output / f"bootstrap-{index}.log", BOOTSTRAP_TIMEOUT):
                raise Refused(f"TLSfuzzer pinned bootstrap failed at step {index}")
        self.check_source()
        self.record["runtime"] = capture([str(self.python), "-B", "-I", "--version"])
        self.record["dependencies"] = capture([str(self.python), "-B", "-I", "-m", "pip", "freeze"])
        self.save()

    def save(self):
        (self.output / "result.json").write_text(json.dumps(self.record, indent=2) + "\n")

    def source_binding(self):
        return {"head": capture(["git", "-C", self.checkout, "rev-parse", "HEAD"]),
                "tree": capture(["git", "-C", self.checkout, "rev-parse", "HEAD^{tree}"]),
                "tracked_changes_sha256": hashlib.sha256(capture(
                    ["git", "-C", self.checkout, "diff", "--binary", "HEAD"]).encode()).hexdigest(),
                "distribution_lock_sha256": digest(Path(self.checkout) / "dist/default/Cargo.lock")}

    def check_source(self):
        if capture(["git", "-C", str(self.source), "rev-parse", "HEAD"]) != REVISION:
            raise Refused("TLSfuzzer checkout differs from pinned revision")
        if capture(["git", "-C", str(self.source), "status", "--porcelain", "--untracked-files=all"]):
            raise Refused("TLSfuzzer source contains local changes")
        for name, expected in ((APPLICATION, APPLICATION_SHA256), (ENTRY, ENTRY_SHA256)):
            if digest(self.source / name) != expected:
                raise Refused(f"TLSfuzzer pinned script digest differs: {name}")

    def run(self, label, port, client, negative=False):
        self.check_source()
        # Read only the RSA modulus length and upstream/dependency algorithm roster.
        inspect = ("import sys,json;sys.path.insert(0,sys.argv[1]);"
                   "from tlslite.utils.keyfactory import parsePEMKey;"
                   "from tlslite.constants import SignatureScheme;"
                   "from tlsfuzzer.helpers import RSA_SIG_ALL;"
                   "k=parsePEMKey(open(sys.argv[2]).read(),private=True);"
                   "print(json.dumps({'octets':(k.n.bit_length()+7)//8,"
                   "'algorithms':[SignatureScheme.toStr(a) for a in RSA_SIG_ALL]}))")
        info = json.loads(capture([str(self.python), "-B", "-I", "-c", inspect,
                                   str(self.source), client[1]]))
        roster = ["sanity"] if negative else expected_cases(info["octets"], info["algorithms"])
        log = self.output / f"{label}.log"
        leg = {"expected_count": len(roster), "expected_cases": roster,
               "certificate_sha256": digest(client[0]), "pass": False, "log": log.name}
        self.record["legs"][label] = leg
        self.save()
        command = [str(self.python), "-B", "-u", "-I", str(self.source / ENTRY),
                   "-h", "127.0.0.1", "-p", str(port), "-k", client[1], "-c", client[0],
                   "-n", "0", *dict.fromkeys(roster)]
        try:
            rc = bounded(command, log, NEGATIVE_TIMEOUT if negative else LEG_TIMEOUT,
                         cwd=str(self.source))
            leg["exit"] = rc
            leg["counts"] = judge(log.read_text(errors="replace"), rc, roster, negative)
            self.check_source()
            if digest(self.binary) != self.record["binary_sha256"]:
                raise Refused("actual Busbar binary changed during external conformance")
            if self.source_binding() != self.record["source_binding"]:
                raise Refused("actual Busbar source/lock changed during external conformance")
            leg["pass"] = True
            return []
        except (Refused, OSError, subprocess.SubprocessError) as error:
            leg["error"] = str(error)
            return [f"TLSfuzzer {label}: {error}; see {log}"]
        finally:
            if log.exists():
                text = log.read_text(errors="replace")
                executed = re.findall(r"^(.+) \.\.\.$", text, re.M)
                leg["observed_case_count"] = len(executed)
                leg["observed_roster_sha256"] = hashlib.sha256(
                    json.dumps(sorted(executed)).encode()).hexdigest()
                leg["partial_summary"] = {
                    name: re.findall(rf"^{name}: (\d+)$", text, re.M)
                    for name in ("TOTAL", "SKIP", "PASS", "XFAIL", "FAIL", "XPASS")}
            self.save()

    def finish(self):
        required = {"control", "invalid-client", "subject-data", "subject-admin"}
        self.record["pass"] = (set(self.record["legs"]) == required and
                               all(leg["pass"] for leg in self.record["legs"].values()))
        self.save()
        return [] if self.record["pass"] else ["TLSfuzzer required external legs did not all pass"]
