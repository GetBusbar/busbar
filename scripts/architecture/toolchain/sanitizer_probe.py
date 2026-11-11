#!/usr/bin/env python3
"""Bounded local TSan qualification; no changes to normal native execution policy."""

import argparse
import json
from pathlib import Path
import shutil
import sys

from sanitizer_profile import PINS, derive, prepare, verify_delta

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_confinement import Execution, digest, require


class ProfileExecution(Execution):
    def __init__(self, config, roots, control, profile, expected, baseline):
        super().__init__(config, roots, control)
        self.profile = Path(profile).resolve()
        require(digest(self.profile) == expected, "local profile digest differs")
        self.profile_data = json.loads(self.profile.read_text())
        baseline_data = json.loads(Path(baseline).read_text())
        derive(Path(baseline).read_bytes())  # independently pinned engine baseline
        if self.profile_data != baseline_data:
            verify_delta(baseline_data, self.profile_data)
        self.profile_sha256 = expected

    def _client(self, argv, **kwargs):
        if argv[0] == "create":
            require(
                digest(self.profile) == self.profile_sha256,
                "profile changed before launch",
            )
            argv = [
                argv[0],
                "--security-opt",
                "seccomp=" + str(self.profile),
                *argv[1:],
            ]
        result = super()._client(argv, **kwargs)
        if (
            argv[0] == "inspect"
            and '--format' not in argv
            and result.returncode == 0
            and kwargs.get("capture_output")
        ):
            row = json.loads(result.stdout)[0]
            options = row["HostConfig"]["SecurityOpt"]
            policies = [
                value.split("=", 1)[1]
                for value in options
                if value.startswith("seccomp=")
            ]
            require(
                len(policies) == 1 and json.loads(policies[0]) == self.profile_data,
                "runtime did not retain the exact local seccomp profile",
            )
            require(len(options) == 2, "unexpected additional security option")
        return result


def probe(config_path, config_sha256, baseline_path, work):
    require(
        digest(config_path) == config_sha256, "runtime configuration digest differs"
    )
    config = json.loads(Path(config_path).read_text())
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    profile_record = prepare(baseline_path, work / "profiles")
    roots = {
        name: work / name for name in ("checkout", "candidate", "trusted", "harness")
    }
    control = work / "control"
    for path in [*roots.values(), control]:
        path.mkdir()
    (roots["checkout"] / ".git").mkdir()
    (roots["harness"] / "immutable").write_text("trusted harness\n")
    (control / "secret").write_text("controller fixture secret\n")
    baseline = work / "profiles/baseline.json"
    original = ProfileExecution(
        config, roots, control, baseline, profile_record["baseline_sha256"], baseline
    )
    sanitizer = ProfileExecution(
        config,
        roots,
        control,
        work / "profiles/sanitizer.json",
        profile_record["profile_sha256"],
        baseline,
    )
    version = json.loads(
        original._client(
            ["version", "--format", "{{json .Server}}"], capture_output=True, text=True
        ).stdout
    )
    require(
        version["Version"] == PINS["engine_version"]
        and PINS["engine_git_commit"].startswith(version["GitCommit"]),
        "local daemon no longer matches the pinned baseline engine",
    )
    rows = {}
    report = {
        "schema": "busbar.local-sanitizer-qualification/1",
        "scope": "local fixture only",
        "image": config["image"],
        "engine": version,
        "profile": profile_record,
        "production_activation": False,
        "release_eligible": False,
    }
    env = {"TSAN_OPTIONS": "halt_on_error=1:exitcode=66"}

    def run(execution, name, argv, success=False):
        result = execution.run(
            argv,
            cwd=roots["checkout"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        rows[name] = {
            "argv": list(map(str, argv)),
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "profile_sha256": execution.profile_sha256,
        }
        (control / (name + ".json")).write_text(json.dumps(rows[name], indent=2) + "\n")
        if success:
            require(result.returncode == 0, name + " failed: " + result.stderr[-2000:])
        return result

    try:
        source = roots["checkout"] / "sanitizer.c"
        source.write_text("""#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <sys/personality.h>
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;
static int counter;
static void *worker(void *ignored) {
    (void)ignored;
    pthread_barrier_wait(&barrier);
    for (int n = 0; n < 1000; ++n) {
#ifndef DELIBERATE_RACE
        pthread_mutex_lock(&mutex);
#endif
        ++counter;
#ifndef DELIBERATE_RACE
        pthread_mutex_unlock(&mutex);
#endif
    }
    return 0;
}
int main(void) {
    printf("personality=%d\\n", personality(0xffffffff)); fflush(stdout);
    if (pthread_barrier_init(&barrier, 0, 2)) return 2;
    pthread_t one, two;
    if (pthread_create(&one, 0, worker, 0) || pthread_create(&two, 0, worker, 0)) return 3;
    pthread_join(one, 0); pthread_join(two, 0);
    pthread_barrier_destroy(&barrier);
    return 0;
}
""")
        clean, race = roots["candidate"] / "clean", roots["candidate"] / "race"
        for name, target, flags in [
            ("compile-clean", clean, []),
            ("compile-race", race, ["-DDELIBERATE_RACE"]),
        ]:
            run(
                original,
                name,
                [
                    "cc",
                    "-std=c11",
                    "-g",
                    "-fsanitize=thread",
                    "-pthread",
                    *flags,
                    str(source),
                    "-o",
                    str(target),
                ],
                success=True,
            )
        report["instrumented_binaries"] = {
            "race_free_sha256": digest(clean),
            "race_sha256": digest(race),
        }
        blocked = run(original, "baseline-tsan", [str(clean)])
        require(
            blocked.returncode != 0 and "personality" in blocked.stderr,
            "baseline did not reproduce the actual TSan personality obstruction",
        )
        good = run(sanitizer, "sanitizer-race-free", [str(clean)])
        bad = run(sanitizer, "sanitizer-deliberate-race", [str(race)])
        require(
            good.returncode == 0 and "personality=262144" in good.stdout,
            "race-free instrumented control did not pass with observed process ASLR disabled",
        )
        require(
            bad.returncode == 66 and "ThreadSanitizer: data race" in bad.stderr,
            "instrumented deliberate race was not detected",
        )
        denial = """import ctypes,errno,json,os,pathlib,socket,sys
r=pathlib.Path(%r)
libc=ctypes.CDLL(None,use_errno=True)
libc.personality.argtypes=[ctypes.c_ulong]
libc.personality.restype=ctypes.c_int
before=libc.personality(0xffffffff)
if before == 0:
 assert libc.personality(262144) == 0
 os.execv(sys.executable,[sys.executable,'-c',sys.argv[1],sys.argv[1]])
assert before == 262144
assert libc.personality(262144 | 0x0400000) == -1 and ctypes.get_errno() == errno.EPERM
assert os.geteuid()!=0
status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert all(int(status[name].strip(),16)==0 for name in ['CapEff','CapPrm','CapBnd'])
assert status['NoNewPrivs'].strip()=='1' and status['Seccomp'].strip()=='2'
assert not (r/'control/secret').exists()
assert not pathlib.Path('/var/run/docker.sock').exists()
assert not any(k in os.environ for k in ['CI_JOB_TOKEN','AWS_SECRET_ACCESS_KEY','GOOGLE_APPLICATION_CREDENTIALS'])
for p in [r/'harness/immutable',r/'trusted/created',r/'checkout/created',pathlib.Path('/etc/created')]:
 try:p.write_text('BAD')
 except OSError:pass
 else:raise AssertionError(str(p))
for host in ['169.254.169.254','1.1.1.1']:
 try:socket.create_connection((host,80),timeout=.2)
 except OSError:pass
 else:raise AssertionError(host)
assert libc.unshare(0x10000000 | 0x00020000) == -1
(r/'candidate/denial-witness').write_text('all denied with process ASLR disabled')
print(json.dumps({'personality':before,'uid':os.geteuid(),'seccomp':int(status['Seccomp']),'all_denied':True}))
""" % str(work)
        env.update(
            CI_JOB_TOKEN="fixture-secret",
            AWS_SECRET_ACCESS_KEY="fixture-secret",
            GOOGLE_APPLICATION_CREDENTIALS="/host/secret",
        )
        denied = run(
            sanitizer,
            "sanitizer-denial-witness",
            ["/usr/bin/python3", "-c", denial, denial],
            success=True,
        )
        report.update(
            status="local-sanitizer-fixtures-pass",
            per_process_aslr_disabled=True,
            race_free_passed=True,
            deliberate_race_detected=True,
            denial_witness=json.loads(denied.stdout),
        )
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        report["commands"] = rows
        report["baseline_observations"] = original.observations
        report["sanitizer_observations"] = sanitizer.observations
        (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        for path in roots.values():
            shutil.rmtree(path)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    result = probe(args.config, args.config_sha256, args.baseline, args.work)
    print(
        json.dumps(
            {
                k: v
                for k, v in result.items()
                if k
                not in (
                    "commands",
                    "baseline_observations",
                    "sanitizer_observations",
                    "engine",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
