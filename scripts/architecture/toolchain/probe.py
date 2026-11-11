#!/usr/bin/env python3
"""Small actual compiler/TSan witnesses through the unchanged native boundary."""

import argparse
import json
import re
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_confinement import Execution, digest, require


def probe(config, expected, plan_sha256, work, require_tsan=False, require_tools=False):
    require(digest(config) == expected, "runtime configuration digest differs")
    config = json.loads(Path(config).read_text())
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    roots = {key: work / key for key in ("checkout", "candidate", "trusted", "harness")}
    control = work / "control"
    for path in [*roots.values(), control]:
        path.mkdir()
    (roots["checkout"] / ".git").mkdir()
    execution = Execution(config, roots, control)
    env = {
        "CARGO_TARGET_DIR": str(roots["candidate"] / "target"),
        "RUSTUP_TOOLCHAIN": "1.98.0",
        "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
    }
    rows = {}

    def run(name, argv, *, success=True):
        result = execution.run(
            argv,
            cwd=roots["checkout"],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        rows[name] = {
            "argv": list(map(str, argv)),
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        (control / (name + ".json")).write_text(json.dumps(rows[name], indent=2) + "\n")
        if success:
            require(result.returncode == 0, name + " failed: " + result.stderr[-2000:])
        return result

    report = {"scope": "small actual compiler fixtures only", "release_eligible": False}
    try:
        seed = json.loads(
            run(
                "seed-identity",
                [
                    "/usr/bin/python3",
                    "-c",
                    'from pathlib import Path; print(Path("/opt/busbar-native/seed.json").read_text())',
                ],
            ).stdout
        )
        require(
            seed["plan_sha256"] == plan_sha256,
            "image seed differs from independently approved fixture plan",
        )
        report.update(
            image=config["image"],
            plan_sha256=plan_sha256,
            vector_sha256=seed["vector_sha256"],
        )
        for tool in ("rustc", "cargo", "rustfmt", "clippy-driver", "cc"):
            run(tool + "-version", [tool, "--version"])
        if require_tools:
            for tool in ('cargo-nextest', 'cargo-deny', 'cargo-vet', 'node'):
                run(tool + '-version', [tool, '--version'])
            run('python-yaml', ['/usr/bin/python3', '-I', '-c',
                'import yaml; assert yaml.__version__ == "6.0.3"; assert yaml.safe_load("key: value") == {"key":"value"}'])
        personality = run(
            "personality-query",
            [
                "/usr/bin/python3",
                "-c",
                'import ctypes,json; libc=ctypes.CDLL(None,use_errno=True); libc.personality.argtypes=[ctypes.c_ulong]; libc.personality.restype=ctypes.c_int; value=libc.personality(0xffffffff); print(json.dumps({"personality":value,"errno":ctypes.get_errno()}))',
            ],
        )
        report["personality_query"] = json.loads(personality.stdout)
        checkout, harness = roots["checkout"], roots["harness"]
        has_registry = any(p["name"] == "itoa" for entries in seed.get("packages", {}).values() for p in entries)
        (checkout / "src").mkdir()
        (checkout / "Cargo.toml").write_text(
            '[workspace]\n[package]\nname="boundary-candidate"\nversion="0.0.0"\nedition="2021"\n[dependencies]\n' + ('itoa="=1.0.18"\n' if has_registry else '')
        )
        (checkout / "src/lib.rs").write_text(
            'pub fn answer() -> u64 { let mut b = itoa::Buffer::new(); assert_eq!(b.format(42), "42"); 42 }\n' if has_registry else 'pub fn answer() -> u64 { 42 }\n'
        )
        git_packages = [
            p
            for rows in seed.get("packages", {}).values()
            for p in rows
            if p["name"] == "busbar-seed-git"
        ]
        if git_packages:
            row = git_packages[0]
            match = re.fullmatch(
                r"git\+(https://github\.com/[^?]+)\?rev=([0-9a-f]{40})#\2",
                row["source"],
            )
            require(match, "fixture Git source is not immutable")
            with (checkout / "Cargo.toml").open("a") as manifest_file:
                manifest_file.write(
                    "busbar-seed-git={git="
                    + json.dumps(match[1])
                    + ",rev="
                    + json.dumps(match[2])
                    + "}\n"
                )
            (checkout / "src/lib.rs").write_text(
                'pub fn answer() -> u64 { let mut b = itoa::Buffer::new(); assert_eq!(b.format(42), "42"); assert_eq!(busbar_seed_git::answer(), 7); 42 }\n'
            )
        (checkout / "build.rs").write_text(
            "fn main() { assert!(std::fs::write("
            + json.dumps(str(harness / "owned"))
            + ', "escape").is_err()); }\n'
        )
        (harness / "src").mkdir()
        (harness / "examples").mkdir()
        (harness / "Cargo.toml").write_text(
            '[workspace]\n[package]\nname="boundary-harness"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nboundary-candidate={path='
            + json.dumps(str(checkout))
            + "}\n"
        )
        (harness / "src/lib.rs").write_text(
            "#[test]\nfn trusted_positive() { assert_eq!(boundary_candidate::answer(), 42); }\n"
        )
        (harness / "examples/negative.rs").write_text(
            "fn main() { let _: &str = boundary_candidate::answer(); }\n"
        )
        manifest = str(harness / "Cargo.toml")
        run(
            "cargo-positive",
            ["cargo", "test", "--offline", "--manifest-path", manifest, "--lib"],
        )
        if require_tools:
            tool_fixture = roots['candidate'] / 'native-tools'
            shutil.copytree(harness, tool_fixture)
            tool_manifest = str(tool_fixture / 'Cargo.toml')
            run('nextest-positive', ['cargo', 'nextest', 'run', '--offline',
                                    '--manifest-path', tool_manifest, '--lib'])
            # Exercise vet's actual policy-store locks against read-only inputs.
            store = tool_fixture / 'supply-chain'
            store.mkdir()
            (store / 'config.toml').write_text('\n# cargo-vet config file\n\n[cargo-vet]\nversion = "0.10"\n' + ('\n[[exemptions.itoa]]\nversion = "1.0.18"\ncriteria = "safe-to-deploy"\n' if has_registry else ''))
            (store / 'audits.toml').write_text('\n# cargo-vet audits file\n\n[audits]\n')
            (store / 'imports.lock').write_text('\n# cargo-vet imports lock\n')
            execution.extra_readonly.append(tool_fixture)
            run('vet-offline', ['cargo', 'vet', '--locked', '--frozen', '--manifest-path', tool_manifest])
            execution.extra_readonly.remove(tool_fixture)
            report['native_tools'] = {'nextest': True, 'vet_offline': True,
                                      'deny_version': True, 'node': True, 'python_yaml': True}
        run(
            "cargo-clippy",
            [
                "cargo",
                "clippy",
                "--offline",
                "--manifest-path",
                manifest,
                "--lib",
                "--",
                "-D",
                "warnings",
            ],
        )
        negative = run(
            "cargo-negative",
            [
                "cargo",
                "check",
                "--offline",
                "--manifest-path",
                manifest,
                "--example",
                "negative",
                "--message-format=json",
            ],
            success=False,
        )
        diagnostics = [
            json.loads(line)
            for line in negative.stdout.splitlines()
            if line.startswith("{")
        ]
        require(
            negative.returncode != 0
            and any(
                row.get("reason") == "compiler-message"
                and row.get("target", {}).get("name") == "negative"
                and row.get("message", {}).get("code", {}).get("code") == "E0308"
                for row in diagnostics
            ),
            "negative compiler witness did not produce E0308",
        )
        require(
            not (harness / "Cargo.lock").exists() and not (harness / "owned").exists(),
            "candidate modified trusted harness",
        )
        report["cargo_harness"] = {
            "positive": True,
            "negative_E0308": True,
            "offline_registry_dependency": has_registry,
            "offline_git_dependency": bool(git_packages),
            "readonly_harness": True,
            "external_lockfile": True,
            "clippy": True,
        }
        c_source = checkout / "witness.c"
        c_source.write_text("""#include <pthread.h>
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int counter;
static void *worker(void *ignored) {
    (void)ignored;
    for (int n = 0; n < 1000; ++n) {
#ifndef DELIBERATE_RACE
        pthread_mutex_lock(&lock);
#endif
        ++counter;
#ifndef DELIBERATE_RACE
        pthread_mutex_unlock(&lock);
#endif
    }
    return 0;
}
int main(void) {
    pthread_t one, two;
    if (pthread_create(&one, 0, worker, 0) || pthread_create(&two, 0, worker, 0)) return 2;
    pthread_join(one, 0); pthread_join(two, 0);
    return counter == 2000 ? 0 : 3;
}
""")
        plain, clean, race = [
            roots["candidate"] / name for name in ("plain", "tsan-clean", "tsan-race")
        ]
        run(
            "c-compile", ["cc", "-std=c11", "-pthread", str(c_source), "-o", str(plain)]
        )
        run("c-positive", [str(plain)])
        run(
            "tsan-compile-positive",
            [
                "cc",
                "-std=c11",
                "-pthread",
                "-g",
                "-fsanitize=thread",
                str(c_source),
                "-o",
                str(clean),
            ],
        )
        run(
            "tsan-compile-negative",
            [
                "cc",
                "-std=c11",
                "-pthread",
                "-g",
                "-fsanitize=thread",
                "-DDELIBERATE_RACE",
                str(c_source),
                "-o",
                str(race),
            ],
        )
        clean_result = run("tsan-positive", [str(clean)], success=False)
        race_result = run("tsan-negative", [str(race)], success=False)
        supported = (
            clean_result.returncode == 0
            and race_result.returncode == 66
            and "ThreadSanitizer: data race" in race_result.stderr
        )
        report["tsan"] = {
            "supported": supported,
            "positive_exit": clean_result.returncode,
            "negative_exit": race_result.returncode,
        }
        if not supported:
            fixed = run(
                "tsan-setarch",
                ["setarch", "--addr-no-randomize", str(clean)],
                success=False,
            )
            report["tsan"].update(
                positive_stderr=clean_result.stderr,
                negative_stderr=race_result.stderr,
                setarch_exit=fixed.returncode,
                setarch_stderr=fixed.stderr,
            )
        report["status"] = (
            "fixture-compiler-pass"
            if supported
            else "fixture-compiler-pass-tsan-blocked"
        )
        require(
            not require_tsan or supported,
            "TSan runtime is not qualified; sandbox was not weakened",
        )
    except BaseException as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        report["commands"] = rows
        report["observations"] = execution.observations
        (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        for path in roots.values():
            shutil.rmtree(path)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--require-tsan", action="store_true")
    parser.add_argument("--require-tools", action="store_true")
    args = parser.parse_args()
    result = probe(
        args.config, args.config_sha256, args.plan_sha256, args.work, args.require_tsan,
        args.require_tools
    )
    print(
        json.dumps(
            {k: v for k, v in result.items() if k not in ("commands", "observations")}
        )
    )


if __name__ == "__main__":
    main()
