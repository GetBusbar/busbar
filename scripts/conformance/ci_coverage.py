#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check that every registered suite has an execution owner and CI stage.

Regenerate with --write --archive-root <directory of git-archive product inputs>.
This is coverage metadata, never a passing suite verdict or certification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "conformance/ci-coverage.json"


def roster(data):
    rows = {}
    for line in data.decode().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2 or not parts[1].strip() or parts[0] in rows:
            raise ValueError("suite roster needs unique ids and real TAB-separated commands")
        rows[parts[0]] = parts[1]
    return rows


def script_path(command):
    paths = [p for p in shlex.split(command) if p.startswith("testing/")]
    if not paths or any(".." in Path(p).parts for p in paths):
        raise ValueError("suite command must name a repository-owned testing script")
    return paths[0]


def generate(archive_roots):
    registry_file = ROOT / "conformance/registry.toml"
    entries = tomllib.loads(registry_file.read_text())["suite"]
    pin_data = json.loads((ROOT / "scripts/ci-product-pins.json").read_text())
    pins = {p["repo"]: p["commit"] for p in pin_data["products"]}
    sdks = {p["repo"]: p.get("sdk", pin_data["sdk"]) for p in pin_data["products"]}
    core_roster = roster((ROOT / "testing/conformance/suites.tsv").read_bytes())
    result = {"schema": "busbar.conformance.ci-coverage/1",
              "registry_sha256": hashlib.sha256(registry_file.read_bytes()).hexdigest(),
              "scope": "Execution coverage only; suite verdicts and issued certifications are separate",
              "suites": {}}
    for entry in entries:
        suite, repo = entry["id"], entry["repo"]
        if repo == "GetBusbar/busbar":
            stage = "main" if suite == "sigstore" else "qa"
            command = "python3 -I testing/conformance/sigstore.py" if suite == "sigstore" else core_roster.get(suite)
            if not command:
                raise ValueError(f"{suite}: no core execution command")
            script = script_path(command)
            data = (ROOT / script).read_bytes()
            commit = "checkout"
        else:
            name = repo.split("/")[1]
            commit = pins[name]
            found = None
            for directory in archive_roots:
                archive = directory / (name + ".tar.gz")
                if not archive.exists():
                    continue
                with tarfile.open(archive) as source:
                    if source.pax_headers.get("comment") != commit:
                        continue
                    commands = roster(source.extractfile("testing/conformance/suites.tsv").read())
                    command = commands.get(suite)
                    if not command:
                        raise ValueError(f"{suite}: no execution command in {repo}")
                    script = script_path(command)
                    data = source.extractfile(script).read()
                    found = archive
                    break
            if found is None:
                raise ValueError(f"{suite}: no git archive at exact {repo} pin {commit}")
            stage = "qa"
        result["suites"][suite] = {"repo": repo, "source_commit": commit,
                                    "core_pin": "checkout" if repo == "GetBusbar/busbar" else sdks[name], "stage": stage,
                                    "check": "main/certify-sigstore" if stage == "main" else "conformance",
                                    "command": command, "script": script,
                                    "script_sha256": hashlib.sha256(data).hexdigest()}
    return result


def validate(data):
    path = ROOT / "conformance/registry.toml"
    registry = {r["id"]: r for r in tomllib.loads(path.read_text())["suite"]}
    pin_data = json.loads((ROOT / "scripts/ci-product-pins.json").read_text())
    pins = {p["repo"]: p["commit"] for p in pin_data["products"]}
    sdks = {p["repo"]: p.get("sdk", pin_data["sdk"]) for p in pin_data["products"]}
    if data.get("registry_sha256") != hashlib.sha256(path.read_bytes()).hexdigest():
        raise ValueError("registry changed; regenerate CI coverage")
    if set(data.get("suites", {})) != set(registry):
        raise ValueError("registered suites and CI coverage differ")
    core_commands = roster((ROOT / "testing/conformance/suites.tsv").read_bytes())
    for name, row in data["suites"].items():
        if row["repo"] != registry[name]["repo"] or row["stage"] not in {"qa", "main"}:
            raise ValueError(f"{name}: wrong execution owner/stage")
        expected_check = "main/certify-sigstore" if name == "sigstore" else "conformance"
        expected_core = "checkout" if row["repo"] == "GetBusbar/busbar" else sdks[row["repo"].split("/")[1]]
        if row["check"] != expected_check or row["core_pin"] != expected_core:
            raise ValueError(f"{name}: wrong CI check or SDK binding")
        if row["repo"] == "GetBusbar/busbar":
            expected_stage = "main" if name == "sigstore" else "qa"
            expected_command = "python3 -I testing/conformance/sigstore.py" if name == "sigstore" else core_commands.get(name)
            if row["stage"] != expected_stage or row["command"] != expected_command:
                raise ValueError(f"{name}: CI stage or roster command does not match the declared execution")
            if hashlib.sha256((ROOT / row["script"]).read_bytes()).hexdigest() != row["script_sha256"]:
                raise ValueError(f"{name}: core check changed; regenerate coverage")
        elif row["stage"] != "qa" or row["source_commit"] != pins[row["repo"].split("/")[1]]:
            raise ValueError(f"{name}: wrong QA stage or product pin; regenerate from the new exact archive")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--archive-root", type=Path, action="append", default=[])
    args = parser.parse_args()
    data = generate(args.archive_root) if args.write else json.loads(OUTPUT.read_text())
    validate(data)
    if args.write:
        OUTPUT.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(f"{len(data['suites'])} registered suites have an exact owner, script and QA/main stage")


if __name__ == "__main__":
    main()
