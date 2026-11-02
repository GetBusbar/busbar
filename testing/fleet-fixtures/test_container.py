# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Exercise the actual fixture shell entrypoints against a Docker double; no real services."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
IMAGE = "valkey/valkey:8@sha256:" + "495e4fecdc98ee48a20b207726caa5ab6451e0fac3642a9be10d9e70b3068df6"
IMAGE_ID = "sha256:" + "a" * 64
MOCK = r'''
import json, os, re, sys
p = os.environ["FIXTURE_DOCKER_STATE"]
s = json.load(open(p))
a = sys.argv[1:]
def obj(name):
    return s["containers"].get(name) or next((v for v in s["containers"].values() if v["Id"] == name), None)
def emit(value):
    print(json.dumps([value])); sys.exit(0)
if a[:2] == ["image", "inspect"] and a[2] in s["images"]:
    emit(s["images"][a[2]])
if a[:2] == ["ps", "-aq"]:
    pattern = a[-1].split("=", 1)[1]
    print("\n".join(v["Id"] for n, v in s["containers"].items() if re.search(pattern, "/" + n)))
    sys.exit(0)
if a and a[0] == "inspect":
    o = obj(a[-1])
    if o is None: sys.exit(1)
    if len(a) > 2 and a[1] == "-f":
        print("true" if o["State"]["Running"] else "false"); sys.exit(0)
    emit(o)
if a and a[0] == "run":
    name = a[a.index("--name") + 1]
    image = a[-1]
    if name in s["containers"] or image not in s["images"]: sys.exit(1)
    number = s.get("next", 0) + 1
    s["next"] = number
    s["containers"][name] = {"Id": f"{number:064x}", "Image": s["images"][image]["Id"],
        "Config": {"Labels": {"dev.getbusbar.fixture.owner": name}}, "State": {"Running": True},
        "NetworkSettings": {"Ports": {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(20000 + number)}]}}}
    with open(p, "w") as f: json.dump(s, f)
    print(s["containers"][name]["Id"])
    sys.exit(0)
if a and a[0] == "exec":
    sys.exit(0 if obj(a[1]) is not None else 1)
if a and a[0] == "rm":
    o = obj(a[-1])
    if o is None: sys.exit(1)
    s.setdefault("removed", []).append(a[-1])
    s["containers"] = {n: v for n, v in s["containers"].items() if v["Id"] != o["Id"]}
    with open(p, "w") as f: json.dump(s, f)
    sys.exit(0)
sys.exit(8)
'''


def container(name, port="20001", number=1):
    return {"Id": f"{number:064x}", "Image": IMAGE_ID,
            "Config": {"Labels": {"dev.getbusbar.fixture.owner": name}},
            "State": {"Running": True},
            "NetworkSettings": {"Ports": {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": port}]}}}


class FixtureIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        docker = self.work / "docker"
        docker.write_text("#!" + sys.executable + "\n" + MOCK)
        docker.chmod(0o755)
        self.state_path = self.work / "docker.json"
        self.name = "busbar-store-qa-valkey"
        self.state = {"images": {IMAGE: {"Id": IMAGE_ID}},
                      "containers": {self.name: container(self.name)}}
        self.env = dict(os.environ, PATH=str(self.work) + os.pathsep + os.environ["PATH"],
                        FIXTURE_DOCKER_STATE=str(self.state_path))
        self.env["ORACLE_CELLS_JSON"] = str(self.work / "cells.json")
        (self.work / "cells.json").write_text('{"cells": []}\n')
        for key in ("BUSBAR_STORE_QA_TAG", "SERVICE_IMAGES_TSV", "VALKEY_URL", "BUSBAR_TEST_MYSQL_URL",
                    "BUSBAR_TEST_POSTGRES_URL"):
            self.env.pop(key, None)

    def run_helper(self, function, *args):
        self.state_path.write_text(json.dumps(self.state))
        return subprocess.run(["bash", "-c", '. "$1"; shift; ' + function + ' "$@"', "fixture",
                               str(HERE / "container.sh"), *args], env=self.env,
                              capture_output=True, text=True)

    def port(self):
        return self.run_helper("fixture_container_port", self.name, IMAGE, "20001", "6379")

    def test_matching_owned_image_and_endpoint_are_accepted(self):
        out = self.port()
        self.assertEqual((out.returncode, out.stdout), (0, "20001\n"), out.stderr)

    def test_unpinned_image_reference_is_refused(self):
        out = self.run_helper("fixture_container_port", self.name, "valkey/valkey:8", "20001", "6379")
        self.assertNotEqual(out.returncode, 0)

    def test_old_image_is_refused(self):
        self.state["containers"][self.name]["Image"] = "sha256:" + "b" * 64
        self.assertNotEqual(self.port().returncode, 0)

    def test_missing_owner_and_foreign_owner_are_refused(self):
        for labels in (None, {}, {"dev.getbusbar.fixture.owner": "another-owner"}):
            with self.subTest(labels=labels):
                self.state["containers"][self.name]["Config"]["Labels"] = labels
                self.assertNotEqual(self.port().returncode, 0)

    def test_wrong_host_port_and_nonloopback_binding_are_refused(self):
        binding = self.state["containers"][self.name]["NetworkSettings"]["Ports"]["6379/tcp"][0]
        binding["HostPort"] = "20002"
        self.assertNotEqual(self.port().returncode, 0)
        binding.update(HostPort="20001", HostIp="0.0.0.0")
        self.assertNotEqual(self.port().returncode, 0)

    def test_stopped_container_is_not_ready(self):
        self.state["containers"][self.name]["State"]["Running"] = False
        self.assertNotEqual(self.port().returncode, 0)

    def test_teardown_removes_verified_id_and_refuses_unknown_owner(self):
        original = copy.deepcopy(self.state)
        out = self.run_helper("fixture_remove_container", self.name)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(self.state_path.read_text())["removed"], [container(self.name)["Id"]])
        self.state = original
        self.state["containers"][self.name]["Config"]["Labels"] = None
        self.assertNotEqual(self.run_helper("fixture_remove_container", self.name).returncode, 0)
        self.assertNotIn("removed", json.loads(self.state_path.read_text()))

    def test_missing_container_teardown_is_idempotent(self):
        self.state["containers"] = {}
        self.assertEqual(self.run_helper("fixture_remove_container", self.name).returncode, 0)

    def test_sixteen_valkey_namespaces_have_distinct_endpoints(self):
        # The old fifteen-index hash necessarily aliases at least two of these sixteen owners.
        tokens = ["a" + str(i) for i in range(16)]
        self.state["containers"] = {}
        self.state_path.write_text(json.dumps(self.state))
        urls = []
        for token in tokens:
            out = subprocess.run(["bash", str(HERE / "store-services.sh"), "ns", "valkey", token],
                                 env=self.env, capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            urls.append(out.stdout.strip())
        self.assertEqual(len(set(urls)), 16)
        self.assertTrue(all(url.endswith("/0") for url in urls))
        repeated = subprocess.run(["bash", str(HERE / "store-services.sh"), "ns", "valkey", tokens[0]],
                                  env=self.env, capture_output=True, text=True)
        self.assertNotEqual(repeated.returncode, 0, "an existing namespace must not count as fresh evidence")

    def test_sourced_oracle_preparation_failure_exports_no_urls(self):
        self.state["containers"] = {}
        self.state_path.write_text(json.dumps(self.state))
        oracle = HERE.parent / "shadow-oracle" / "scripts" / "oracle-box-store-services.sh"
        script = '. "$1" up; rc=$?; [ "$rc" -ne 0 ] && [ -z "${VALKEY_URL+x}" ] && [ -z "${BUSBAR_TEST_POSTGRES_URL+x}" ] && [ -z "${BUSBAR_TEST_MYSQL_URL+x}" ]'
        out = subprocess.run(["bash", "-c", script, "fixture", str(oracle)], env=self.env,
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)


if __name__ == "__main__":
    unittest.main()
