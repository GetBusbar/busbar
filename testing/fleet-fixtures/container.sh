#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
# Shared fixture identity checks. These functions print only a verified port or container id.
# Every created fixture carries dev.getbusbar.fixture.owner=<its exact container name>.

fixture_container_port() { # <name> <immutable image ref> <host port or *> <container port>
  python3 - "$@" <<'PY'
import json
import re
import subprocess
import sys
name, image, host_port, container_port = sys.argv[1:]
def refuse(why):
    raise SystemExit(f"fixture-container: {name}: {why}")
def inspect(argv):
    try:
        return json.loads(subprocess.check_output(argv, stderr=subprocess.DEVNULL, timeout=30))[0]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, ValueError, IndexError):
        refuse("cannot verify the Docker object; refusing reuse")
if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image):
    refuse("the requested image is not pinned by digest")
obj = inspect(["docker", "inspect", name])
if (obj.get("Config", {}).get("Labels") or {}).get("dev.getbusbar.fixture.owner") != name:
    refuse("the named container does not carry this fixture owner's label")
if obj.get("State", {}).get("Running") is not True:
    refuse("the owned container is not running")
expected = inspect(["docker", "image", "inspect", image])
if obj.get("Image") != expected.get("Id") or not expected.get("Id"):
    refuse("the running image content does not match the requested pin")
bindings = obj.get("NetworkSettings", {}).get("Ports", {}).get(container_port + "/tcp") or []
if len(bindings) != 1 or bindings[0].get("HostIp") != "127.0.0.1":
    refuse("the service does not have exactly one loopback host binding")
port = bindings[0].get("HostPort", "")
if not port.isdecimal() or not 1 <= int(port) <= 65535 or (host_port != "*" and port != host_port):
    refuse("the published host port does not match the requested endpoint")
print(port)
PY
}

fixture_remove_container() { # <name>: absence is idempotent; unknown ownership is an error
  local name="$1" id
  id="$(python3 - "$name" <<'PY'
import json
import re
import subprocess
import sys
name = sys.argv[1]
def refuse(why):
    raise SystemExit(f"fixture-container: {name}: {why}")
try:
    ids = subprocess.check_output(["docker", "ps", "-aq", "--filter", "name=^/" + re.escape(name) + "$"],
                                  stderr=subprocess.DEVNULL, timeout=30).decode().split()
    if not ids:
        sys.exit(0)
    if len(ids) != 1:
        refuse("the exact name did not select one container")
    obj = json.loads(subprocess.check_output(["docker", "inspect", ids[0]], stderr=subprocess.DEVNULL, timeout=30))[0]
except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, ValueError, IndexError):
    refuse("cannot verify teardown ownership")
if (obj.get("Config", {}).get("Labels") or {}).get("dev.getbusbar.fixture.owner") != name:
    refuse("refusing to remove a container without this fixture owner's label")
print(obj["Id"])
PY
)" || return 1
  [ -z "$id" ] || docker rm -f -v "$id" >/dev/null
}
