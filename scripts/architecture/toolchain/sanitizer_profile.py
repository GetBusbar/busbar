"""One exact syscall-argument exception, for a separately authorized local fixture."""

import copy
import hashlib
import json
from pathlib import Path

PINS = json.loads(Path(__file__).with_name("sanitizer-profile-pins.json").read_text())
RULE = {
    "names": ["personality"],
    "action": "SCMP_ACT_ALLOW",
    "args": [{"index": 0, "value": 262144, "op": "SCMP_CMP_EQ"}],
}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def derive(raw):
    if hashlib.sha256(raw).hexdigest() != PINS["baseline_sha256"]:
        raise ValueError("baseline differs from the exact pinned engine source")
    baseline = json.loads(raw)
    if (
        baseline.get("defaultAction") != "SCMP_ACT_ERRNO"
        or RULE in baseline["syscalls"]
    ):
        raise ValueError("unexpected baseline policy")
    result = copy.deepcopy(baseline)
    result["syscalls"].append(copy.deepcopy(RULE))
    verify_delta(baseline, result)
    return result


def verify_delta(baseline, result):
    if set(baseline) != set(result) or any(
        baseline[k] != result[k] for k in baseline if k != "syscalls"
    ):
        raise ValueError("sanitizer profile changed non-syscall policy")
    if result["syscalls"] != [*baseline["syscalls"], RULE]:
        raise ValueError(
            "sanitizer profile must append only the exact personality argument"
        )


def prepare(baseline_path, destination):
    raw = Path(baseline_path).read_bytes()
    profile = derive(raw)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "baseline.json").write_bytes(raw)
    encoded = canonical(profile)
    (destination / "sanitizer.json").write_bytes(encoded)
    record = {
        "schema": "busbar.local-sanitizer-profile/1",
        "pins": PINS,
        "baseline_sha256": hashlib.sha256(raw).hexdigest(),
        "profile_sha256": hashlib.sha256(encoded).hexdigest(),
        "exact_delta": RULE,
        "per_process_aslr_disabled": True,
        "production_activation": False,
    }
    (destination / "profile-record.json").write_bytes(canonical(record))
    return record
