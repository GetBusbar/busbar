#!/usr/bin/env python3
"""Refuse suites whose isolated runtime was not provisioned by the controller.

The manifest is a read-only controller mount, not candidate authorization. It
allows the driver to preserve an honest verdict for each required suite while
the controller continues to enforce filesystem, process and network isolation.
No manifest field is an executable, endpoint, environment variable or command.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "busbar.conformance.capabilities/1"


def unavailable(path, repo, source, suite):
    """Return a bounded public limitation, or None when the suite can execute."""
    try:
        with open(path, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("manifest is not a regular file")
            payload = stream.read(65537)
        if len(payload) > 65536:
            raise ValueError("manifest exceeds its byte limit")
        record = json.loads(payload)
        if not isinstance(record, dict) or set(record) != {
            "schema", "repo", "source", "toolchain_ready", "suites"
        }:
            raise ValueError("invalid manifest fields")
        if record["schema"] != SCHEMA:
            raise ValueError("unsupported manifest schema")
        if (not re.fullmatch(r"[0-9a-f]{40}", source)
                or record["repo"] != repo or record["source"] != source):
            raise ValueError("manifest does not bind the admitted repository and source")
        if type(record["toolchain_ready"]) is not bool or not isinstance(record["suites"], dict):
            raise ValueError("invalid toolchain or suite declarations")
        for name, row in record["suites"].items():
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name)
                    or not isinstance(row, dict) or set(row) - {"available", "reason"}
                    or type(row.get("available")) is not bool):
                raise ValueError("invalid suite capability")
            reason = row.get("reason")
            if reason is not None and (not isinstance(reason, str) or not reason.strip()
                                       or len(reason) > 2000 or any(ord(c) < 32 for c in reason)):
                raise ValueError("invalid public limitation")
            if row["available"] is False and reason is None:
                raise ValueError("unavailable suite needs a public limitation")
        if not record["toolchain_ready"]:
            return "controller has not staged the required pinned offline toolchain"
        row = record["suites"].get(suite)
        if row is None:
            return "controller has not provisioned an isolated runtime for this suite"
        if not row["available"]:
            return row["reason"]
    except (OSError, ValueError, TypeError, RecursionError) as error:
        # File errors can embed host paths. Only controlled validation errors are public.
        detail = str(error) if type(error) is ValueError else type(error).__name__
        return "controller capability manifest refused: " + detail
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite")
    parser.add_argument("verdict", type=Path)
    args = parser.parse_args()
    why = unavailable(os.environ["CONFORMANCE_CAPABILITIES"], os.environ["CONF_REPO"],
                      os.environ["CONF_HEAD"], args.suite)
    if why is None:
        return 0
    args.verdict.write_text(json.dumps({
        "suite": args.suite, "status": "fail", "armed": True,
        "reason": "required external evaluation could not run safely: " + why,
    }, indent=2) + "\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
