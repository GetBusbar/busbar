#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Boot the real default product for the TLS scanner; no resolver or TLS policy overrides."""
import importlib.util
from pathlib import Path
import signal
import sys
import time


def main():
    binary, work = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "tls_product_evidence", repo / "testing/evidence-conformance/evidence.py")
    evidence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evidence)
    data, admin = evidence.free_port(), evidence.free_port()
    cert, key = work / "cert.pem", work / "key.pem"
    cfg = evidence.base_config(data, admin,
                               tls={"cert": {"file": str(cert)}, "key": {"file": str(key)}})
    subject = evidence.Busbar(str(binary), str(work), "product", cfg)

    def terminate(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        def ready():
            admitted, detail = evidence.probe(data, str(cert))
            if admitted != "admitted":
                raise OSError(detail)
        subject.wait(ready)
        (work / "addr").write_text(f"127.0.0.1:{data}\n")
        while subject.proc.poll() is None:
            time.sleep(0.5)
        raise evidence.Refused(f"busbar exited after readiness: {evidence.tail(subject.log)}")
    finally:
        subject.stop()


if __name__ == "__main__":
    main()
